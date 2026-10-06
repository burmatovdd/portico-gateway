// Package scanportal serves a read-only browser view of user-owned scans.
package scanportal

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"regexp"
	"strings"
	"time"

	"portico-gateway/internal/adminauth"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/proxy"
)

// Auth keeps OIDC credentials on the server. Use adminauth.NewPortal, not New.
type Auth interface {
	Authenticate(*http.Request) (identity.Identity, string, error)
	Access(*http.Request) (identity.Identity, string, error)
	Login(http.ResponseWriter, *http.Request)
	Callback(http.ResponseWriter, *http.Request)
	Logout(http.ResponseWriter, *http.Request)
}

type Server struct {
	Auth    Auth
	Proxy   *proxy.Proxy
	Service string
}

func New(auth Auth, upstream *proxy.Proxy, service string) (*Server, error) {
	if auth == nil || upstream == nil || upstream.Client == nil {
		return nil, errors.New("portal dependencies are required")
	}
	config, ok := upstream.Services[service]
	if !ok || config.Operations["getStatus"].Method != "GET" || config.Operations["listReports"].Method != "GET" || config.Operations["getReportManifest"].Method != "GET" {
		return nil, errors.New("portal requires configured read-only getStatus, listReports and getReportManifest operations")
	}
	return &Server{Auth: auth, Proxy: upstream, Service: service}, nil
}

//go:embed page.html portal.js portal.css
var assets embed.FS
var page = template.Must(template.ParseFS(assets, "page.html"))
var scanID = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)

type Stage struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
}
type ModelTiming struct {
	DurationMS   *float64 `json:"duration_ms,omitempty"`
	TTFTMS       *float64 `json:"ttft_ms,omitempty"`
	InputTokens  *float64 `json:"input_tokens,omitempty"`
	OutputTokens *float64 `json:"output_tokens,omitempty"`
}
type Observation struct {
	Available        bool        `json:"available"`
	Stale            bool        `json:"stale"`
	AgeSeconds       *float64    `json:"age_seconds,omitempty"`
	TargetCount      *int        `json:"target_count,omitempty"`
	AgentCount       *int        `json:"agent_count,omitempty"`
	SurfacesReviewed *int        `json:"surfaces_reviewed,omitempty"`
	FindingsCount    *int        `json:"findings_count,omitempty"`
	LatestRequest    ModelTiming `json:"latest_request"`
}
type Progress struct {
	Observations        map[string]Observation `json:"observations,omitempty"`
	LifecycleStageIndex int                    `json:"lifecycle_stage_index,omitempty"`
	LifecycleStageCount int                    `json:"lifecycle_stage_count,omitempty"`
	Available           bool                   `json:"available"`
	Stage               string                 `json:"stage"`
	Tool                string                 `json:"tool"`
	LastEventAt         *time.Time             `json:"last_event_at"`
	LastUsefulEventAt   *time.Time             `json:"last_useful_event_at"`
	HeartbeatAt         *time.Time             `json:"heartbeat_at"`
	HeartbeatAgeSeconds *float64               `json:"heartbeat_age_seconds"`
	Stale               bool                   `json:"stale"`
	ETASeconds          *float64               `json:"eta_seconds"`
	ETAReason           string                 `json:"eta_reason"`
	LifecycleStage      string                 `json:"lifecycle_stage"`
	LifecycleStages     []Stage                `json:"lifecycle_stages"`
	Stages              []Stage                `json:"stages"`
}
type Scan struct {
	ScanID          string     `json:"scan_id"`
	TargetURL       string     `json:"target_url"`
	Status          string     `json:"status"`
	Attempt         int        `json:"attempt"`
	CreatedAt       *time.Time `json:"created_at"`
	StartedAt       *time.Time `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at"`
	DurationSeconds *float64   `json:"duration_seconds"`
	Progress        Progress   `json:"progress"`
}
type view struct {
	Subject, CSRF, Error string
	Login                bool
	Scan                 *Scan
	Scans                []Scan
}

func headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	headers(w)
	switch r.URL.Path {
	case "/portal/login":
		s.Auth.Login(w, r)
		return
	case "/portal/callback":
		s.Auth.Callback(w, r)
		return
	case "/portal/logout":
		s.Auth.Logout(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Метод не поддерживается.", 405)
		return
	}
	if r.URL.Path == "/portal/portal.js" || r.URL.Path == "/portal/portal.css" {
		filename := strings.TrimPrefix(r.URL.Path, "/portal/")
		body, _ := assets.ReadFile(filename)
		if filename == "portal.js" {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		}
		_, _ = w.Write(body)
		return
	}
	if id, ok := subrouteID(r.URL.Path, "/portal/api/scans/", "/artifacts"); ok {
		s.artifacts(w, r, id)
		return
	}
	if id, ok := subrouteID(r.URL.Path, "/portal/scans/", "/evidence"); ok {
		s.evidence(w, r, id)
		return
	}
	if id, ok := reportID(r.URL.Path); ok {
		s.download(w, r, id)
		return
	}
	if r.URL.Path == "/portal/" {
		s.home(w, r)
		return
	}
	for _, prefix := range []string{"/portal/api/scans/", "/portal/scans/"} {
		if strings.HasPrefix(r.URL.Path, prefix) {
			id := strings.TrimPrefix(r.URL.Path, prefix)
			if !scanID.MatchString(id) {
				s.fail(w, r, 404, strings.Contains(prefix, "/api/"))
				return
			}
			s.status(w, r, id, strings.Contains(prefix, "/api/"))
			return
		}
	}
	s.fail(w, r, 404, false)
}
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, api bool) {
	messages := map[int]string{401: "Для просмотра проверок выполните вход.", 403: "Доступ к проверке запрещён.", 404: "Проверка не найдена или недоступна.", 503: "Состояние проверки временно недоступно."}
	message := messages[status]
	if message == "" {
		status = 503
		message = messages[503]
	}
	if api {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = page.Execute(w, view{Error: message, Login: status == 401})
}
func authStatus(err error) int {
	if errors.Is(err, adminauth.ErrForbidden) {
		return 403
	}
	return 401
}
func (s *Server) call(r *http.Request, op string, args map[string]any) ([]byte, int) {
	id, token, err := s.Auth.Access(r)
	if err != nil {
		return nil, authStatus(err)
	}
	if s.Proxy == nil || s.Proxy.Client == nil {
		return nil, 503
	}
	config, ok := s.Proxy.Services[s.Service]
	if !ok || config.Operations[op].Method != "GET" {
		return nil, 503
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, err := s.Proxy.Call(ctx, id, token, s.Service, op, args)
	if errors.Is(err, proxy.ErrForbidden) {
		return nil, 403
	}
	if err != nil {
		return nil, 503
	}
	switch result.Status {
	case 200:
		return result.Body, 200
	case 401, 403, 404:
		return nil, result.Status
	default:
		return nil, 503
	}
}
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	id, csrf, err := s.Auth.Authenticate(r)
	if err != nil {
		s.fail(w, r, authStatus(err), false)
		return
	}
	args := map[string]any{}
	if s.Proxy != nil {
		op := s.Proxy.Services[s.Service].Operations["listReports"]
		if _, ok := op.Parameters["limit"]; ok {
			args["limit"] = float64(50)
		}
	}
	body, status := s.call(r, "listReports", args)
	if status != 200 {
		s.fail(w, r, status, false)
		return
	}
	var scans []Scan
	if json.Unmarshal(body, &scans) != nil || scans == nil {
		s.fail(w, r, 503, false)
		return
	}
	filtered := make([]Scan, 0, len(scans))
	for _, scan := range scans {
		if scanID.MatchString(scan.ScanID) {
			filtered = append(filtered, scan)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, view{Subject: id.Subject, CSRF: csrf, Scans: filtered})
}
func (s *Server) status(w http.ResponseWriter, r *http.Request, id string, api bool) {
	body, status := s.call(r, "getStatus", map[string]any{"scan_id": id})
	if status != 200 {
		s.fail(w, r, status, api)
		return
	}
	var scan Scan
	if json.Unmarshal(body, &scan) != nil || scan.ScanID != id {
		s.fail(w, r, 503, api)
		return
	}
	if api {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(scan)
		return
	}
	user, csrf, err := s.Auth.Authenticate(r)
	if err != nil {
		s.fail(w, r, authStatus(err), false)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, view{Subject: user.Subject, CSRF: csrf, Scan: &scan})
}

func validScanResponse(body []byte, id string) bool {
	var scan Scan
	return json.Unmarshal(body, &scan) == nil && scan.ScanID == id
}
