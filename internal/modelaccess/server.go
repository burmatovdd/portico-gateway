package modelaccess

import (
	"context"
	"encoding/json"
	"net/http"
	"portico-gateway/internal/identity"
	"sort"
	"strings"
	"time"
)

type Verifier interface {
	Verify(context.Context, string) (identity.Identity, error)
}
type Policy interface {
	Allowed(context.Context, []string) (map[string]bool, error)
}
type Server struct {
	Policy   Policy
	Verifier Verifier
	Config   Config
	Key      string
	Client   *http.Client
}

func New(v Verifier, c Config, key string, client *http.Client) *Server {
	copy := *client
	copy.Timeout = 0
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Server{Verifier: v, Config: c, Key: key, Client: &copy}
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, code string) {
	respond(w, status, map[string]any{"error": map[string]string{"message": code, "type": "portico_error", "code": code}})
}
func (s *Server) allowed(id identity.Identity) map[string]bool {
	out := map[string]bool{}
	for _, g := range id.Roles {
		for _, m := range s.Config.Rules[g] {
			out[m] = true
		}
	}
	return out
}
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == "GET" && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") {
			if r.URL.Path == "/readyz" && s.Policy != nil {
				check, cancel := context.WithTimeout(r.Context(), 2*time.Second)
				_, err := s.Policy.Allowed(check, nil)
				cancel()
				if err != nil {
					failure(w, 503, "policy_unavailable")
					return
				}
			}
			w.WriteHeader(200)
			return
		}
		if !(r.Method == "GET" && r.URL.Path == "/v1/models" || r.Method == "POST" && r.URL.Path == "/v1/chat/completions") {
			failure(w, 404, "not_found")
			return
		}
		if r.URL.RawQuery != "" {
			failure(w, 400, "query_not_supported")
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") || len(h) > 32768 || len(h) == 7 {
			failure(w, 401, "invalid_token")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		id, e := s.Verifier.Verify(ctx, strings.TrimPrefix(h, "Bearer "))
		cancel()
		if e != nil || !id.Expires.After(time.Now()) {
			failure(w, 401, "invalid_token")
			return
		}
		allowed := s.allowed(id)
		if s.Policy != nil {
			check, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			allowed, e = s.Policy.Allowed(check, id.Roles)
			cancel()
			if e != nil {
				failure(w, 503, "policy_unavailable")
				return
			}
		}
		if r.Method == "GET" {
			names := []string{}
			for m := range allowed {
				names = append(names, m)
			}
			sort.Strings(names)
			data := []map[string]any{}
			for _, m := range names {
				data = append(data, map[string]any{"id": m, "object": "model", "created": 0, "owned_by": "portico"})
			}
			respond(w, 200, map[string]any{"object": "list", "data": data})
			return
		}
		s.complete(w, r, id, allowed)
	})
}
