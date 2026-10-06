package scanportal

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// download has a fixed origin/path and first performs an owner-authorized status
// lookup. The downstream download endpoint must independently enforce ownership.
func (s *Server) download(w http.ResponseWriter, r *http.Request, id string) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["format"]) != 1 {
		s.fail(w, r, 404, false)
		return
	}
	format := query.Get("format")
	contentType, extension := "", ""
	switch format {
	case "html":
		contentType, extension = "text/html", "html"
	case "markdown":
		contentType, extension = "text/markdown", "md"
	case "pdf":
		contentType, extension = "application/pdf", "pdf"
	default:
		s.fail(w, r, 404, false)
		return
	}
	s.downloadFile(w, r, id, "/reports/"+id+"/download", url.Values{"format": {format}}, contentType, id+"-report."+extension)
}

func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request, id, path string, query url.Values, contentType, filename string) {
	body, status := s.call(r, "getStatus", map[string]any{"scan_id": id})
	if status != 200 {
		s.fail(w, r, status, false)
		return
	}
	// A valid owner check must identify the requested scan, not a generic success.
	if !validScanResponse(body, id) {
		s.fail(w, r, 503, false)
		return
	}
	_, token, err := s.Auth.Access(r)
	if err != nil {
		s.fail(w, r, authStatus(err), false)
		return
	}
	base, err := url.Parse(s.Proxy.Services[s.Service].BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		s.fail(w, r, 503, false)
		return
	}
	base.Path = path
	base.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		s.fail(w, r, 503, false)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", contentType)
	client := *s.Proxy.Client
	client.Timeout = 30 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		s.fail(w, r, 503, false)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		code := 503
		if response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 404 {
			code = response.StatusCode
		}
		s.fail(w, r, code, false)
		return
	}
	actual, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || actual != contentType {
		s.fail(w, r, 503, false)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || len(payload) > 16<<20 {
		s.fail(w, r, 503, false)
		return
	}
	w.Header().Set("Content-Type", contentType+"; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	// Do not relay any upstream headers, cookies or filenames.
	_, _ = w.Write(payload)
}

func reportID(path string) (string, bool) {
	if !strings.HasPrefix(path, "/portal/scans/") || !strings.HasSuffix(path, "/report") {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, "/portal/scans/"), "/report")
	return id, scanID.MatchString(id)
}

var evidenceName = regexp.MustCompile(`^evidence/[A-Za-z0-9][A-Za-z0-9_.-]{0,191}\.md$`)

func artifactType(name string) string {
	switch name {
	case "report.md":
		return "text/markdown"
	case "findings.json", "findings.sarif", "coverage.json":
		return "application/json"
	case "vulnerabilities.csv":
		return "text/csv"
	}
	if evidenceName.MatchString(name) {
		return "text/markdown"
	}
	return ""
}
func (s *Server) evidence(w http.ResponseWriter, r *http.Request, id string) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["name"]) != 1 {
		s.fail(w, r, 404, false)
		return
	}
	name := query.Get("name")
	contentType := artifactType(name)
	if contentType == "" {
		s.fail(w, r, 404, false)
		return
	}
	filename := id + "-" + strings.TrimPrefix(name, "evidence/")
	s.downloadFile(w, r, id, "/reports/"+id+"/downloads/"+name, nil, contentType, filename)
}
func (s *Server) artifacts(w http.ResponseWriter, r *http.Request, id string) {
	body, status := s.call(r, "getReportManifest", map[string]any{"scan_id": id})
	if status != 200 {
		s.fail(w, r, status, true)
		return
	}
	var response struct {
		ScanID   string `json:"scan_id"`
		Manifest struct {
			ScanID    string                     `json:"scan_id"`
			Artifacts map[string]json.RawMessage `json:"artifacts"`
		} `json:"manifest"`
	}
	if json.Unmarshal(body, &response) != nil || response.ScanID != id || response.Manifest.ScanID != id || response.Manifest.Artifacts == nil {
		s.fail(w, r, 503, true)
		return
	}
	manifest := response.Manifest
	names := []string{}
	for name := range manifest.Artifacts {
		if artifactType(name) != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		ScanID    string   `json:"scan_id"`
		Artifacts []string `json:"artifacts"`
	}{id, names})
}
func subrouteID(path, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return id, scanID.MatchString(id)
}
