package scanportal

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"portico-gateway/internal/adminauth"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/proxy"
)

type fakeAuth struct {
	err   error
	roles []string
}

func (a *fakeAuth) Authenticate(*http.Request) (identity.Identity, string, error) {
	return identity.Identity{Subject: "<user>", Roles: a.roles}, "csrf-safe", a.err
}
func (a *fakeAuth) Access(*http.Request) (identity.Identity, string, error) {
	return identity.Identity{Subject: "owner-a", Roles: a.roles}, "PRIVATE-TOKEN", a.err
}
func (*fakeAuth) Login(w http.ResponseWriter, r *http.Request)    { w.WriteHeader(303) }
func (*fakeAuth) Callback(w http.ResponseWriter, r *http.Request) { w.WriteHeader(303) }
func (*fakeAuth) Logout(w http.ResponseWriter, r *http.Request)   { w.WriteHeader(403) }

type transport func(*http.Request) (*http.Response, error)

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }
func fixture(t *testing.T, body string, status int) (*Server, *fakeAuth, *int) {
	t.Helper()
	auth := &fakeAuth{roles: []string{"users"}}
	calls := new(int)
	upstream := &proxy.Proxy{Client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		*calls++
		if r.Header.Get("Authorization") != "Bearer PRIVATE-TOKEN" {
			t.Error("owner credential not propagated")
		}
		if r.Method != "GET" {
			t.Error("mutation forwarded")
		}
		if strings.Contains(r.URL.String(), "PRIVATE-TOKEN") {
			t.Error("token leaked to URL")
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}, Services: map[string]proxy.Service{"strix": {BaseURL: "https://upstream.example", Roles: []string{"users"}, Operations: map[string]proxy.Operation{
		"getReportManifest": {Method: "GET", Path: "/reports/{scan_id}", Parameters: map[string]proxy.Parameter{"scan_id": {Kind: "id", In: "path", Required: true}}},
		"getStatus":         {Method: "GET", Path: "/scans/{scan_id}", Parameters: map[string]proxy.Parameter{"scan_id": {Kind: "id", In: "path", Required: true}}},
		"listReports":       {Method: "GET", Path: "/reports", Parameters: map[string]proxy.Parameter{"limit": {Kind: "integer", In: "query"}}},
	}}}}
	server, err := New(auth, upstream, "strix")
	if err != nil {
		t.Fatal(err)
	}
	return server, auth, calls
}
func serve(s *Server, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "https://portico.example"+path, nil))
	return w
}
func TestUnauthorizedAndForbiddenNeverReachUpstream(t *testing.T) {
	s, a, calls := fixture(t, `{}`, 200)
	for _, tc := range []struct {
		err    error
		status int
	}{{adminauth.ErrUnauthorized, 401}, {adminauth.ErrForbidden, 403}, {errors.New("token unavailable"), 401}} {
		a.err = tc.err
		w := serve(s, "/portal/api/scans/scan-one")
		if w.Code != tc.status || *calls != 0 {
			t.Fatalf("%d calls %d", w.Code, *calls)
		}
		if strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal("credential leak")
		}
	}
	a.err = nil
	a.roles = []string{"users-other"}
	if w := serve(s, "/portal/api/scans/scan-one"); w.Code != 403 || *calls != 0 {
		t.Fatal("proxy role bypass")
	}
}
func TestOwnerTokenAndDownstreamDenialPropagate(t *testing.T) {
	for _, code := range []int{401, 403, 404, 500} {
		s, _, calls := fixture(t, `{"error":"PRIVATE-TOKEN"}`, code)
		w := serve(s, "/portal/api/scans/scan-one")
		want := code
		if code == 500 {
			want = 503
		}
		if w.Code != want || *calls != 1 {
			t.Fatalf("status %d", w.Code)
		}
		if strings.Contains(w.Body.String(), "PRIVATE-TOKEN") {
			t.Fatal("raw backend error leaked")
		}
	}
}
func TestEscapedPageAndWhitelistedJSON(t *testing.T) {
	body := `{"scan_id":"scan-one","target_url":"<script>alert(1)</script>","status":"<img src=x onerror=alert(1)>","access_token":"PRIVATE-TOKEN","progress":{"eta_seconds":null,"stage":"<script>"}}`
	s, _, _ := fixture(t, body, 200)
	w := serve(s, "/portal/scans/scan-one")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	html := w.Body.String()
	if strings.Contains(html, "<img src") || strings.Contains(html, "<script>alert") || strings.Contains(html, "PRIVATE-TOKEN") {
		t.Fatal("unescaped or secret content")
	}
	for _, want := range []string{"&lt;img", `data-scan-id="scan-one"`, `action="/portal/logout"`, `name="csrf" value="csrf-safe"`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("security headers missing")
	}
	w = serve(s, "/portal/api/scans/scan-one")
	if w.Code != 200 || strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "PRIVATE-TOKEN") {
		t.Fatal("unfiltered JSON")
	}
}
func TestScanIDsAndUnknownPathsCannotDispatch(t *testing.T) {
	s, _, calls := fixture(t, `{}`, 200)
	for _, path := range []string{"/portal/scans/%3Cscript%3E", "/portal/api/scans/../admin", "/portal/api/scans/scan-one/other", "/portal/api/startScan", "/portal/api/scans/scan_one"} {
		if w := serve(s, path); w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	if *calls != 0 {
		t.Fatal("invalid identifier reached backend")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "https://portico.example/portal/api/scans/scan-one", nil))
	if w.Code != 405 || *calls != 0 {
		t.Fatal("mutation allowed")
	}
}
func TestHomeEscapesAndFiltersLinks(t *testing.T) {
	s, _, _ := fixture(t, `[{"scan_id":"scan-one","status":"running","target_url":"<img src=x>"},{"scan_id":"../../admin","status":"bad"}]`, 200)
	w := serve(s, "/portal/")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `href="/portal/scans/scan-one"`) || strings.Contains(w.Body.String(), "../../admin") || strings.Contains(w.Body.String(), "<img src") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestInvalidUpstreamResponseAndReadonlyConfiguration(t *testing.T) {
	for _, body := range []string{"not JSON", `{"scan_id":"scan-other"}`, `{"scan_id":"scan-one","started_at":"not a date"}`} {
		s, _, _ := fixture(t, body, 200)
		if w := serve(s, "/portal/api/scans/scan-one"); w.Code != 503 {
			t.Fatal(w.Code)
		}
	}
	s, a, calls := fixture(t, `{}`, 200)
	service := s.Proxy.Services["strix"]
	op := service.Operations["getStatus"]
	op.Method = "POST"
	service.Operations["getStatus"] = op
	if _, err := New(a, s.Proxy, "strix"); err == nil {
		t.Fatal("mutating operation accepted")
	}
	if w := serve(s, "/portal/api/scans/scan-one"); w.Code != 503 || *calls != 0 {
		t.Fatal("read-only check bypassed")
	}
}

func TestDownloadOwnerDeniedDoesNotFetchFile(t *testing.T) {
	s, _, calls := fixture(t, `{"detail":"secret"}`, 403)
	w := serve(s, "/portal/scans/scan-one/report?format=html")
	if w.Code != 403 || *calls != 1 {
		t.Fatalf("code %d calls %d", w.Code, *calls)
	}
}
func TestDownloadUsesFixedHostBoundedTypesAndSafeFilename(t *testing.T) {
	for _, format := range []string{"html", "markdown", "pdf"} {
		s, _, calls := fixture(t, `{"scan_id":"scan-one"}`, 200)
		original := s.Proxy.Client.Transport
		s.Proxy.Client.Transport = transport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/scans/scan-one" {
				return original.RoundTrip(r)
			}
			*calls++
			if r.URL.Scheme != "https" || r.URL.Host != "upstream.example" || r.URL.Path != "/reports/scan-one/download" || r.URL.Query().Get("format") != format || r.Header.Get("Authorization") != "Bearer PRIVATE-TOKEN" {
				t.Fatal("unsafe download request", r.URL)
			}
			contentType := "text/" + format
			if format == "pdf" {
				contentType = "application/pdf"
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {contentType}, "Set-Cookie": {"unsafe=1"}, "Content-Disposition": {"inline; filename=evil.html"}}, Body: io.NopCloser(strings.NewReader("<report>"))}, nil
		})
		w := serve(s, "/portal/scans/scan-one/report?format="+format)
		if w.Code != 200 || *calls != 2 || w.Body.String() != "<report>" {
			t.Fatal(w.Code, *calls, w.Body.String())
		}
		if !strings.HasPrefix(w.Header().Get("Content-Disposition"), `attachment; filename="scan-one-report.`) || w.Header().Get("Set-Cookie") != "" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
			t.Fatal("unsafe download headers", w.Header())
		}
	}
}
func TestDownloadRejectsRedirectsWrongTypesAndOversize(t *testing.T) {
	for _, tc := range []struct {
		status            int
		contentType, body string
	}{{302, "text/html", "secret"}, {200, "application/javascript", "secret"}, {500, "text/html", "secret"}, {200, "text/html", strings.Repeat("x", (16<<20)+1)}} {
		s, _, _ := fixture(t, `{"scan_id":"scan-one"}`, 200)
		original := s.Proxy.Client.Transport
		s.Proxy.Client.Transport = transport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/scans/scan-one" {
				return original.RoundTrip(r)
			}
			if r.URL.Host != "upstream.example" {
				t.Fatal("redirect followed")
			}
			return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {tc.contentType}, "Location": {"https://evil.example"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})
		w := serve(s, "/portal/scans/scan-one/report?format=html")
		if w.Code != 503 || strings.Contains(w.Body.String(), "secret") {
			t.Fatal(w.Code)
		}
	}
}
func TestDownloadFormatAllowlist(t *testing.T) {
	s, _, calls := fixture(t, `{}`, 200)
	for _, query := range []string{"format=html&format=markdown", "format=html&url=https://evil.example", "format=../html", ""} {
		if w := serve(s, "/portal/scans/scan-one/report?"+query); w.Code != 404 {
			t.Fatal(w.Code)
		}
	}
	if *calls != 0 {
		t.Fatal("invalid query dispatched")
	}
}

func TestArtifactsExposeOnlyAllowedNamesNotStorageMetadata(t *testing.T) {
	s, _, calls := fixture(t, `{"scan_id":"scan-one","manifest":{"scan_id":"scan-one","artifacts":{"report.md":{"key":"PRIVATE"},"findings.json":{"size":1},"evidence/vuln-0001.md":{},"evidence/../secret.md":{},"events.jsonl":{}}}}`, 200)
	w := serve(s, "/portal/api/scans/scan-one/artifacts")
	if w.Code != 200 || *calls != 1 {
		t.Fatal(w.Code)
	}
	for _, want := range []string{"report.md", "findings.json", "evidence/vuln-0001.md"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatal("missing artifact", want)
		}
	}
	for _, bad := range []string{"PRIVATE", "secret", "events.jsonl", "size"} {
		if strings.Contains(w.Body.String(), bad) {
			t.Fatal("unsafe manifest projection", bad)
		}
	}
}
func TestEvidenceNamesAndOwnership(t *testing.T) {
	for _, name := range []string{"../report.md", "evidence/../x.md", "evidence%2F..%2Fx.md", "evidence/.md", "evidence/x.html", "events.jsonl"} {
		s, _, calls := fixture(t, `{}`, 200)
		w := serve(s, "/portal/scans/scan-one/evidence?name="+name)
		if w.Code != 404 || *calls != 0 {
			t.Fatal("unsafe name dispatched", name, w.Code)
		}
	}
	s, _, calls := fixture(t, `{}`, 403)
	if w := serve(s, "/portal/scans/scan-one/evidence?name=evidence/vuln-0001.md"); w.Code != 403 || *calls != 1 {
		t.Fatal("owner denial bypassed")
	}
}
func TestEvidenceDownloadPathFixedAndTyped(t *testing.T) {
	s, _, calls := fixture(t, `{"scan_id":"scan-one"}`, 200)
	original := s.Proxy.Client.Transport
	s.Proxy.Client.Transport = transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/scans/scan-one" {
			return original.RoundTrip(r)
		}
		*calls++
		if r.URL.Path != "/reports/scan-one/downloads/evidence/vuln-0001.md" || r.URL.RawQuery != "" || r.URL.Host != "upstream.example" {
			t.Fatal(r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/markdown; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader("proof"))}, nil
	})
	w := serve(s, "/portal/scans/scan-one/evidence?name=evidence%2Fvuln-0001.md")
	if w.Code != 200 || *calls != 2 || w.Body.String() != "proof" || w.Header().Get("Content-Disposition") != `attachment; filename="scan-one-vuln-0001.md"` {
		t.Fatal(w.Code, w.Header(), w.Body.String())
	}
}
