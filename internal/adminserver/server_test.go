package adminserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"portico-gateway/internal/adminauth"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/modelpolicy"
	"strings"
	"testing"
)

type fakeAuth struct {
	err  error
	csrf bool
}

func (a fakeAuth) Authenticate(*http.Request) (identity.Identity, string, error) {
	return identity.Identity{Issuer: "iss", Subject: "admin"}, "csrf", a.err
}
func (a fakeAuth) CheckCSRF(*http.Request) bool                { return a.csrf }
func (a fakeAuth) Login(http.ResponseWriter, *http.Request)    {}
func (a fakeAuth) Callback(http.ResponseWriter, *http.Request) {}
func (a fakeAuth) Logout(http.ResponseWriter, *http.Request)   {}

type fakeDualAuth struct{ fakeAuth }

func (fakeDualAuth) LocalLogin(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusTeapot)
}
func (fakeDualAuth) OIDCLogin(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusAccepted)
}

func TestSeparateAdminLoginRoutes(t *testing.T) {
	s := &Server{Auth: fakeDualAuth{}}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/admin/local/login", http.StatusTeapot},
		{"GET", "/admin/oidc/login", http.StatusAccepted},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
}

type fakePolicies struct{ updated bool }

func (p *fakePolicies) Read(context.Context) (modelpolicy.Snapshot, error) {
	return modelpolicy.Snapshot{Revision: 1, Rules: map[string][]string{"g": {"triage"}}}, nil
}
func (p *fakePolicies) History(context.Context) ([]modelpolicy.Audit, error) { return nil, nil }
func (p *fakePolicies) Update(context.Context, int64, string, map[string][]string) error {
	p.updated = true
	return nil
}
func TestAdminAuthorizationAndCSRF(t *testing.T) {
	for _, tc := range []struct {
		a      fakeAuth
		status int
	}{{fakeAuth{err: adminauth.ErrForbidden}, 403}, {fakeAuth{err: adminauth.ErrUnauthorized}, 401}, {fakeAuth{}, 403}} {
		p := &fakePolicies{}
		s := &Server{Auth: tc.a, Policies: p}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/admin/models", nil))
		if w.Code != tc.status || p.updated {
			t.Fatal(w.Code, p.updated)
		}
	}
}
func TestCatalogBoundsNewGrants(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key" {
			t.Error("missing key")
		}
		w.Write([]byte(`{"data":[{"id":"triage"}]}`))
	}))
	defer up.Close()
	for _, tc := range []struct {
		model  string
		status int
	}{{"pentest", 400}, {"triage", 303}} {
		p := &fakePolicies{}
		s := &Server{Auth: fakeAuth{csrf: true}, Policies: p, CatalogURL: up.URL, CatalogKey: "key", Client: up.Client()}
		form := url.Values{"group": {"g"}, "models": {tc.model}, "revision": {"1"}, "csrf": {"csrf"}}
		r := httptest.NewRequest("POST", "/admin/models", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.status || p.updated != (tc.status == 303) {
			t.Fatal(w.Code, p.updated, w.Body.String())
		}
	}
}
func TestParseEmptyAndDuplicateRows(t *testing.T) {
	r, e := parseRules(url.Values{"group": {"", "g"}, "models": {"", "triage, pentest"}})
	if e != nil || len(r) != 1 {
		t.Fatal(r, e)
	}
	for _, f := range []url.Values{{"group": {"g", "g"}, "models": {"a", "b"}}, {"group": {"g"}, "models": {""}}, {"group": {"g"}, "models": {"a,a"}}} {
		if _, e = parseRules(f); e == nil {
			t.Fatal(f)
		}
	}
}
