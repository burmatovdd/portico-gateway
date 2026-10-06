package adminauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"strings"
	"testing"
	"time"
)

type memory struct{ rows map[string]*session.Record }

func (m *memory) Create(_ context.Context, k string, r session.Record) error {
	m.rows[k] = &r
	return nil
}
func (m *memory) Locked(_ context.Context, k string, f func(*session.Record) error) error {
	if m.rows[k] == nil {
		return session.ErrUnauthorized
	}
	return f(m.rows[k])
}

type provider struct {
	roles []string
	calls int
}

func (p *provider) Verify(context.Context, string) (identity.Identity, error) {
	p.calls++
	return identity.Identity{Issuer: "idp", Subject: "user", Roles: p.roles, Expires: time.Now().Add(time.Hour)}, nil
}
func (p *provider) Refresh(context.Context, string) (identity.Tokens, error) {
	return identity.Tokens{}, errors.New("unused")
}
func setup(t *testing.T) (*Server, *provider, string) {
	t.Helper()
	v, _ := vault.New(make([]byte, 32))
	p := &provider{roles: []string{"admins"}}
	m := &session.Manager{Store: &memory{map[string]*session.Record{}}, Vault: v, Provider: p, MaxAge: time.Hour, IdleAge: time.Hour}
	c, e := m.Create(context.Background(), identity.Tokens{AccessToken: "secret"})
	if e != nil {
		t.Fatal(e)
	}
	return &Server{public: "https://portico.example", groups: map[string]bool{"admins": true}, sessions: m}, p, c
}
func request(c string) *http.Request {
	r := httptest.NewRequest("GET", "https://portico.example/admin/", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
	return r
}
func TestAuthenticateRevalidatesExactSignedGroups(t *testing.T) {
	s, p, c := setup(t)
	_, csrf, e := s.Authenticate(request(c))
	if e != nil || csrf == "" {
		t.Fatal(e)
	}
	p.roles = []string{"Admins", "org/admins", "admins-suffix"}
	if _, _, e = s.Authenticate(request(c)); !errors.Is(e, ErrForbidden) {
		t.Fatalf("group match: %v", e)
	}
	if p.calls != 3 {
		t.Fatalf("provider calls: %d", p.calls)
	}
}
func TestMCPAuthIsNotAdminCookie(t *testing.T) {
	s, _, c := setup(t)
	r := httptest.NewRequest("GET", "https://portico.example/admin/", nil)
	r.Header.Set("Authorization", "Bearer "+c)
	r.AddCookie(&http.Cookie{Name: "__Host-portico-oauth", Value: c})
	if _, _, e := s.Authenticate(r); !errors.Is(e, ErrUnauthorized) {
		t.Fatal(e)
	}
}
func TestCSRFRequiresOriginMethodAndBoundToken(t *testing.T) {
	s, _, c := setup(t)
	_, token, _ := s.Authenticate(request(c))
	for _, tt := range []struct {
		method, origin, token string
		want                  bool
	}{{"POST", s.public, token, true}, {"GET", s.public, token, false}, {"POST", "", token, false}, {"POST", "https://evil.example", token, false}, {"POST", s.public, "wrong", false}} {
		r := httptest.NewRequest(tt.method, s.public+"/admin/logout", strings.NewReader(url.Values{"csrf": {tt.token}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", tt.origin)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
		if got := s.CheckCSRF(r); got != tt.want {
			t.Errorf("%+v: %v", tt, got)
		}
	}
}
func TestFlowBinding(t *testing.T) {
	cookie := session.NewCredential()
	f := flow{Cookie: session.Hash(cookie)}
	r := httptest.NewRequest("GET", "https://portico.example/admin/callback", nil)
	if bound(r, f) {
		t.Fatal("missing cookie accepted")
	}
	r.AddCookie(&http.Cookie{Name: flowCookieName, Value: session.NewCredential()})
	if bound(r, f) {
		t.Fatal("different browser accepted")
	}
	r = httptest.NewRequest("GET", "https://portico.example/admin/callback", nil)
	r.AddCookie(&http.Cookie{Name: flowCookieName, Value: cookie})
	if !bound(r, f) {
		t.Fatal("bound browser rejected")
	}
}
func TestLogoutRequiresCSRFAndRevokesSession(t *testing.T) {
	s, _, c := setup(t)
	w := httptest.NewRecorder()
	s.Logout(w, request(c))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal(w.Code)
	}
	_, token, _ := s.Authenticate(request(c))
	r := httptest.NewRequest("POST", s.public+"/admin/logout", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
	r.Header.Set("Origin", s.public)
	r.Header.Set("X-CSRF-Token", token)
	w = httptest.NewRecorder()
	s.Logout(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatal(w.Code)
	}
	if _, _, e := s.Authenticate(request(c)); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("logout did not revoke", e)
	}
}

func TestCSRFIsBoundToSessionAndCannotUseQuery(t *testing.T) {
	s, _, c := setup(t)
	_, token, _ := s.Authenticate(request(c))
	other := session.NewCredential()
	r := httptest.NewRequest("POST", s.public+"/admin/logout", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: other})
	r.Header.Set("Origin", s.public)
	r.Header.Set("X-CSRF-Token", token)
	if s.CheckCSRF(r) {
		t.Fatal("token from different session accepted")
	}
	r = httptest.NewRequest("POST", s.public+"/admin/logout?csrf="+token, strings.NewReader(""))
	r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
	r.Header.Set("Origin", s.public)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.CheckCSRF(r) {
		t.Fatal("query token accepted")
	}
}
func TestDuplicateCookiesAndOriginsRejected(t *testing.T) {
	s, _, c := setup(t)
	r := request(c)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
	if _, _, e := s.Authenticate(r); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("duplicate cookies accepted")
	}
	r = httptest.NewRequest("POST", s.public+"/admin/logout", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
	r.Header.Add("Origin", s.public)
	r.Header.Add("Origin", "https://evil.example")
	r.Header.Set("X-CSRF-Token", csrf(c))
	if s.CheckCSRF(r) {
		t.Fatal("duplicate origins accepted")
	}
}
func TestCSRFFormSizeIsBounded(t *testing.T) {
	s, _, c := setup(t)
	body := "csrf=" + csrf(c) + "&padding=" + strings.Repeat("x", 65<<10)
	r := httptest.NewRequest("POST", s.public+"/admin/logout", strings.NewReader(body))
	r.Header.Set("Origin", s.public)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
	if s.CheckCSRF(r) {
		t.Fatal("oversize body accepted")
	}
}
