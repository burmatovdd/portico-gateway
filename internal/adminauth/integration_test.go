package adminauth

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"strings"
	"testing"
	"time"
)

type fakeOIDC struct {
	state, nonce, pkce, redirect string
	exchanges                    int
}

func (p *fakeOIDC) AuthorizationURL(state, nonce, pkce, redirect string) (string, error) {
	p.state, p.nonce, p.pkce, p.redirect = state, nonce, pkce, redirect
	return "https://idp.example/authorize?state=" + state, nil
}
func (p *fakeOIDC) ExchangeCode(_ context.Context, code, verifier, redirect, nonce string) (identity.Tokens, error) {
	p.exchanges++
	if code != "ok" || challenge(verifier) != p.pkce || nonce != p.nonce || redirect != p.redirect {
		return identity.Tokens{}, ErrUnauthorized
	}
	return identity.Tokens{AccessToken: "secret"}, nil
}
func integrationServer(t *testing.T) (*Server, *fakeOIDC) {
	t.Helper()
	dsn := os.Getenv("PORTICO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PostgreSQL integration requires PORTICO_TEST_DATABASE_URL")
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.MaxConns = 1
	pool, e := pgxpool.NewWithConfig(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	s, _, _ := setup(t)
	v, _ := vault.New(make([]byte, 32))
	idp := &fakeOIDC{}
	s, e = New(s.public, []string{"admins"}, pool, v, s.sessions, idp)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	return s, idp
}
func startLogin(t *testing.T, s *Server, p *fakeOIDC) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	s.Login(w, httptest.NewRequest("GET", s.public+"/admin/login", nil))
	if w.Code != 303 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != flowCookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].MaxAge != 300 {
		t.Fatalf("flow cookie: %+v", cookies)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), "DELETE FROM portico_admin_flows WHERE id=$1", session.Hash(p.state))
	})
	return cookies[0]
}
func callback(s *Server, p *fakeOIDC, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", s.public+"/admin/callback?"+url.Values{"state": {p.state}, "code": {"ok"}}.Encode(), nil)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.Callback(w, r)
	return w
}
func TestPostgresFlowBoundEncryptedSingleUse(t *testing.T) {
	s, p := integrationServer(t)
	c := startLogin(t, s, p)
	if p.redirect != s.public+"/admin/callback" || len(p.nonce) != 43 || len(p.pkce) != 43 {
		t.Fatal("missing OIDC bindings")
	}
	var data []byte
	if e := s.pool.QueryRow(context.Background(), "SELECT data FROM portico_admin_flows WHERE id=$1", session.Hash(p.state)).Scan(&data); e != nil {
		t.Fatal(e)
	}
	if json.Valid(data) || strings.Contains(string(data), c.Value) {
		t.Fatal("unencrypted login state")
	}
	wrong := *c
	wrong.Value = session.NewCredential()
	if w := callback(s, p, &wrong); w.Code != 400 || p.exchanges != 0 {
		t.Fatalf("wrong browser accepted: %d", w.Code)
	}
	w := callback(s, p, c)
	if w.Code != 303 || w.Header().Get("Location") != "/admin/" || p.exchanges != 1 {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	var handle string
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == cookieName {
			handle = cookie.Value
			if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("weak session cookie")
			}
		}
	}
	if len(handle) != 43 {
		t.Fatal("missing admin session")
	}
	if _, _, e := s.Authenticate(request(handle)); e != nil {
		t.Fatal(e)
	}
	if w := callback(s, p, c); w.Code != 400 || p.exchanges != 1 {
		t.Fatalf("replayed exchange: %d, %d", w.Code, p.exchanges)
	}
}
func TestPostgresExpiredFlowCannotExchange(t *testing.T) {
	s, p := integrationServer(t)
	c := startLogin(t, s, p)
	if _, e := s.pool.Exec(context.Background(), "UPDATE portico_admin_flows SET expires_at=now()-interval '1 second' WHERE id=$1", session.Hash(p.state)); e != nil {
		t.Fatal(e)
	}
	if w := callback(s, p, c); w.Code != 400 || p.exchanges != 0 {
		t.Fatal("expired flow accepted")
	}
	if e := s.Cleanup(context.Background()); e != nil {
		t.Fatal(e)
	}
	var count int
	if e := s.pool.QueryRow(context.Background(), "SELECT count(*) FROM portico_admin_flows WHERE id=$1", session.Hash(p.state)).Scan(&count); e != nil || count != 0 {
		t.Fatal("expired flow retained", e)
	}
}

func TestPostgresPortalFlowCannotBeConsumedByAdmin(t *testing.T) {
	admin, p := integrationServer(t)
	portal, e := NewPortal(admin.public, []string{"admins"}, admin.pool, admin.vault, admin.sessions, p)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	portal.Login(w, httptest.NewRequest("GET", portal.public+"/portal/login", nil))
	if w.Code != 303 || p.redirect != portal.public+"/portal/callback" {
		t.Fatal("portal login", w.Code, p.redirect)
	}
	var binding *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == portal.loginCookie() {
			binding = c
		}
	}
	if binding == nil {
		t.Fatal("missing portal login cookie")
	}
	t.Cleanup(func() {
		_, _ = admin.pool.Exec(context.Background(), "DELETE FROM portico_admin_flows WHERE id=$1", session.Hash(p.state))
	})
	if got := callback(admin, p, binding); got.Code != 400 || p.exchanges != 0 {
		t.Fatal("admin consumed portal flow", got.Code)
	}
	r := httptest.NewRequest("GET", portal.public+"/portal/callback?"+url.Values{"state": {p.state}, "code": {"ok"}}.Encode(), nil)
	r.AddCookie(binding)
	w = httptest.NewRecorder()
	portal.Callback(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/portal/" || p.exchanges != 1 {
		t.Fatal("portal callback", w.Code, w.Body.String())
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == portal.sessionCookie() {
			found = true
		}
		if c.Name == cookieName {
			t.Fatal("admin session cookie written")
		}
	}
	if !found {
		t.Fatal("missing portal session cookie")
	}
}
