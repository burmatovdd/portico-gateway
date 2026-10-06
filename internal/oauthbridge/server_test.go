package oauthbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/postgres"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
)

type fakeIDP struct{}

func (fakeIDP) Verify(context.Context, string) (identity.Identity, error) {
	return identity.Identity{Issuer: "https://idp.example", Subject: "user", Expires: time.Now().Add(time.Hour)}, nil
}
func (fakeIDP) Refresh(context.Context, string) (identity.Tokens, error) {
	return identity.Tokens{AccessToken: "access", RefreshToken: "refresh"}, nil
}
func (fakeIDP) AuthorizationURL(state, nonce, pkce, redirect string) (string, error) {
	return "https://idp.example/authorize?state=" + state, nil
}
func (fakeIDP) ExchangeCode(context.Context, string, string, string, string) (identity.Tokens, error) {
	return identity.Tokens{AccessToken: "access", RefreshToken: "refresh"}, nil
}
func testServer(t *testing.T) *Server {
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
	store := &postgres.Store{Pool: pool}
	if e = store.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	v, _ := vault.New(make([]byte, 32))
	sessions := &session.Manager{Store: store, Vault: v, Provider: fakeIDP{}, MaxAge: time.Hour, IdleAge: time.Hour}
	s, e := New("https://gateway.example", []Client{{ID: "native", RedirectURIs: []string{"http://127.0.0.1:9000/callback"}}, {ID: "other", RedirectURIs: []string{"https://other.example/callback"}}}, pool, v, sessions, nil)
	if e != nil {
		t.Fatal(e)
	}
	s.idp = fakeIDP{}
	if e = s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	return s
}
func post(s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func grant(t *testing.T, s *Server) (string, string, string) {
	t.Helper()
	handle, e := s.sessions.Create(context.Background(), identity.Tokens{AccessToken: "access", RefreshToken: "refresh"})
	if e != nil {
		t.Fatal(e)
	}
	code, verifier := session.NewCredential(), session.NewCredential()
	data, e := s.seal(codeGrant{"native", "http://127.0.0.1:9000/callback", challenge(verifier), handle, time.Now().Add(time.Hour)}, "code:"+session.Hash(code))
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.pool.Exec(context.Background(), "INSERT INTO portico_oauth_codes(id,data,expires_at) VALUES($1,$2,$3)", session.Hash(code), data, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	return code, verifier, handle
}
func exchangeForm(code, verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {"native"}, "redirect_uri": {"http://127.0.0.1:9000/callback"}, "resource": {"https://gateway.example/mcp"}, "code": {code}, "code_verifier": {verifier}}
}
func result(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var v map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func TestCodeBindingResourceAndReplay(t *testing.T) {
	s := testServer(t)
	code, verifier, handle := grant(t, s)
	f := exchangeForm(code, verifier)
	f.Set("resource", "https://evil.example/mcp")
	if w := post(s, "/oauth/token", f); w.Code != 400 {
		t.Fatal("accepted wrong resource")
	}
	f.Set("resource", s.resource)
	f.Set("code_verifier", session.NewCredential())
	if w := post(s, "/oauth/token", f); w.Code != 400 {
		t.Fatal("accepted wrong PKCE")
	}
	f.Set("code_verifier", verifier)
	f.Set("client_id", "other")
	if w := post(s, "/oauth/token", f); w.Code != 400 {
		t.Fatal("accepted wrong client")
	}
	f.Set("client_id", "native")
	tokens := result(t, post(s, "/oauth/token", f))
	if w := post(s, "/oauth/token", f); w.Code != 400 {
		t.Fatal("accepted code replay")
	}
	got, _, e := s.AuthorizeMCP(context.Background(), tokens["access_token"].(string))
	if e != nil || got != handle {
		t.Fatal("facade did not resolve internal handle")
	}
	if tokens["access_token"] == handle {
		t.Fatal("exposed internal session credential")
	}
}
func TestRefreshRotationReuseAndRevocation(t *testing.T) {
	s := testServer(t)
	code, verifier, handle := grant(t, s)
	tokens := result(t, post(s, "/oauth/token", exchangeForm(code, verifier)))
	refresh := tokens["refresh_token"].(string)
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"native"}, "resource": {s.resource}, "refresh_token": {refresh}}
	next := result(t, post(s, "/oauth/token", form))
	if next["refresh_token"] == refresh {
		t.Fatal("refresh not rotated")
	}
	if _, _, e := s.AuthorizeMCP(context.Background(), tokens["access_token"].(string)); e == nil {
		t.Fatal("old access token still active")
	}
	if w := post(s, "/oauth/token", form); w.Code != 400 {
		t.Fatal("reuse accepted")
	}
	if _, _, e := s.AuthorizeMCP(context.Background(), next["access_token"].(string)); e == nil {
		t.Fatal("reuse did not revoke family")
	}
	if _, _, e := s.sessions.Access(context.Background(), handle); e == nil {
		t.Fatal("reuse did not revoke upstream session")
	}
	code, verifier, _ = grant(t, s)
	tokens = result(t, post(s, "/oauth/token", exchangeForm(code, verifier)))
	w := post(s, "/oauth/revoke", url.Values{"client_id": {"native"}, "token": {tokens["access_token"].(string)}})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if _, _, e := s.AuthorizeMCP(context.Background(), tokens["access_token"].(string)); e == nil {
		t.Fatal("revoked token accepted")
	}
}
func TestConsentBindingAndCallbackSingleUse(t *testing.T) {
	s := testServer(t)
	id, cookie := session.NewCredential(), session.NewCredential()
	f := flow{Client: "native", Redirect: "http://127.0.0.1:9000/callback", Challenge: challenge(session.NewCredential()), Cookie: session.Hash(cookie), CSRF: session.NewCredential(), Nonce: session.NewCredential(), Verifier: session.NewCredential()}
	data, _ := s.seal(f, "flow:"+session.Hash(id))
	_, e := s.pool.Exec(context.Background(), "INSERT INTO portico_oauth_flows(id,data,expires_at,phase) VALUES($1,$2,$3,'consent')", session.Hash(id), data, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	call := func(path, origin, csrf, c string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"transaction": {id}, "csrf": {csrf}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := call("/oauth/login", "https://evil.example", f.CSRF, cookie); w.Code != 403 {
		t.Fatal("cross-origin consent accepted")
	}
	if w := call("/oauth/login", s.public, f.CSRF, "wrong"); w.Code != 403 {
		t.Fatal("unbound cookie accepted")
	}
	if w := call("/oauth/login", s.public, f.CSRF, cookie); w.Code != 303 {
		t.Fatal(w.Code)
	}
	callback := func(c string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/oauth/callback?code=upstream&state="+id, nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := callback("wrong"); w.Code != 400 {
		t.Fatal("callback cookie bypass")
	}
	if w := callback(cookie); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := callback(cookie); w.Code != 400 {
		t.Fatal("callback replay accepted")
	}
}
func TestRejectUnsafeClientRedirect(t *testing.T) {
	_, e := New("https://gateway.example", []Client{{ID: "native", RedirectURIs: []string{"http://external.example/callback"}}}, nil, nil, nil, nil)
	if e == nil {
		t.Fatal("HTTP external redirect accepted")
	}
}

func TestRefreshChecksUnderlyingSessionWithoutExtendingIdle(t *testing.T) {
	for _, mode := range []string{"logout", "idle", "active"} {
		t.Run(mode, func(t *testing.T) {
			s := testServer(t)
			code, verifier, handle := grant(t, s)
			tokens := result(t, post(s, "/oauth/token", exchangeForm(code, verifier)))
			var idle time.Time
			if e := s.pool.QueryRow(context.Background(), "SELECT idle_until FROM portico_sessions WHERE credential_hash=$1", session.Hash(handle)).Scan(&idle); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "logout":
				if e := s.sessions.Logout(context.Background(), handle); e != nil {
					t.Fatal(e)
				}
			case "idle":
				if _, e := s.pool.Exec(context.Background(), "UPDATE portico_sessions SET idle_until=now()-interval '1 second' WHERE credential_hash=$1", session.Hash(handle)); e != nil {
					t.Fatal(e)
				}
			}
			// Resource omission on refresh defaults only to the family's fixed MCP resource.
			form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"native"}, "refresh_token": {tokens["refresh_token"].(string)}}
			form.Set("resource", "https://wrong.example/mcp")
			if w := post(s, "/oauth/token", form); w.Code != 400 {
				t.Fatal("wrong resource accepted")
			}
			form.Del("resource")
			w := post(s, "/oauth/token", form)
			if mode != "active" {
				if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
					t.Fatal(w.Code, w.Body.String())
				}
				if _, _, e := s.AuthorizeMCP(context.Background(), tokens["access_token"].(string)); e == nil {
					t.Fatal("inactive underlying session did not revoke family")
				}
				return
			}
			result(t, w)
			var after time.Time
			if e := s.pool.QueryRow(context.Background(), "SELECT idle_until FROM portico_sessions WHERE credential_hash=$1", session.Hash(handle)).Scan(&after); e != nil {
				t.Fatal(e)
			}
			if !after.Equal(idle) {
				t.Fatal("refresh extended idle expiry")
			}
		})
	}
}
func TestConsentCSPAllowsTrustedIdPAndRegisteredCallback(t *testing.T) {
	s := testServer(t)
	query := url.Values{"client_id": {"native"}, "redirect_uri": {"http://127.0.0.1:9000/callback"}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge(session.NewCredential())}, "scope": {"mcp"}, "resource": {s.resource}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/oauth/authorize?"+query.Encode(), nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://idp.example http://127.0.0.1:9000;") {
		t.Fatal("IdP redirect blocked by CSP", csp)
	}
	if strings.Contains(csp, "evil.example") || strings.Contains(csp, "*") {
		t.Fatal("untrusted callback origin allowed in form-action")
	}
}
