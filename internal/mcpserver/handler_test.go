package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/proxy"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"strings"
	"sync"
	"testing"
	"time"
)

type memory struct {
	mu   sync.Mutex
	rows map[string]*session.Record
}

func (s *memory) Create(_ context.Context, h string, r session.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[h] = &r
	return nil
}
func (s *memory) Locked(_ context.Context, h string, f func(*session.Record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[h]
	if r == nil {
		return session.ErrUnauthorized
	}
	return f(r)
}

type provider struct{}

func (provider) Verify(_ context.Context, t string) (identity.Identity, error) {
	return identity.Identity{Issuer: "https://idp.example", Subject: t, Roles: []string{t}, Expires: time.Now().Add(time.Hour)}, nil
}
func (provider) Refresh(context.Context, string) (identity.Tokens, error) {
	return identity.Tokens{}, errors.New("unused")
}

type authorizer map[string]string

func (a authorizer) AuthorizeMCP(_ context.Context, t string) (string, time.Time, error) {
	c, ok := a[t]
	if !ok {
		return "", time.Time{}, errors.New("SECRET backend details")
	}
	return c, time.Now().Add(time.Hour), nil
}
func fixture(t *testing.T) (http.Handler, *session.Manager, string, *int) {
	t.Helper()
	v, _ := vault.New(make([]byte, 32))
	m := &session.Manager{Store: &memory{rows: map[string]*session.Record{}}, Vault: v, Provider: provider{}, MaxAge: time.Hour, IdleAge: time.Hour}
	a, _ := m.Create(context.Background(), identity.Tokens{AccessToken: "reader"})
	b, _ := m.Create(context.Background(), identity.Tokens{AccessToken: "admin"})
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer reader" {
			t.Error("wrong upstream credential")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)
	p := &proxy.Proxy{Client: up.Client(), Services: map[string]proxy.Service{"app": {BaseURL: up.URL, Roles: []string{"reader"}, Operations: map[string]proxy.Operation{"read": {Method: "GET", Path: "/read", Parameters: map[string]proxy.Parameter{"id": {Kind: "id", In: "query", Required: true}}}}}, "admin": {BaseURL: up.URL, Roles: []string{"admin"}, Operations: map[string]proxy.Operation{"read": {Method: "GET", Path: "/"}}}}}
	return Handler("https://gateway.example", []string{"https://trusted.example"}, authorizer{"oauth-a": a, "oauth-b": b}, m, p), m, a, &calls
}
func rpc(h http.Handler, token, origin, method string, params any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	r := httptest.NewRequest("POST", "http://localhost/mcp", strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAuthenticationAndOrigin(t *testing.T) {
	h, _, _, _ := fixture(t)
	for _, token := range []string{"", "invalid"} {
		w := rpc(h, token, "", "initialize", map[string]any{})
		if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "https://gateway.example/.well-known/oauth-protected-resource/mcp") || strings.Contains(w.Body.String(), "SECRET") {
			t.Fatalf("bad challenge: %d %s %s", w.Code, w.Header(), w.Body)
		}
	}
	if w := rpc(h, "oauth-a", "https://evil.example", "tools/list", map[string]any{}); w.Code != 403 {
		t.Fatalf("origin accepted: %d", w.Code)
	}
	w := rpc(h, "oauth-a", "https://trusted.example", "initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "serverInfo") || w.Header().Get("Mcp-Session-Id") != "" {
		t.Fatalf("initialize: %d %s", w.Code, w.Body)
	}
}
func TestRolesCallsAndLogout(t *testing.T) {
	h, m, c, calls := fixture(t)
	for _, tc := range []struct{ token, want, absent string }{{"oauth-a", "app__read", "admin__read"}, {"oauth-b", "admin__read", "app__read"}} {
		w := rpc(h, tc.token, "", "tools/list", map[string]any{})
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.want) || strings.Contains(w.Body.String(), tc.absent) {
			t.Fatalf("role leak: %d %s", w.Code, w.Body)
		}
	}
	for _, args := range []any{map[string]any{}, map[string]any{"id": "../x"}, map[string]any{"id": "ok", "extra": true}, nil, []string{"bad"}} {
		rpc(h, "oauth-a", "", "tools/call", map[string]any{"name": "app__read", "arguments": args})
	}
	rpc(h, "oauth-b", "", "tools/call", map[string]any{"name": "app__read", "arguments": map[string]any{"id": "ok"}})
	if *calls != 0 {
		t.Fatal("invalid or unauthorized call reached upstream")
	}
	w := rpc(h, "oauth-a", "", "tools/call", map[string]any{"name": "app__read", "arguments": map[string]any{"id": "ok"}})
	if *calls != 1 || !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("call: %s", w.Body)
	}
	rpc(h, "oauth-a", "", "tools/call", map[string]any{"name": "portico_logout", "arguments": map[string]any{"other": "user"}})
	if _, _, err := m.Access(context.Background(), c); err != nil {
		t.Fatal("logout accepted arguments")
	}
	w = rpc(h, "oauth-a", "", "tools/call", map[string]any{"name": "portico_logout", "arguments": map[string]any{}})
	if !strings.Contains(w.Body.String(), "not canceled") {
		t.Fatalf("logout result: %s", w.Body)
	}
	if w = rpc(h, "oauth-a", "", "tools/list", map[string]any{}); w.Code != 401 {
		t.Fatalf("logged out call accepted: %d %s", w.Code, w.Body)
	}
	if w = rpc(h, "oauth-b", "", "tools/list", map[string]any{}); w.Code != 200 {
		t.Fatal("logout affected other user")
	}
}

// The provider changes roles between transport authentication and tool dispatch.
// A list-time or middleware-only authorization check would incorrectly call upstream.
type changedRoles struct{ calls int }

func (p *changedRoles) Verify(_ context.Context, token string) (identity.Identity, error) {
	p.calls++
	roles := []string{"reader"}
	if p.calls > 1 {
		roles = []string{"admin"}
	}
	return identity.Identity{Issuer: "https://idp.example", Subject: token, Roles: roles, Expires: time.Now().Add(time.Hour)}, nil
}
func (*changedRoles) Refresh(context.Context, string) (identity.Tokens, error) {
	return identity.Tokens{}, errors.New("unused")
}
func TestCallRechecksCurrentRoles(t *testing.T) {
	h, m, _, calls := fixture(t)
	m.Provider = &changedRoles{}
	w := rpc(h, "oauth-a", "", "tools/call", map[string]any{"name": "app__read", "arguments": map[string]any{"id": "ok"}})
	if *calls != 0 || !strings.Contains(w.Body.String(), "operation is not permitted") {
		t.Fatalf("stale roles permitted call: %d %s", *calls, w.Body)
	}
}
func TestBodyLimitAndPreflight(t *testing.T) {
	h, _, _, calls := fixture(t)
	w := rpc(h, "oauth-a", "", "tools/call", map[string]any{"name": "app__read", "arguments": map[string]any{"id": strings.Repeat("a", 70<<10)}})
	if w.Code != http.StatusRequestEntityTooLarge || *calls != 0 {
		t.Fatalf("body limit: %d %s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		origin string
		status int
	}{{"https://trusted.example", 204}, {"null", 403}, {"https://evil.example", 403}} {
		r := httptest.NewRequest("OPTIONS", "http://localhost/mcp", nil)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("preflight %s: %d", tc.origin, w.Code)
		}
		if tc.status == 204 && w.Header().Get("Access-Control-Allow-Origin") != tc.origin {
			t.Fatal("missing allow origin")
		}
	}
	r := httptest.NewRequest("POST", "http://localhost/mcp", nil)
	r.Header.Add("Origin", "https://trusted.example")
	r.Header.Add("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("ambiguous origin accepted")
	}
}
