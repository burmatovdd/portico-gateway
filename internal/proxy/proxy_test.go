package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"portico-gateway/internal/identity"
	"testing"
)

func TestRoutesOnlyRegisteredOperations(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/reports/scan-1" || r.Header.Get("Authorization") != "Bearer upstream-token" {
			t.Error("incorrect upstream request")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	p := &Proxy{Client: srv.Client(), Services: map[string]Service{"reports": {BaseURL: srv.URL, Roles: []string{"reader"}, Operations: map[string]Operation{"get": {Method: "GET", Path: "/reports/{id}", Parameters: map[string]Parameter{"id": {Kind: "id", In: "path", Required: true}}}}}}}
	id := identity.Identity{Roles: []string{"reader"}}
	if _, e := p.Call(context.Background(), id, "upstream-token", "reports", "get", map[string]any{"id": "../admin"}); e == nil {
		t.Fatal("accepted traversal")
	}
	if _, e := p.Call(context.Background(), identity.Identity{}, "upstream-token", "reports", "get", map[string]any{"id": "scan-1"}); e == nil {
		t.Fatal("accepted missing role")
	}
	if _, e := p.Call(context.Background(), id, "upstream-token", "reports", "get", map[string]any{"id": "scan-1", "url": "https://evil.example"}); e == nil {
		t.Fatal("accepted unregistered argument")
	}
	r, e := p.Call(context.Background(), id, "upstream-token", "reports", "get", map[string]any{"id": "scan-1"})
	if e != nil || r.Status != 200 {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatalf("unexpected upstream calls: %d", calls)
	}
}
func TestNeverFollowsRedirectWithToken(t *testing.T) {
	leaked := false
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer srv.Close()
	p := &Proxy{Client: srv.Client(), Services: map[string]Service{"s": {BaseURL: srv.URL, Roles: []string{"r"}, Operations: map[string]Operation{"get": {Method: "GET", Path: "/"}}}}}
	if _, e := p.Call(context.Background(), identity.Identity{Roles: []string{"r"}}, "secret", "s", "get", nil); e == nil {
		t.Fatal("accepted redirect")
	}
	if leaked {
		t.Fatal("token sent to another origin")
	}
}
