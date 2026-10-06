package modelaccess

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type changingPolicy struct {
	grant string
	err   error
}

func (p *changingPolicy) Allowed(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{p.grant: true}, p.err
}
func TestPolicyChangesWithoutRestartAndFailsClosed(t *testing.T) {
	p := &changingPolicy{grant: "triage"}
	s := New(verifier{[]string{"g"}}, Config{Rules: map[string][]string{"g": {"static"}}}, "k", http.DefaultClient)
	s.Policy = p
	h := s.Handler()
	for _, model := range []string{"triage", "pentest"} {
		p.grant = model
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/v1/models", nil)
		r.Header.Set("Authorization", "Bearer x")
		h.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), model) || strings.Contains(w.Body.String(), "static") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	p.err = errors.New("offline")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/models", nil)
	r.Header.Set("Authorization", "Bearer x")
	h.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
func TestOverflowRetriesOnlyWithSmallerHistory(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":{"code":"context_length_exceeded"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer up.Close()
	s := New(verifier{[]string{"g"}}, Config{Upstream: up.URL, Rules: map[string][]string{"g": {"triage"}}, MaxRequestBytes: 10000, MaxDurationSeconds: 30, ContextBudgets: map[string]ContextBudget{"triage": {WindowTokens: 16384, ReserveTokens: 2048}}}, "k", up.Client())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"triage","messages":[{"role":"user","content":"old"},{"role":"assistant","content":"old answer"},{"role":"user","content":"current"}]}`))
	r.Header.Set("Authorization", "Bearer x")
	r.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || calls != 2 || w.Header().Get("X-Portico-Context-Turns-Removed") != "1" {
		t.Fatal(w.Code, calls, w.Header())
	}
}

func TestPolicyReadinessFailsClosedButLivenessRemainsHealthy(t *testing.T) {
	p := &changingPolicy{grant: "triage", err: errors.New("database offline")}
	s := New(verifier{}, Config{}, "k", http.DefaultClient)
	s.Policy = p
	for _, tc := range []struct {
		path   string
		status int
	}{{"/readyz", 503}, {"/healthz", 200}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
	p.err = nil
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
