package modelaccess

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"portico-gateway/internal/identity"
	"strings"
	"testing"
	"time"
)

type verifier struct{ groups []string }

func (v verifier) Verify(context.Context, string) (identity.Identity, error) {
	return identity.Identity{Subject: "u", Roles: v.groups, Expires: time.Now().Add(time.Minute)}, nil
}
func TestPolicyAndUpstreamBoundary(t *testing.T) {
	called := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Header.Get("Authorization") != "Bearer upstream-key" || r.Header.Get("Cookie") != "" {
			t.Error("credential boundary failed")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()
	s := New(verifier{[]string{"example/red-team"}}, Config{Upstream: upstream.URL, Rules: map[string][]string{"example/red-team": {"pentest"}}, MaxRequestBytes: 1048576, MaxDurationSeconds: 60}, "upstream-key", upstream.Client())
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/v1/models", "", 200},
		{"POST", "/v1/chat/completions", `{"model":"triage","messages":[]}`, 403},
		{"POST", "/v1/chat/completions", `{"model":"pentest","model":"triage","messages":[]}`, 400},
		{"POST", "/v1/chat/completions", `{"model":"pentest","messages":[],"api_base":"https://evil"}`, 400},
		{"POST", "/v1/chat/completions", `{"model":"pentest","messages":[]}`, 200},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer user-token")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Cookie", "secret")
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%s got %d %s", tc.body, w.Code, w.Body.String())
		}
		if tc.method == "GET" && strings.Contains(w.Body.String(), "triage") {
			t.Error("forbidden model listed")
		}
	}
	if called != 1 {
		t.Errorf("upstream calls %d", called)
	}
}
func TestNoGroupNoModelsAndNoTokenDenied(t *testing.T) {
	s := New(verifier{}, Config{Rules: map[string][]string{"example/red-team": {"pentest"}}}, "key", http.DefaultClient)
	for _, token := range []string{"", "Bearer valid"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/v1/models", nil)
		r.Header.Set("Authorization", token)
		s.Handler().ServeHTTP(w, r)
		if token == "" && w.Code != 401 {
			t.Fatal(w.Code)
		}
		if token != "" && (w.Code != 200 || !strings.Contains(w.Body.String(), `"data":[]`)) {
			t.Fatal(w.Body.String())
		}
	}
}

func TestStreamingAndRedirects(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer target.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "text/event-stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: {\"choices\":[]}\n\ndata: [DONE]\n\n")
			return
		}
		http.Redirect(w, r, target.URL, 307)
	}))
	defer up.Close()
	s := New(verifier{[]string{"g"}}, Config{Upstream: up.URL, Rules: map[string][]string{"g": {"pentest"}}, MaxRequestBytes: 4096, MaxDurationSeconds: 30}, "key", up.Client())
	for _, stream := range []string{"true", "false"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"pentest","messages":[],"stream":`+stream+`}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer token")
		s.Handler().ServeHTTP(w, r)
		if stream == "true" && (w.Code != 200 || !strings.Contains(w.Body.String(), "[DONE]")) {
			t.Fatal(w.Body.String())
		}
		if stream == "false" && w.Code != 502 {
			t.Fatal(w.Code)
		}
	}
	if called {
		t.Fatal("redirect followed")
	}
}
