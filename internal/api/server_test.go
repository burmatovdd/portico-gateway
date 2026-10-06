package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistrationRequiresAdapterCredential(t *testing.T) {
	s := &Server{AdapterKey: "a-long-test-adapter-secret"}
	for _, key := range []string{"", "incorrect"} {
		r := httptest.NewRequest("POST", "/v1/sessions", strings.NewReader(`{"access_token":"private"}`))
		r.Header.Set("X-Portico-Adapter-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d", w.Code)
		}
		if strings.Contains(w.Body.String(), "private") {
			t.Fatal("echoed token")
		}
	}
}
func TestRejectsBrowserOriginAtCredentialEndpoints(t *testing.T) {
	s := &Server{AdapterKey: "secret"}
	r := httptest.NewRequest("POST", "/v1/device/start", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
