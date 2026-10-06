package oauthbridge

import (
	"net/http/httptest"
	"testing"
)

func TestBrowserConsentReferrerPolicy(t *testing.T) {
	s := authTestServer(t, "client_secret_post")
	for _, tc := range []struct{ path, want string }{
		{"/oauth/authorize", "strict-origin"},
		{"/.well-known/oauth-authorization-server", "no-referrer"},
		{"/oauth/callback", "no-referrer"},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		if got := w.Header().Get("Referrer-Policy"); got != tc.want {
			t.Errorf("%s policy=%q, want %q: HTML form POST must retain Origin without leaking query", tc.path, got, tc.want)
		}
	}
	for _, origin := range []string{"", "null", "https://evil.example"} {
		r := httptest.NewRequest("POST", "/oauth/login", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("untrusted origin %q accepted: %d", origin, w.Code)
		}
	}
}
