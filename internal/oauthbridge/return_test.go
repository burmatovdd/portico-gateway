package oauthbridge

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestErrorReturnRequiresRegisteredCallback(t *testing.T) {
	s := &Server{clients: map[string]Client{"chat": {ID: "chat", RedirectURIs: []string{"https://chat.example/callback"}}}}
	for _, tc := range []struct {
		redirect string
		allowed  bool
	}{
		{"https://chat.example/callback", true},
		{"https://evil.example/callback", false},
		{"javascript:alert(1)", false},
	} {
		r := httptest.NewRequest("GET", "https://gateway.example/oauth/callback", nil)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		s.callbackFailure(w, r, flow{Client: "chat", Redirect: tc.redirect, State: "state-value"}, 400, "access_denied")
		body := w.Body.String()
		if strings.Contains(body, "Вернуться в приложение") != tc.allowed {
			t.Fatal("incorrect return link policy")
		}
		if tc.allowed && (!strings.Contains(body, "error=access_denied") || !strings.Contains(body, "state=state-value")) {
			t.Fatal("missing OAuth error or state")
		}
		if strings.Contains(body, "evil.example") || strings.Contains(body, "javascript:") {
			t.Fatal("unregistered URL rendered")
		}
	}
}

func TestErrorReturnPreservesJSONResponse(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "https://gateway.example/oauth/callback", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	s.callbackFailure(w, r, flow{}, 400, "access_denied")
	if strings.Contains(w.Body.String(), "<html") || !strings.Contains(w.Body.String(), "access_denied") {
		t.Fatal("protocol response changed")
	}
}
