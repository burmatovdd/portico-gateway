package oauthbridge

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFormRedirectPolicyIncludesOnlyRegisteredClient(t *testing.T) {
	s := &Server{clients: map[string]Client{"chat": {ID: "chat", RedirectURIs: []string{"https://chat.example/oauth/callback"}}}}
	w := httptest.NewRecorder()
	if !s.allowLoginRedirect(w, "https://idp.example/authorize?state=private", flow{Client: "chat", Redirect: "https://chat.example/oauth/callback"}) {
		t.Fatal("registered redirect rejected")
	}
	p := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(p, "form-action 'self' https://idp.example https://chat.example;") || strings.Contains(p, "private") {
		t.Fatal("incorrect policy", p)
	}
	for _, raw := range []string{"https://evil.example/callback", "javascript:alert(1)", "https://chat.example/other"} {
		w = httptest.NewRecorder()
		if s.allowLoginRedirect(w, "https://idp.example/authorize", flow{Client: "chat", Redirect: raw}) {
			t.Fatal("unregistered redirect accepted")
		}
	}
}
