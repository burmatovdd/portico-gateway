package oauthbridge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const testClientSecret = "test-client-secret-with-at-least-32-bytes"

func registeredTestClient(t *testing.T, method string) Client {
	t.Helper()
	var c Client
	if err := yaml.Unmarshal([]byte("id: web\nredirect_uris: [https://chat.example/oauth/clients/mcp:portico/callback]\ntoken_endpoint_auth_method: "+method+"\nclient_secret_env: PORTICO_TEST_CLIENT_SECRET\n"), &c); err != nil {
		t.Fatal(err)
	}
	return c
}
func authTestServer(t *testing.T, method string) *Server {
	t.Helper()
	t.Setenv("PORTICO_TEST_CLIENT_SECRET", testClientSecret)
	s, e := New("https://gateway.example", []Client{registeredTestClient(t, method), {ID: "public", RedirectURIs: []string{"http://127.0.0.1:9000/callback"}}}, nil, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func authRequest(s *Server, path string, f url.Values, basicUser, basicSecret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		r.SetBasicAuth(url.QueryEscape(basicUser), url.QueryEscape(basicSecret))
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestConfidentialClientAuthentication(t *testing.T) {
	for _, method := range []string{"client_secret_post", "client_secret_basic"} {
		t.Run(method, func(t *testing.T) {
			s := authTestServer(t, method)
			for _, path := range []string{"/oauth/token", "/oauth/revoke"} {
				for _, secret := range []string{testClientSecret, "wrong", ""} {
					f := url.Values{"client_id": {"web"}, "grant_type": {"unsupported"}, "resource": {s.resource}, "token": {"short"}}
					user, pass := "", ""
					if method == "client_secret_post" {
						if secret != "" {
							f.Set("client_secret", secret)
						}
					} else if secret != "" {
						user, pass = "web", secret
						f.Del("client_id")
					}
					w := authRequest(s, path, f, user, pass)
					if secret == testClientSecret {
						if path == "/oauth/token" && (w.Code != 400 || !strings.Contains(w.Body.String(), "unsupported_grant_type")) {
							t.Fatalf("valid credentials rejected: %d %s", w.Code, w.Body.String())
						}
						if path == "/oauth/revoke" && w.Code != 200 {
							t.Fatalf("valid revocation credentials rejected: %d %s", w.Code, w.Body.String())
						}
					} else if w.Code != 401 || !strings.Contains(w.Body.String(), "invalid_client") {
						t.Fatalf("invalid credentials not rejected: %s %d %s", path, w.Code, w.Body.String())
					}
					if strings.Contains(w.Body.String(), testClientSecret) {
						t.Fatal("secret in response")
					}
				}
			}
		})
	}
}
func TestRejectMixedAndDowngradedClientAuthentication(t *testing.T) {
	s := authTestServer(t, "client_secret_post")
	for _, tc := range []struct{ name, id, secret, basicUser, basicSecret string }{
		{"public-secret", "public", testClientSecret, "", ""},
		{"wrong-method", "web", "", "web", testClientSecret},
		{"mixed", "web", testClientSecret, "web", testClientSecret},
		{"unknown", "unknown", testClientSecret, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := url.Values{"client_id": {tc.id}, "resource": {s.resource}, "grant_type": {"unsupported"}}
			if tc.secret != "" {
				f.Set("client_secret", tc.secret)
			}
			for _, path := range []string{"/oauth/token", "/oauth/revoke"} {
				w := authRequest(s, path, f, tc.basicUser, tc.basicSecret)
				if w.Code != 400 && w.Code != 401 {
					t.Fatalf("accepted invalid client auth: %d", w.Code)
				}
			}
		})
	}
	f := url.Values{"client_id": {"public"}, "resource": {s.resource}, "grant_type": {"unsupported"}}
	if w := authRequest(s, "/oauth/token", f, "", ""); !strings.Contains(w.Body.String(), "unsupported_grant_type") {
		t.Fatal("public client compatibility lost")
	}
	f = url.Values{"client_id": {"web"}, "client_secret": {testClientSecret, testClientSecret}, "resource": {s.resource}, "grant_type": {"unsupported"}}
	if w := authRequest(s, "/oauth/token", f, "", ""); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_request") {
		t.Fatal("duplicate credential accepted")
	}
}
func TestClientSecretConfigurationFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, method, value string }{
		{"missing", "client_secret_post", ""}, {"short", "client_secret_basic", "weak"}, {"unknown", "unknown", testClientSecret}, {"public-with-secret", "none", testClientSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PORTICO_TEST_CLIENT_SECRET", tc.value)
			if _, e := New("https://gateway.example", []Client{registeredTestClient(t, tc.method)}, nil, nil, nil, nil); e == nil {
				t.Fatal("invalid confidential client configuration accepted")
			}
		})
	}
}
func TestClientAuthDiscovery(t *testing.T) {
	s := authTestServer(t, "client_secret_post")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	var m map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &m); e != nil {
		t.Fatal(e)
	}
	methods := m["token_endpoint_auth_methods_supported"].([]any)
	found := false
	for _, method := range methods {
		if method == "client_secret_post" {
			found = true
		}
	}
	if !found {
		t.Fatal("static OAuth client method missing from metadata")
	}
	if strings.Contains(w.Body.String(), testClientSecret) || strings.Contains(w.Body.String(), "PORTICO_TEST_CLIENT_SECRET") {
		t.Fatal("client secrets in discovery")
	}
}
