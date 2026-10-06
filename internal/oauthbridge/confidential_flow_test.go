package oauthbridge

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
)

func TestConfidentialCodeRefreshAndRevoke(t *testing.T) {
	for _, method := range []string{"client_secret_post", "client_secret_basic"} {
		t.Run(method, func(t *testing.T) {
			base := testServer(t)
			t.Setenv("PORTICO_TEST_CLIENT_SECRET", testClientSecret)
			s, e := New(base.public, []Client{registeredTestClient(t, method), {ID: "public", RedirectURIs: []string{"http://127.0.0.1:9000/callback"}}}, base.pool, base.vault, base.sessions, nil)
			if e != nil {
				t.Fatal(e)
			}
			s.idp = fakeIDP{}
			redirect := "https://chat.example/oauth/clients/mcp:portico/callback"
			handle, e := s.sessions.Create(context.Background(), identity.Tokens{AccessToken: "access", RefreshToken: "refresh"})
			if e != nil {
				t.Fatal(e)
			}
			code, verifier := session.NewCredential(), session.NewCredential()
			sealed, e := s.seal(codeGrant{"web", redirect, challenge(verifier), handle, time.Now().Add(time.Hour)}, "code:"+session.Hash(code))
			if e != nil {
				t.Fatal(e)
			}
			_, e = s.pool.Exec(context.Background(), "INSERT INTO portico_oauth_codes(id,data,expires_at) VALUES($1,$2,$3)", session.Hash(code), sealed, time.Now().Add(time.Minute))
			if e != nil {
				t.Fatal(e)
			}
			send := func(path string, f url.Values, secret string) *httptest.ResponseRecorder {
				copy := url.Values{}
				for k, v := range f {
					copy[k] = append([]string(nil), v...)
				}
				copy.Set("client_id", "web")
				if method == "client_secret_post" {
					copy.Set("client_secret", secret)
					return authRequest(s, path, copy, "", "")
				}
				copy.Del("client_id")
				return authRequest(s, path, copy, "web", secret)
			}
			form := url.Values{"grant_type": {"authorization_code"}, "redirect_uri": {redirect}, "resource": {s.resource}, "code": {code}, "code_verifier": {verifier}}
			if w := send("/oauth/token", form, "wrong"); w.Code != 401 {
				t.Fatal("invalid secret accepted")
			}
			form.Set("code_verifier", session.NewCredential())
			if w := send("/oauth/token", form, testClientSecret); w.Code != 400 {
				t.Fatal("PKCE bypass")
			}
			form.Set("code_verifier", verifier)
			form.Set("redirect_uri", "https://wrong.example/callback")
			if w := send("/oauth/token", form, testClientSecret); w.Code != 400 {
				t.Fatal("redirect bypass")
			}
			form.Set("redirect_uri", redirect)
			tokens := result(t, send("/oauth/token", form, testClientSecret))
			if w := send("/oauth/token", form, testClientSecret); w.Code != 400 {
				t.Fatal("code replay")
			}
			access, refresh := tokens["access_token"].(string), tokens["refresh_token"].(string)
			foreign := url.Values{"client_id": {"public"}, "grant_type": {"refresh_token"}, "refresh_token": {refresh}}
			if w := post(s, "/oauth/token", foreign); w.Code != 400 {
				t.Fatal("token crossed client boundary")
			}
			refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
			if w := send("/oauth/token", refreshForm, "wrong"); w.Code != 401 {
				t.Fatal("unauthenticated refresh")
			}
			tokens = result(t, send("/oauth/token", refreshForm, testClientSecret))
			if tokens["refresh_token"] == refresh {
				t.Fatal("refresh not rotated")
			}
			if _, _, e := s.AuthorizeMCP(context.Background(), access); e == nil {
				t.Fatal("previous access token accepted")
			}
			current := tokens["access_token"].(string)
			if w := send("/oauth/revoke", url.Values{"token": {current}}, "wrong"); w.Code != 401 {
				t.Fatal("unauthenticated revocation")
			}
			if _, _, e := s.AuthorizeMCP(context.Background(), current); e != nil {
				t.Fatal("failed auth revoked valid session")
			}
			if w := post(s, "/oauth/revoke", url.Values{"client_id": {"public"}, "token": {current}}); w.Code != 200 {
				t.Fatal(w.Code)
			}
			if _, _, e := s.AuthorizeMCP(context.Background(), current); e != nil {
				t.Fatal("other client revoked token")
			}
			result(t, send("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}}, testClientSecret))
			// Old refresh token reuse still revokes the complete family for confidential clients.
			if w := send("/oauth/token", refreshForm, testClientSecret); w.Code != 400 {
				t.Fatal("refresh replay accepted")
			}
			if _, _, e := s.sessions.Access(context.Background(), handle); e == nil {
				t.Fatal("refresh replay did not revoke underlying session")
			}
		})
	}
}
func TestBasicEncodingAndDuplicateAuthorization(t *testing.T) {
	s := authTestServer(t, "client_secret_basic")
	// RFC 6749 HTTP Basic encodes credentials as form components before base64.
	special := "a+/: secret-with-at-least-32-characters"
	t.Setenv("PORTICO_TEST_CLIENT_SECRET", special)
	s, e := New(s.public, []Client{registeredTestClient(t, "client_secret_basic")}, nil, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	f := url.Values{"grant_type": {"unsupported"}, "resource": {s.resource}}
	if w := authRequest(s, "/oauth/token", f, "web", special); !strings.Contains(w.Body.String(), "unsupported_grant_type") {
		t.Fatal("Basic credential decoding failed")
	}
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("web", testClientSecret)
	r.Header.Add("Authorization", r.Header.Get("Authorization"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("ambiguous Authorization accepted")
	}
}
