package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthorizationBindsLoginAndAccessIdentity(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "jwks_uri": srv.URL + "/keys", "token_endpoint": srv.URL + "/token", "authorization_endpoint": srv.URL + "/authorize"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	})
	sign := func(audience, subject, nonce string) string {
		j := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": srv.URL, "aud": audience, "sub": subject, "nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
		j.Header["kid"] = "key"
		v, _ := j.SignedString(key)
		return v
	}
	loginSub, accessSub, loginNonce := "user", "user", "nonce"
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("code_verifier") != "verifier" || r.Form.Get("client_id") != "login-client" || r.Form.Get("redirect_uri") != "https://portico.example/oauth/callback" {
			t.Error("lost exchange binding")
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": sign("service", accessSub, ""), "id_token": sign("login-client", loginSub, loginNonce), "refresh_token": "refresh"})
	})
	p, err := NewOIDC(context.Background(), Options{Issuer: srv.URL, ClientID: "login-client", Audience: "service", Scopes: []string{"openid", "offline_access"}}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.AuthorizationURL("state", "nonce", "challenge", "https://portico.example/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if u.Query().Get("state") != "state" || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("nonce") != "nonce" {
		t.Fatal("missing authorization protections")
	}
	for _, tc := range []struct {
		name, nonce, subject string
		bad                  bool
	}{{"valid", "nonce", "user", false}, {"wrong nonce", "other", "user", true}, {"identity substitution", "nonce", "attacker", true}} {
		t.Run(tc.name, func(t *testing.T) {
			loginNonce = tc.nonce
			accessSub = tc.subject
			tokens, err := p.ExchangeCode(context.Background(), "code", "verifier", "https://portico.example/oauth/callback", "nonce")
			if (err != nil) != tc.bad {
				t.Fatalf("unexpected result %v", err)
			}
			if !tc.bad && tokens.RefreshToken != "refresh" {
				t.Fatal("missing refresh")
			}
		})
	}
}
