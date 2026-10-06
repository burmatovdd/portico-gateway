package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCRejectsInvalidIdentity(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var issuer string
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	issuer = srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "token_endpoint": issuer + "/token", "device_authorization_endpoint": issuer + "/device", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "one", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	})
	p, e := NewOIDC(context.Background(), Options{Issuer: issuer, ClientID: "client", Audience: "client", RolesClaim: "roles", RolesFormat: "casdoor"}, srv.Client())
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name   string
		change func(jwt.MapClaims)
		bad    bool
	}{{"valid", func(c jwt.MapClaims) {}, false}, {"audience", func(c jwt.MapClaims) { c["aud"] = "other" }, true}, {"issuer", func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }, true}, {"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, true}, {"subject", func(c jwt.MapClaims) { delete(c, "sub") }, true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": issuer, "sub": "user", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "roles": []any{map[string]any{"owner": "org", "name": "reader"}}}
			tc.change(claims)
			j := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			j.Header["kid"] = "one"
			token, _ := j.SignedString(key)
			id, e := p.Verify(context.Background(), token)
			if (e != nil) != tc.bad {
				t.Fatalf("bad=%v error=%v", tc.bad, e)
			}
			if !tc.bad && (id.Subject != "user" || len(id.Roles) != 1 || id.Roles[0] != "org/reader") {
				t.Fatal("lost identity")
			}
		})
	}
}

func TestGroupClaimsAndOrganization(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "jwks_uri": srv.URL + "/keys", "token_endpoint": srv.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "one", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	})
	p, e := NewOIDC(context.Background(), Options{Issuer: srv.URL, ClientID: "webui", Audience: "webui", RolesClaim: "groups", RolesFormat: "strings", RequiredOrganization: "example"}, srv.Client())
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name   string
		owner  any
		groups any
		nbf    any
		bad    bool
		count  int
	}{{"valid", "example", []string{"example/red-team"}, nil, false, 1}, {"other org", "other", []string{"example/red-team"}, nil, true, 0}, {"missing org", nil, []string{"example/red-team"}, nil, true, 0}, {"missing groups", "example", nil, nil, false, 0}, {"wrong groups", "example", "example/red-team", nil, false, 0}, {"future", "example", []string{"example/red-team"}, time.Now().Add(time.Hour).Unix(), true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			c := jwt.MapClaims{"iss": srv.URL, "sub": "user", "aud": "webui", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "owner": tc.owner, "groups": tc.groups}
			if tc.nbf != nil {
				c["nbf"] = tc.nbf
			}
			j := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
			j.Header["kid"] = "one"
			raw, _ := j.SignedString(key)
			id, e := p.Verify(context.Background(), raw)
			if (e != nil) != tc.bad {
				t.Fatalf("bad=%v err=%v", tc.bad, e)
			}
			if !tc.bad && len(id.Roles) != tc.count {
				t.Fatal(id.Roles)
			}
		})
	}
}
