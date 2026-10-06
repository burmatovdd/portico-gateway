package oauthbridge

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

var secretEnvName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// configureClientAuth resolves a secret reference once at startup. Only the hash
// is retained by the OAuth server; the public configuration contains no secret.
func (s *Server) configureClientAuth(c *Client) error {
	if c.AuthMethod == "" {
		c.AuthMethod = "none"
	}
	switch c.AuthMethod {
	case "none":
		if c.SecretEnv != "" {
			return errors.New("public OAuth client must not configure a client secret")
		}
	case "client_secret_post", "client_secret_basic":
		if !secretEnvName.MatchString(c.SecretEnv) {
			return errors.New("confidential OAuth client requires a secret environment reference")
		}
		secret := os.Getenv(c.SecretEnv)
		if len(secret) < 32 || len(secret) > 1024 {
			return errors.New("OAuth client secret must contain between 32 and 1024 bytes")
		}
		s.clientSecretHashes[c.ID] = sha256.Sum256([]byte(secret))
	default:
		return errors.New("unsupported OAuth client authentication method")
	}
	return nil
}

// authenticateClient is shared by token exchange, refresh and revocation. Client
// authentication never replaces PKCE, exact redirect matching or user consent.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request) (string, bool) {
	invalid := func() (string, bool) {
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Portico"`)
		}
		failure(w, http.StatusUnauthorized, "invalid_client")
		return "", false
	}
	if len(r.Header.Values("Authorization")) > 1 {
		failure(w, 400, "invalid_request")
		return "", false
	}
	id := r.PostForm.Get("client_id")
	secret := r.PostForm.Get("client_secret")
	method := "none"
	if r.Header.Get("Authorization") != "" {
		if r.PostForm.Has("client_secret") {
			failure(w, 400, "invalid_request")
			return "", false
		}
		username, password, ok := r.BasicAuth()
		if !ok {
			return invalid()
		}
		basicID, e1 := url.QueryUnescape(username)
		basicSecret, e2 := url.QueryUnescape(password)
		if e1 != nil || e2 != nil || (r.PostForm.Has("client_id") && id != basicID) {
			return invalid()
		}
		id, secret, method = basicID, basicSecret, "client_secret_basic"
	} else if r.PostForm.Has("client_secret") {
		method = "client_secret_post"
	}
	c, ok := s.clients[id]
	if !ok || c.AuthMethod != method {
		return invalid()
	}
	if method != "none" {
		want, ok := s.clientSecretHashes[id]
		got := sha256.Sum256([]byte(secret))
		if !ok || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			return invalid()
		}
	}
	return id, true
}
