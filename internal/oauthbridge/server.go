// Package oauthbridge exposes an OAuth facade for public and confidential MCP clients.
// Its opaque credentials are never forwarded to downstream services.
package oauthbridge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"portico-gateway/internal/webui"
)

type Client struct {
	ID           string   `yaml:"id"`
	RedirectURIs []string `yaml:"redirect_uris"`
	AuthMethod   string   `yaml:"token_endpoint_auth_method,omitempty"`
	SecretEnv    string   `yaml:"client_secret_env,omitempty"`
}
type upstream interface {
	AuthorizationURL(string, string, string, string) (string, error)
	ExchangeCode(context.Context, string, string, string, string) (identity.Tokens, error)
}
type Server struct {
	public, resource   string
	clients            map[string]Client
	clientSecretHashes map[string][32]byte
	pool               *pgxpool.Pool
	vault              *vault.Vault
	sessions           *session.Manager
	idp                upstream
}

var errInvalid = errors.New("invalid OAuth credential")

func New(publicURL string, clients []Client, pool *pgxpool.Pool, v *vault.Vault, sessions *session.Manager, idp *identity.OIDC) (*Server, error) {
	u, e := url.Parse(publicURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("OAuth issuer must be an HTTPS origin")
	}
	s := &Server{public: u.Scheme + "://" + u.Host, clients: map[string]Client{}, clientSecretHashes: map[string][32]byte{}, pool: pool, vault: v, sessions: sessions, idp: idp}
	s.resource = s.public + "/mcp"
	for _, c := range clients {
		if c.ID == "" || len(c.ID) > 256 || len(c.RedirectURIs) == 0 {
			return nil, errors.New("invalid OAuth client")
		}
		if _, ok := s.clients[c.ID]; ok {
			return nil, errors.New("duplicate OAuth client")
		}
		if e := s.configureClientAuth(&c); e != nil {
			return nil, e
		}
		for _, raw := range c.RedirectURIs {
			r, e := url.Parse(raw)
			if e != nil || r.User != nil || r.Fragment != "" || r.Host == "" || (r.Scheme != "https" && (r.Scheme != "http" || r.Hostname() != "127.0.0.1")) {
				return nil, errors.New("invalid OAuth redirect URI")
			}
			if c.AuthMethod != "none" && r.Scheme != "https" {
				return nil, errors.New("confidential OAuth clients require HTTPS redirects")
			}
		}
		s.clients[c.ID] = c
	}
	return s, nil
}
func (s *Server) registered(client, redirect string) bool {
	c, ok := s.clients[client]
	if !ok {
		return false
	}
	for _, r := range c.RedirectURIs {
		if r == redirect {
			return true
		}
	}
	return false
}
func challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func validPKCE(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~", c) {
			return false
		}
	}
	return true
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, code string) {
	reply(w, status, map[string]string{"error": code})
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", webui.Home)
	mux.Handle("GET /assets/", webui.Assets())
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.resourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.resourceMetadata)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/login", s.login)
	mux.HandleFunc("GET /oauth/callback", s.callback)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revoke)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// HTML form navigation needs its Origin for the login CSRF check.
		// strict-origin preserves Origin without exposing OAuth query parameters.
		if r.URL.Path == "/oauth/authorize" {
			w.Header().Set("Referrer-Policy", "strict-origin")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	reply(w, 200, map[string]any{"issuer": s.public, "authorization_endpoint": s.public + "/oauth/authorize", "token_endpoint": s.public + "/oauth/token", "revocation_endpoint": s.public + "/oauth/revoke", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"}, "revocation_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"mcp"}})
}
func (s *Server) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	reply(w, 200, map[string]any{"resource": s.resource, "authorization_servers": []string{s.public}, "scopes_supported": []string{"mcp"}, "bearer_methods_supported": []string{"header"}})
}
func (s *Server) seal(v any, binding string) ([]byte, error) {
	plain, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return s.vault.Seal(plain, binding)
}
func (s *Server) open(data []byte, binding string, out any) error {
	plain, e := s.vault.Open(data, binding)
	if e != nil {
		return e
	}
	return json.Unmarshal(plain, out)
}
func parseForm(r *http.Request) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/x-www-form-urlencoded" {
		return errInvalid
	}
	if e := r.ParseForm(); e != nil {
		return e
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			return errInvalid
		}
	}
	return nil
}

// Browser navigation gets a readable page; OAuth API clients retain the JSON contract.
func browserFailure(w http.ResponseWriter, r *http.Request, status int, code string) {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		webui.Error(w, status, code)
		return
	}
	failure(w, status, code)
}
