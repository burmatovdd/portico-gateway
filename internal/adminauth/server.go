// Package adminauth provides a separate browser OIDC session for administration.
package adminauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/url"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"strings"
	"time"
)

const cookieName = "__Host-portico-admin"
const flowCookieName = "__Host-portico-admin-login"

var ErrUnauthorized = errors.New("требуется вход администратора")
var ErrForbidden = errors.New("доступ администратора запрещён")

type IdentityProvider interface {
	AuthorizationURL(state, nonce, challenge, redirect string) (string, error)
	ExchangeCode(context.Context, string, string, string, string) (identity.Tokens, error)
}
type Server struct {
	public   string
	basePath string
	groups   map[string]bool
	pool     *pgxpool.Pool
	vault    *vault.Vault
	sessions *session.Manager
	idp      IdentityProvider
}
type flow struct{ Cookie, Nonce, Verifier string }

func New(publicURL string, adminGroups []string, pool *pgxpool.Pool, v *vault.Vault, sessions *session.Manager, idp IdentityProvider) (*Server, error) {
	u, e := url.Parse(publicURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(u.Host, " ;\t\r\n") {
		return nil, errors.New("admin public URL must be an HTTPS origin")
	}
	if pool == nil || v == nil || sessions == nil || sessions.Provider == nil || sessions.Store == nil || sessions.Vault == nil || idp == nil || sessions.MaxAge <= 0 {
		return nil, errors.New("admin authentication dependencies are required")
	}
	groups := map[string]bool{}
	for _, g := range adminGroups {
		if g == "" || strings.TrimSpace(g) != g {
			return nil, errors.New("invalid admin group")
		}
		groups[g] = true
	}
	if len(groups) == 0 {
		return nil, errors.New("at least one admin group is required")
	}
	return &Server{public: u.Scheme + "://" + u.Host, groups: groups, pool: pool, vault: v, sessions: sessions, idp: idp}, nil
}

// NewPortal creates a normal-user browser session isolated from admin cookies,
// CSRF tokens and encrypted login-flow purpose. Groups are exact signed roles.
func NewPortal(publicURL string, allowedGroups []string, pool *pgxpool.Pool, v *vault.Vault, sessions *session.Manager, idp IdentityProvider) (*Server, error) {
	s, err := New(publicURL, allowedGroups, pool, v, sessions, idp)
	if err != nil {
		return nil, err
	}
	s.basePath = "/portal"
	return s, nil
}
func (s *Server) base() string {
	if s.basePath == "/portal" {
		return "/portal"
	}
	return "/admin"
}
func (s *Server) sessionCookie() string {
	if s.base() == "/portal" {
		return "__Host-portico-portal"
	}
	return cookieName
}
func (s *Server) loginCookie() string {
	if s.base() == "/portal" {
		return "__Host-portico-portal-login"
	}
	return flowCookieName
}
func (s *Server) flowAAD(state string) string {
	return strings.TrimPrefix(s.base(), "/") + "-flow:" + session.Hash(state)
}
func (s *Server) csrf(c string) string {
	if s.base() == "/portal" {
		return challenge("portico-portal-csrf-v1\x00" + c)
	}
	return csrf(c)
}
func (s *Server) bound(r *http.Request, f flow) bool {
	c, ok := credential(r, s.loginCookie())
	return ok && subtle.ConstantTimeCompare([]byte(session.Hash(c)), []byte(f.Cookie)) == 1
}

func headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
}
func failure(w http.ResponseWriter, status int) {
	headers(w)
	msg := "Не удалось выполнить вход. Попробуйте ещё раз."
	if status == 403 {
		msg = "Доступ администратора запрещён."
	}
	http.Error(w, msg, status)
}
func method(w http.ResponseWriter, r *http.Request, want string) bool {
	headers(w)
	if r.Method != want {
		w.Header().Set("Allow", want)
		failure(w, http.StatusMethodNotAllowed)
		return false
	}
	return true
}
func cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func credential(r *http.Request, name string) (string, bool) {
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			count++
			value = c.Value
		}
	}
	if count != 1 || len(value) != 43 {
		return "", false
	}
	b, e := base64.RawURLEncoding.DecodeString(value)
	return value, e == nil && len(b) == 32
}
func bound(r *http.Request, f flow) bool {
	c, ok := credential(r, flowCookieName)
	return ok && subtle.ConstantTimeCompare([]byte(session.Hash(c)), []byte(f.Cookie)) == 1
}
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func csrf(credential string) string { return challenge("portico-admin-csrf-v1\x00" + credential) }
func (s *Server) allowed(id identity.Identity) bool {
	for _, role := range id.Roles {
		if s.groups[role] {
			return true
		}
	}
	return false
}

// Authenticate re-verifies or refreshes the signed identity every request and
// returns a CSRF token, never an upstream access or refresh token.
func (s *Server) Authenticate(r *http.Request) (identity.Identity, string, error) {
	id, _, err := s.Access(r)
	if err != nil {
		return identity.Identity{}, "", err
	}
	c, _ := credential(r, s.sessionCookie())
	return id, s.csrf(c), nil
}

// Access returns the current user token exclusively for server-side upstream
// requests. Never place this token in HTML, JSON, logs or browser cookies.
func (s *Server) Access(r *http.Request) (identity.Identity, string, error) {
	c, ok := credential(r, s.sessionCookie())
	if !ok {
		return identity.Identity{}, "", ErrUnauthorized
	}
	id, token, err := s.sessions.Access(r.Context(), c)
	if err != nil {
		return identity.Identity{}, "", ErrUnauthorized
	}
	if !s.allowed(id) {
		return identity.Identity{}, "", ErrForbidden
	}
	return id, token, nil
}

// CheckCSRF checks request integrity, not authentication: callers must also
// Authenticate every mutation. Forms use csrf; JSON may use X-CSRF-Token.
func (s *Server) CheckCSRF(r *http.Request) bool {
	if r.Method != http.MethodPost || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != s.public {
		return false
	}
	c, ok := credential(r, s.sessionCookie())
	if !ok {
		return false
	}
	values := r.Header.Values("X-CSRF-Token")
	var token string
	if len(values) > 1 {
		return false
	}
	if len(values) == 1 {
		token = values[0]
	} else {
		if r.Body == nil {
			return false
		}
		r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
		if e := r.ParseForm(); e != nil {
			return false
		}
		tokens := r.PostForm["csrf"]
		if len(tokens) != 1 {
			return false
		}
		token = tokens[0]
	}
	return len(token) == 43 && subtle.ConstantTimeCompare([]byte(token), []byte(s.csrf(c))) == 1
}
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	state, binding := session.NewCredential(), session.NewCredential()
	f := flow{Cookie: session.Hash(binding), Nonce: session.NewCredential(), Verifier: session.NewCredential()}
	target, e := s.idp.AuthorizationURL(state, f.Nonce, challenge(f.Verifier), s.public+s.base()+"/callback")
	u, parseErr := url.Parse(target)
	if e != nil || parseErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(u.Host, " ;\t\r\n") {
		s.failure(w, 503)
		return
	}
	plain, e := json.Marshal(f)
	if e != nil {
		s.failure(w, 503)
		return
	}
	data, e := s.vault.Seal(plain, s.flowAAD(state))
	if e != nil {
		s.failure(w, 503)
		return
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		s.failure(w, 503)
		return
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(742901117)")
	if e == nil {
		_, e = tx.Exec(ctx, "DELETE FROM portico_admin_flows WHERE expires_at<=now()")
	}
	var n int
	if e == nil {
		e = tx.QueryRow(ctx, "SELECT count(*) FROM portico_admin_flows").Scan(&n)
	}
	if e != nil {
		s.failure(w, 503)
		return
	}
	if n >= 1000 {
		s.failure(w, 429)
		return
	}
	_, e = tx.Exec(ctx, "INSERT INTO portico_admin_flows(id,data,expires_at) VALUES($1,$2,$3)", session.Hash(state), data, time.Now().Add(5*time.Minute))
	if e == nil {
		e = tx.Commit(ctx)
	}
	if e != nil {
		s.failure(w, 503)
		return
	}
	cookie(w, s.loginCookie(), binding, 300)
	http.Redirect(w, r, target, http.StatusSeeOther)
}
func (s *Server) Callback(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if len(r.URL.RawQuery) > 8192 {
		s.failure(w, 400)
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		s.failure(w, 400)
		return
	}
	for _, values := range q {
		if len(values) != 1 {
			s.failure(w, 400)
			return
		}
	}
	state := q.Get("state")
	if len(state) != 43 {
		s.failure(w, 400)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 25*time.Second)
	defer cancel()
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		s.failure(w, 503)
		return
	}
	defer tx.Rollback(ctx)
	var data []byte
	e = tx.QueryRow(ctx, "SELECT data FROM portico_admin_flows WHERE id=$1 AND expires_at>now() FOR UPDATE", session.Hash(state)).Scan(&data)
	if e != nil {
		s.failure(w, 400)
		return
	}
	plain, e := s.vault.Open(data, s.flowAAD(state))
	if e != nil {
		s.failure(w, 400)
		return
	}
	var f flow
	if json.Unmarshal(plain, &f) != nil || !s.bound(r, f) {
		s.failure(w, 400)
		return
	}
	// Consume under lock before exchanging the code; failed exchanges cannot replay.
	_, e = tx.Exec(ctx, "DELETE FROM portico_admin_flows WHERE id=$1", session.Hash(state))
	if e == nil {
		e = tx.Commit(ctx)
	}
	if e != nil {
		s.failure(w, 503)
		return
	}
	cookie(w, s.loginCookie(), "", -1)
	if q.Get("error") != "" || q.Get("code") == "" || len(q.Get("code")) > 4096 {
		s.failure(w, 400)
		return
	}
	tokens, e := s.idp.ExchangeCode(ctx, q.Get("code"), f.Verifier, s.public+s.base()+"/callback", f.Nonce)
	if e != nil {
		s.failure(w, 400)
		return
	}
	handle, e := s.sessions.Create(ctx, tokens)
	if e != nil {
		s.failure(w, 503)
		return
	}
	id, _, e := s.sessions.Access(ctx, handle)
	if e != nil || !s.allowed(id) {
		_ = s.sessions.Logout(ctx, handle)
		s.failure(w, 403)
		return
	}
	if old, ok := credential(r, s.sessionCookie()); ok {
		if e = s.sessions.Logout(ctx, old); e != nil && !errors.Is(e, session.ErrUnauthorized) {
			_ = s.sessions.Logout(ctx, handle)
			s.failure(w, 503)
			return
		}
	}
	cookie(w, s.sessionCookie(), handle, int(s.sessions.MaxAge/time.Second))
	if s.base() == "/admin" {
		cookie(w, localCookieName, "", -1)
	}
	http.Redirect(w, r, s.base()+"/", http.StatusSeeOther)
}
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !s.CheckCSRF(r) {
		s.failure(w, 403)
		return
	}
	if _, _, e := s.Authenticate(r); e != nil {
		s.failure(w, 403)
		return
	}
	c, _ := credential(r, s.sessionCookie())
	if e := s.sessions.Logout(r.Context(), c); e != nil {
		s.failure(w, 503)
		return
	}
	cookie(w, s.sessionCookie(), "", -1)
	cookie(w, s.loginCookie(), "", -1)
	http.Redirect(w, r, s.base()+"/login", http.StatusSeeOther)
}

func (s *Server) failure(w http.ResponseWriter, status int) {
	if s.base() == "/portal" && status == http.StatusForbidden {
		headers(w)
		http.Error(w, "Доступ к проверкам запрещён.", status)
		return
	}
	failure(w, status)
}
