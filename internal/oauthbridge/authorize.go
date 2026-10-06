package oauthbridge

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"net/url"
	"portico-gateway/internal/session"
	"portico-gateway/internal/webui"
	"strings"
	"time"
)

const cookieName = "__Host-portico-oauth"

type flow struct{ Client, Redirect, State, Challenge, Cookie, CSRF, Nonce, Verifier string }
type codeGrant struct {
	Client, Redirect, Challenge, Session string
	Expires                              time.Time
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for _, v := range q {
		if len(v) != 1 {
			browserFailure(w, r, 400, "invalid_request")
			return
		}
	}
	if !s.registered(q.Get("client_id"), q.Get("redirect_uri")) {
		browserFailure(w, r, 400, "invalid_request")
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || !validPKCE(q.Get("code_challenge")) || q.Get("scope") != "mcp" || q.Get("resource") != s.resource || len(q.Get("state")) > 1024 {
		browserFailure(w, r, 400, "invalid_request")
		return
	}
	id, cookie := session.NewCredential(), session.NewCredential()
	f := flow{Client: q.Get("client_id"), Redirect: q.Get("redirect_uri"), State: q.Get("state"), Challenge: q.Get("code_challenge"), Cookie: session.Hash(cookie), CSRF: session.NewCredential(), Nonce: session.NewCredential(), Verifier: session.NewCredential()}
	data, e := s.seal(f, "flow:"+session.Hash(id))
	if e != nil {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	// Limit unauthenticated browser transactions before storing additional state.
	tx, e := s.pool.Begin(r.Context())
	if e != nil {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	_, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(742901007)")
	var n int
	if e == nil {
		e = tx.QueryRow(r.Context(), "SELECT count(*) FROM portico_oauth_flows WHERE expires_at>now()").Scan(&n)
	}
	if e != nil || n >= 1000 {
		browserFailure(w, r, 429, "temporarily_unavailable")
		return
	}
	_, e = tx.Exec(r.Context(), "INSERT INTO portico_oauth_flows(id,data,expires_at,phase) VALUES($1,$2,$3,'consent')", session.Hash(id), data, time.Now().Add(10*time.Minute))
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	target, e := s.idp.AuthorizationURL(id, f.Nonce, challenge(f.Verifier), s.public+"/oauth/callback")
	if e != nil || !s.allowLoginRedirect(w, target, f) {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	webui.Consent(w, f.Client, id, f.CSRF)
}
func bound(r *http.Request, f flow) bool {
	c, e := r.Cookie(cookieName)
	return e == nil && len(c.Value) == 43 && subtle.ConstantTimeCompare([]byte(session.Hash(c.Value)), []byte(f.Cookie)) == 1
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.public || parseForm(r) != nil {
		browserFailure(w, r, 403, "access_denied")
		return
	}
	id := r.PostForm.Get("transaction")
	if len(id) != 43 {
		browserFailure(w, r, 400, "invalid_request")
		return
	}
	tx, e := s.pool.Begin(r.Context())
	if e != nil {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	var data []byte
	e = tx.QueryRow(r.Context(), "SELECT data FROM portico_oauth_flows WHERE id=$1 AND phase='consent' AND expires_at>now() FOR UPDATE", session.Hash(id)).Scan(&data)
	var f flow
	if e != nil || s.open(data, "flow:"+session.Hash(id), &f) != nil || !bound(r, f) || subtle.ConstantTimeCompare([]byte(f.CSRF), []byte(r.PostForm.Get("csrf"))) != 1 {
		browserFailure(w, r, 403, "access_denied")
		return
	}
	target, e := s.idp.AuthorizationURL(id, f.Nonce, challenge(f.Verifier), s.public+"/oauth/callback")
	if e != nil {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	_, e = tx.Exec(r.Context(), "UPDATE portico_oauth_flows SET phase='upstream' WHERE id=$1", session.Hash(id))
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	if !s.allowLoginRedirect(w, target, f) {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for _, v := range q {
		if len(v) != 1 {
			browserFailure(w, r, 400, "invalid_request")
			return
		}
	}
	id := q.Get("state")
	if len(id) != 43 {
		browserFailure(w, r, 400, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 25*time.Second)
	defer cancel()
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	defer tx.Rollback(ctx)
	var data []byte
	e = tx.QueryRow(ctx, "SELECT data FROM portico_oauth_flows WHERE id=$1 AND phase='upstream' AND expires_at>now() FOR UPDATE", session.Hash(id)).Scan(&data)
	var f flow
	if e != nil || s.open(data, "flow:"+session.Hash(id), &f) != nil || !bound(r, f) {
		browserFailure(w, r, 400, "invalid_request")
		return
	}
	// Consume before the upstream exchange so replay cannot retry a used code.
	_, e = tx.Exec(ctx, "DELETE FROM portico_oauth_flows WHERE id=$1", session.Hash(id))
	if e == nil {
		e = tx.Commit(ctx)
	}
	if e != nil {
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if q.Get("error") != "" || q.Get("code") == "" {
		slog.Warn("OAuth callback failed", "stage", "authorization_response")
		s.callbackFailure(w, r, f, 400, "access_denied")
		return
	}
	tokens, e := s.idp.ExchangeCode(ctx, q.Get("code"), f.Verifier, s.public+"/oauth/callback", f.Nonce)
	if e != nil {
		slog.Warn("OAuth callback failed", "stage", "token_exchange_or_validation")
		s.callbackFailure(w, r, f, 400, "access_denied")
		return
	}
	sessionEnd := time.Now().Add(s.sessions.MaxAge)
	handle, e := s.sessions.Create(ctx, tokens)
	if e != nil {
		slog.Warn("OAuth callback failed", "stage", "session_creation")
		s.callbackFailure(w, r, f, 400, "access_denied")
		return
	}
	code := session.NewCredential()
	sealed, e := s.seal(codeGrant{f.Client, f.Redirect, f.Challenge, handle, sessionEnd}, "code:"+session.Hash(code))
	if e == nil {
		_, e = s.pool.Exec(ctx, "INSERT INTO portico_oauth_codes(id,data,expires_at) VALUES($1,$2,$3)", session.Hash(code), sealed, time.Now().Add(time.Minute))
	}
	if e != nil {
		_ = s.sessions.Logout(ctx, handle)
		browserFailure(w, r, 503, "temporarily_unavailable")
		return
	}
	target, _ := url.Parse(f.Redirect)
	values := target.Query()
	values.Set("code", code)
	if f.State != "" {
		values.Set("state", f.State)
	}
	target.RawQuery = values.Encode()
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}

// Chrome can enforce form-action across the complete OAuth redirect chain.
// Allow only the trusted IdP and this flow's registered client origin.
func (s *Server) allowLoginRedirect(w http.ResponseWriter, target string, f flow) bool {
	if !s.registered(f.Client, f.Redirect) {
		return false
	}
	u, e := url.Parse(target)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(u.Host, " ;\t\r\n") {
		return false
	}
	client, e := url.Parse(f.Redirect)
	if e != nil || client.Host == "" || client.User != nil || strings.ContainsAny(client.Host, " ;\t\r\n") || (client.Scheme != "https" && (client.Scheme != "http" || client.Hostname() != "127.0.0.1")) {
		return false
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self' "+u.Scheme+"://"+u.Host+" "+client.Scheme+"://"+client.Host+"; frame-ancestors 'none'; base-uri 'none'")
	return true
}

// callbackFailure returns control only to a registered client, preserving OAuth state.
func (s *Server) callbackFailure(w http.ResponseWriter, r *http.Request, f flow, status int, code string) {
	if !strings.Contains(r.Header.Get("Accept"), "text/html") || !s.registered(f.Client, f.Redirect) {
		browserFailure(w, r, status, code)
		return
	}
	target, err := url.Parse(f.Redirect)
	if err != nil {
		browserFailure(w, r, status, code)
		return
	}
	q := target.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	if f.State != "" {
		q.Set("state", f.State)
	} else {
		q.Del("state")
	}
	target.RawQuery = q.Encode()
	webui.ErrorWithReturn(w, status, code, target.String())
}
