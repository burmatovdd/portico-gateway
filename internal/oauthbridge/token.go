package oauthbridge

import (
	"context"
	"crypto/subtle"
	"errors"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net/http"
	"portico-gateway/internal/session"
	"time"
)

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if parseForm(r) != nil {
		failure(w, 400, "invalid_request")
		return
	}
	client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}
	resource := r.PostForm.Get("resource")
	if resource != s.resource && !(r.PostForm.Get("grant_type") == "refresh_token" && !r.PostForm.Has("resource")) {
		failure(w, 400, "invalid_target")
		return
	}
	if scope := r.PostForm.Get("scope"); scope != "" && scope != "mcp" {
		failure(w, 400, "invalid_scope")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.exchange(w, r, client)
	case "refresh_token":
		s.refresh(w, r, client)
	default:
		failure(w, 400, "unsupported_grant_type")
	}
}
func tokenReply(w http.ResponseWriter, access, refresh string, expires time.Time) {
	seconds := int(time.Until(expires).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	reply(w, 200, map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": seconds, "scope": "mcp"})
}
func (s *Server) exchange(w http.ResponseWriter, r *http.Request, client string) {
	code, verifier := r.PostForm.Get("code"), r.PostForm.Get("code_verifier")
	if len(code) != 43 || !validPKCE(verifier) {
		slog.Warn("OAuth code rejected", "reason", "invalid_code_or_verifier_format")
		failure(w, 400, "invalid_grant")
		return
	}
	tx, e := s.pool.Begin(r.Context())
	if e != nil {
		failure(w, 503, "temporarily_unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	var data []byte
	e = tx.QueryRow(r.Context(), "SELECT data FROM portico_oauth_codes WHERE id=$1 AND NOT used AND expires_at>now() FOR UPDATE", session.Hash(code)).Scan(&data)
	var c codeGrant
	reason := ""
	switch {
	case e != nil:
		if errors.Is(e, pgx.ErrNoRows) {
			reason = "code_missing_used_or_expired"
		} else {
			reason = "code_storage_error"
		}
	case s.open(data, "code:"+session.Hash(code), &c) != nil:
		reason = "code_decryption_failed"
	case c.Client != client:
		reason = "client_mismatch"
	case c.Redirect != r.PostForm.Get("redirect_uri"):
		reason = "redirect_mismatch"
	case subtle.ConstantTimeCompare([]byte(c.Challenge), []byte(challenge(verifier))) != 1:
		reason = "pkce_mismatch"
	}
	if reason != "" {
		slog.Warn("OAuth code rejected", "reason", reason)
		failure(w, 400, "invalid_grant")
		return
	}
	family, access, refresh := session.NewCredential(), session.NewCredential(), session.NewCredential()
	now := time.Now()
	end := c.Expires
	if !now.Before(end) {
		failure(w, 400, "invalid_grant")
		return
	}
	expiry := now.Add(5 * time.Minute)
	if expiry.After(end) {
		expiry = end
	}
	sealed, e := s.seal(c.Session, "family:"+family)
	if e == nil {
		_, e = tx.Exec(r.Context(), "INSERT INTO portico_oauth_families(id,client_id,data,access_hash,access_expires,expires_at) VALUES($1,$2,$3,$4,$5,$6)", family, client, sealed, session.Hash(access), expiry, end)
	}
	if e == nil {
		_, e = tx.Exec(r.Context(), "INSERT INTO portico_oauth_refresh(id,family) VALUES($1,$2)", session.Hash(refresh), family)
	}
	if e == nil {
		_, e = tx.Exec(r.Context(), "UPDATE portico_oauth_codes SET used=true WHERE id=$1", session.Hash(code))
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		failure(w, 503, "temporarily_unavailable")
		return
	}
	tokenReply(w, access, refresh, expiry)
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request, client string) {
	credential := r.PostForm.Get("refresh_token")
	if len(credential) != 43 {
		failure(w, 400, "invalid_grant")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Second)
	defer cancel()
	// Validate the underlying session outside the family transaction. This check
	// does not refresh the IdP token or extend idle expiry. The locked query below
	// independently checks family revocation and refresh reuse before rotation.
	var checkedFamily string
	var checkedData []byte
	e := s.pool.QueryRow(ctx, `SELECT f.id,f.data FROM portico_oauth_refresh t JOIN portico_oauth_families f ON f.id=t.family WHERE t.id=$1 AND f.client_id=$2 AND NOT f.revoked AND f.expires_at>now()`, session.Hash(credential), client).Scan(&checkedFamily, &checkedData)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			failure(w, 400, "invalid_grant")
		} else {
			failure(w, 503, "temporarily_unavailable")
		}
		return
	}
	var checkedHandle string
	if s.open(checkedData, "family:"+checkedFamily, &checkedHandle) != nil {
		failure(w, 503, "temporarily_unavailable")
		return
	}
	if e = s.sessions.CheckActive(ctx, checkedHandle); e != nil {
		if !errors.Is(e, session.ErrUnauthorized) {
			failure(w, 503, "temporarily_unavailable")
			return
		}
		if _, e = s.pool.Exec(ctx, "UPDATE portico_oauth_families SET revoked=true WHERE id=$1", checkedFamily); e != nil {
			failure(w, 503, "temporarily_unavailable")
			return
		}
		failure(w, 400, "invalid_grant")
		return
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		failure(w, 503, "temporarily_unavailable")
		return
	}
	defer tx.Rollback(ctx)
	var family, owner string
	var data []byte
	var end time.Time
	var used, revoked bool
	e = tx.QueryRow(ctx, `SELECT f.id,f.client_id,f.data,f.expires_at,t.used,f.revoked FROM portico_oauth_refresh t JOIN portico_oauth_families f ON f.id=t.family WHERE t.id=$1 FOR UPDATE OF f,t`, session.Hash(credential)).Scan(&family, &owner, &data, &end, &used, &revoked)
	if e != nil || owner != client || revoked || !time.Now().Before(end) {
		failure(w, 400, "invalid_grant")
		return
	}
	if used {
		_, e = tx.Exec(ctx, "UPDATE portico_oauth_families SET revoked=true WHERE id=$1", family)
		if e == nil {
			e = tx.Commit(ctx)
		}
		if e != nil {
			failure(w, 503, "temporarily_unavailable")
			return
		}
		var handle string
		if s.open(data, "family:"+family, &handle) == nil {
			_ = s.sessions.Logout(ctx, handle)
		}
		failure(w, 400, "invalid_grant")
		return
	}
	access, refresh := session.NewCredential(), session.NewCredential()
	expiry := time.Now().Add(5 * time.Minute)
	if expiry.After(end) {
		expiry = end
	}
	_, e = tx.Exec(ctx, "UPDATE portico_oauth_refresh SET used=true WHERE id=$1", session.Hash(credential))
	if e == nil {
		_, e = tx.Exec(ctx, "INSERT INTO portico_oauth_refresh(id,family) VALUES($1,$2)", session.Hash(refresh), family)
	}
	if e == nil {
		_, e = tx.Exec(ctx, "UPDATE portico_oauth_families SET access_hash=$2,access_expires=$3 WHERE id=$1", family, session.Hash(access), expiry)
	}
	if e == nil {
		e = tx.Commit(ctx)
	}
	if e != nil {
		failure(w, 503, "temporarily_unavailable")
		return
	}
	tokenReply(w, access, refresh, expiry)
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if parseForm(r) != nil {
		failure(w, 400, "invalid_request")
		return
	}
	client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}
	credential := r.PostForm.Get("token")
	if len(credential) != 43 {
		w.WriteHeader(200)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Second)
	defer cancel()
	var id string
	var data []byte
	e := s.pool.QueryRow(ctx, `UPDATE portico_oauth_families SET revoked=true WHERE client_id=$1 AND (access_hash=$2 OR id IN(SELECT family FROM portico_oauth_refresh WHERE id=$2)) RETURNING id,data`, client, session.Hash(credential)).Scan(&id, &data)
	if e != nil { // Unknown credentials are successful; DB failures must not be masked.
		if errors.Is(e, pgx.ErrNoRows) {
			w.WriteHeader(200)
			return
		}
		failure(w, 503, "temporarily_unavailable")
		return
	}
	var handle string
	if s.open(data, "family:"+id, &handle) != nil {
		failure(w, 503, "temporarily_unavailable")
		return
	}
	if e = s.sessions.Logout(ctx, handle); e != nil && e != session.ErrUnauthorized {
		failure(w, 503, "temporarily_unavailable")
		return
	}
	w.WriteHeader(200)
}
