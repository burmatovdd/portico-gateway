package adminauth

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"html/template"
	"net/http"
	"net/url"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
	"strconv"
	"strings"
	"time"
)

const localCookieName = "__Host-portico-admin-local"
const localLoginCookieName = "__Host-portico-admin-local-login"
const localHashIterations = 600000

// HashLocalPassword creates a salted verifier for a Secret; plaintext is never
// placed in Helm values, environment variables, the database or browser cookies.
func HashLocalPassword(password string) (string, error) {
	if len(password) < 16 || len(password) > 1024 {
		return "", errors.New("local admin password must contain 16-1024 bytes")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, localHashIterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", localHashIterations, base64.RawURLEncoding.EncodeToString(salt), base64.RawURLEncoding.EncodeToString(key)), nil
}

func validLocalHash(encoded string) ([]byte, []byte, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || parts[1] != strconv.Itoa(localHashIterations) {
		return nil, nil, false
	}
	salt, e1 := base64.RawURLEncoding.DecodeString(parts[2])
	key, e2 := base64.RawURLEncoding.DecodeString(parts[3])
	return salt, key, e1 == nil && e2 == nil && len(salt) == 32 && len(key) == 32
}

func VerifyLocalPassword(encoded, password string) bool {
	salt, want, ok := validLocalHash(encoded)
	if !ok || len(password) > 1024 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, localHashIterations, 32)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// Local is a single named administrative account with Portico-owned sessions.
// It has no dependency on an OIDC group or an upstream identity token.
type Local struct {
	public, username, passwordHash string
	store                          session.Store
	pool                           *pgxpool.Pool
	maxAge, idleAge                time.Duration
}

func NewLocal(publicURL, username, passwordHash string, store session.Store, maxAge, idleAge time.Duration) (*Local, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(u.Host, " ;\t\r\n") {
		return nil, errors.New("local admin requires an HTTPS origin")
	}
	if username == "" || len(username) > 128 || strings.TrimSpace(username) != username || strings.ContainsAny(username, "\r\n\x00") || store == nil || maxAge <= 0 || idleAge <= 0 || idleAge > maxAge {
		return nil, errors.New("invalid local admin configuration")
	}
	if _, _, ok := validLocalHash(passwordHash); !ok {
		return nil, errors.New("invalid local admin password hash")
	}
	return &Local{public: u.Scheme + "://" + u.Host, username: username, passwordHash: passwordHash, store: store, maxAge: maxAge, idleAge: idleAge}, nil
}

func (a *Local) SetPool(pool *pgxpool.Pool) { a.pool = pool }

func (a *Local) Migrate(ctx context.Context) error {
	if a.pool == nil {
		return errors.New("local admin database is required")
	}
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(742901118)"); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS portico_local_admin_attempts (
		id integer PRIMARY KEY CHECK (id = 1), failures integer NOT NULL,
		locked_until timestamptz NOT NULL)`)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a *Local) sessionKey(handle string) string { return session.Hash("local-admin:" + handle) }
func (a *Local) fingerprint() string             { return session.Hash(a.passwordHash) }

func (a *Local) createSession(ctx context.Context) (string, error) {
	handle := session.NewCredential()
	now := time.Now()
	err := a.store.Create(ctx, a.sessionKey(handle), session.Record{
		Data: []byte(a.fingerprint()), Expires: now.Add(a.maxAge), IdleUntil: now.Add(a.idleAge),
	})
	return handle, err
}

func (a *Local) Authenticate(r *http.Request) (identity.Identity, string, error) {
	handle, ok := credential(r, localCookieName)
	if !ok {
		return identity.Identity{}, "", ErrUnauthorized
	}
	var expires time.Time
	err := a.store.Locked(r.Context(), a.sessionKey(handle), func(rec *session.Record) error {
		now := time.Now()
		if rec.Revoked || !now.Before(rec.Expires) || !now.Before(rec.IdleUntil) || subtle.ConstantTimeCompare(rec.Data, []byte(a.fingerprint())) != 1 {
			rec.Revoked, rec.Data = true, nil
			return ErrUnauthorized
		}
		expires = rec.Expires
		rec.IdleUntil = now.Add(a.idleAge)
		return nil
	})
	if errors.Is(err, session.ErrUnauthorized) {
		err = ErrUnauthorized
	}
	if err != nil {
		return identity.Identity{}, "", err
	}
	return identity.Identity{Issuer: "portico-local", Subject: a.username, Roles: []string{"admin"}, Expires: expires}, challenge("portico-local-admin-csrf-v1\x00" + handle), nil
}

func (a *Local) CheckCSRF(r *http.Request) bool {
	if r.Method != http.MethodPost || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.public {
		return false
	}
	handle, ok := credential(r, localCookieName)
	if !ok {
		return false
	}
	var token string
	values := r.Header.Values("X-CSRF-Token")
	if len(values) > 1 {
		return false
	}
	if len(values) == 1 {
		token = values[0]
	} else if r.ParseForm() == nil && len(r.PostForm["csrf"]) == 1 {
		token = r.PostForm["csrf"][0]
	}
	want := challenge("portico-local-admin-csrf-v1\x00" + handle)
	return len(token) == len(want) && subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
}

func (a *Local) Logout(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !a.CheckCSRF(r) {
		failure(w, 403)
		return
	}
	if _, _, err := a.Authenticate(r); err != nil {
		failure(w, 403)
		return
	}
	handle, _ := credential(r, localCookieName)
	err := a.store.Locked(r.Context(), a.sessionKey(handle), func(rec *session.Record) error {
		rec.Revoked, rec.Data = true, nil
		return nil
	})
	if err != nil {
		failure(w, 503)
		return
	}
	cookie(w, localCookieName, "", -1)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

var localLoginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Вход администратора Portico</title><link rel="stylesheet" href="/admin/style.css"></head><body><main class="login-card"><h1>Вход администратора Portico</h1>{{if .Error}}<p role="alert">Неверные данные или вход временно ограничен.</p>{{end}}<form method="post" action="/admin/local/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Имя пользователя <input name="username" autocomplete="username" required></label><label>Пароль <input name="password" type="password" autocomplete="current-password" required></label><button class="primary" type="submit">Войти</button></form>{{if .OIDC}}<p><a href="/admin/oidc/login">Войти через OIDC</a></p>{{end}}</main></body></html>`))

func (a *Local) Login(w http.ResponseWriter, r *http.Request, oidc bool) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	csrfCookie := session.NewCredential()
	cookie(w, localLoginCookieName, csrfCookie, 300)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = localLoginPage.Execute(w, struct {
		CSRF        string
		Error, OIDC bool
	}{challenge("portico-local-login-v1\x00" + csrfCookie), r.URL.Query().Get("error") == "1", oidc})
}

// checkAttempt serializes attempts across replicas and locks the single account
// for 15 minutes after five failures. It returns false for invalid credentials.
func (a *Local) checkAttempt(ctx context.Context, username, password string) (bool, error) {
	if a.pool == nil {
		return false, errors.New("local admin database is required")
	}
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "INSERT INTO portico_local_admin_attempts(id,failures,locked_until) VALUES(1,0,to_timestamp(0)) ON CONFLICT DO NOTHING"); err != nil {
		return false, err
	}
	var failures int
	var lockedUntil time.Time
	if err = tx.QueryRow(ctx, "SELECT failures,locked_until FROM portico_local_admin_attempts WHERE id=1 FOR UPDATE").Scan(&failures, &lockedUntil); err != nil {
		return false, err
	}
	if time.Now().Before(lockedUntil) {
		return false, tx.Commit(ctx)
	}
	// Always perform the same KDF for unknown usernames to avoid timing leaks.
	passwordOK := VerifyLocalPassword(a.passwordHash, password)
	usernameOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) == 1
	valid := passwordOK && usernameOK
	if valid {
		_, err = tx.Exec(ctx, "UPDATE portico_local_admin_attempts SET failures=0,locked_until=to_timestamp(0) WHERE id=1")
	} else {
		failures++
		lock := time.Unix(0, 0)
		if failures >= 5 {
			lock = time.Now().Add(15 * time.Minute)
		}
		_, err = tx.Exec(ctx, "UPDATE portico_local_admin_attempts SET failures=$1,locked_until=$2 WHERE id=1", failures, lock)
	}
	if err != nil {
		return false, err
	}
	return valid, tx.Commit(ctx)
}

func (a *Local) Submit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.public {
		failure(w, 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		failure(w, 400)
		return
	}
	bind, ok := credential(r, localLoginCookieName)
	values := r.PostForm["csrf"]
	if !ok || len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(challenge("portico-local-login-v1\x00"+bind))) != 1 {
		failure(w, 403)
		return
	}
	if len(r.PostForm["username"]) != 1 || len(r.PostForm["password"]) != 1 {
		failure(w, 400)
		return
	}
	cookie(w, localLoginCookieName, "", -1)
	valid, err := a.checkAttempt(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
	if err != nil {
		failure(w, 503)
		return
	}
	if !valid {
		http.Redirect(w, r, "/admin/login?error=1", http.StatusSeeOther)
		return
	}
	handle, err := a.createSession(r.Context())
	if err != nil {
		failure(w, 503)
		return
	}
	cookie(w, cookieName, "", -1)
	cookie(w, localCookieName, handle, int(a.maxAge/time.Second))
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// Combined keeps local administration and OIDC administration independent.
type Combined struct {
	Local *Local
	OIDC  *Server
}

func (a *Combined) Authenticate(r *http.Request) (identity.Identity, string, error) {
	if _, ok := credential(r, localCookieName); ok && a.Local != nil {
		return a.Local.Authenticate(r)
	}
	if a.OIDC != nil {
		return a.OIDC.Authenticate(r)
	}
	return identity.Identity{}, "", ErrUnauthorized
}
func (a *Combined) CheckCSRF(r *http.Request) bool {
	if _, ok := credential(r, localCookieName); ok && a.Local != nil {
		return a.Local.CheckCSRF(r)
	}
	return a.OIDC != nil && a.OIDC.CheckCSRF(r)
}
func (a *Combined) Login(w http.ResponseWriter, r *http.Request) {
	if a.Local != nil {
		a.Local.Login(w, r, a.OIDC != nil)
		return
	}
	if a.OIDC != nil {
		a.OIDC.Login(w, r)
		return
	}
	http.NotFound(w, r)
}
func (a *Combined) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	if a.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	a.OIDC.Login(w, r)
}
func (a *Combined) LocalLogin(w http.ResponseWriter, r *http.Request) {
	if a.Local == nil {
		http.NotFound(w, r)
		return
	}
	a.Local.Submit(w, r)
}
func (a *Combined) Callback(w http.ResponseWriter, r *http.Request) {
	if a.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	a.OIDC.Callback(w, r)
}
func (a *Combined) Logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := credential(r, localCookieName); ok && a.Local != nil {
		a.Local.Logout(w, r)
		return
	}
	if a.OIDC != nil {
		a.OIDC.Logout(w, r)
		return
	}
	failure(w, 403)
}
