package adminauth

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"portico-gateway/internal/session"
	"strings"
	"testing"
	"time"
)

func TestLocalPasswordHash(t *testing.T) {
	hash, err := HashLocalPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyLocalPassword(hash, "correct horse battery staple") || VerifyLocalPassword(hash, "wrong") {
		t.Fatal("password verification failed")
	}
	for _, malformed := range []string{"", "plain", "pbkdf2-sha256$1$abc$abc", "pbkdf2-sha256$600000$abc$abc"} {
		if VerifyLocalPassword(malformed, "correct horse battery staple") {
			t.Fatalf("accepted malformed hash %q", malformed)
		}
	}
}

func TestLocalRateLimitAcrossDatabaseConnections(t *testing.T) {
	dsn := os.Getenv("PORTICO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PostgreSQL integration requires PORTICO_TEST_DATABASE_URL")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	hash, _ := HashLocalPassword("correct horse battery staple")
	a, err := NewLocal("https://portico.example", "operator", hash, &memory{rows: map[string]*session.Record{}}, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a.SetPool(pool)
	if err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), "DELETE FROM portico_local_admin_attempts WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(context.Background(), "DELETE FROM portico_local_admin_attempts WHERE id=1")
	for i := 0; i < 5; i++ {
		ok, err := a.checkAttempt(context.Background(), "operator", "wrong")
		if err != nil || ok {
			t.Fatalf("invalid attempt %d: %v %v", i, ok, err)
		}
	}
	if ok, err := a.checkAttempt(context.Background(), "operator", "correct horse battery staple"); err != nil || ok {
		t.Fatalf("locked account accepted: %v %v", ok, err)
	}
}

func TestLocalSessionAndCSRF(t *testing.T) {
	hash, err := HashLocalPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	store := &memory{rows: map[string]*session.Record{}}
	a, err := NewLocal("https://portico.example", "operator", hash, store, time.Hour, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := a.createSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://portico.example/admin/", nil)
	r.AddCookie(&http.Cookie{Name: localCookieName, Value: handle})
	id, csrf, err := a.Authenticate(r)
	if err != nil || id.Issuer != "portico-local" || id.Subject != "operator" || csrf == "" {
		t.Fatalf("identity=%+v csrf=%q err=%v", id, csrf, err)
	}
	post := httptest.NewRequest("POST", "https://portico.example/admin/models", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
	post.Header.Set("Origin", "https://portico.example")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: localCookieName, Value: handle})
	if !a.CheckCSRF(post) {
		t.Fatal("rejected valid CSRF")
	}
	post.Header.Set("Origin", "https://evil.example")
	if a.CheckCSRF(post) {
		t.Fatal("accepted foreign Origin")
	}
	a.passwordHash = strings.Repeat("x", len(hash))
	if _, _, err := a.Authenticate(r); err != ErrUnauthorized {
		t.Fatalf("password rotation must revoke session: %v", err)
	}
}

func TestLocalLoginKeepsAdminFormCSP(t *testing.T) {
	hash, _ := HashLocalPassword("correct horse battery staple")
	a, err := NewLocal("https://portico.example", "operator", hash, &memory{rows: map[string]*session.Record{}}, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'")
	a.Login(w, httptest.NewRequest("GET", "https://portico.example/admin/login", nil), true)
	if got := w.Header().Get("Content-Security-Policy"); !strings.Contains(got, "form-action 'self'") {
		t.Fatalf("login form blocked by CSP: %q", got)
	}
}
