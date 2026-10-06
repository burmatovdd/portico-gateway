package modelpolicy

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	for _, bad := range []map[string][]string{nil, {"": {"a"}}, {"g": {}}, {"g": {"*"}}, {"g": {"a", "a"}}, {"g": {"a\nb"}}} {
		if Validate(bad) == nil {
			t.Fatalf("accepted %#v", bad)
		}
	}
	if Validate(map[string][]string{}) != nil {
		t.Fatal("empty must revoke all")
	}
}
func TestPolicyTransactionAndBootstrap(t *testing.T) {
	dsn := os.Getenv("PORTICO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("local PostgreSQL required")
	}
	ctx := context.Background()
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	if (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") || (cfg.ConnConfig.Database != "portico_test" && cfg.ConnConfig.Database != "portico_admin_test") {
		t.Fatal("only a local disposable portico_test or portico_admin_test database is allowed")
	}
	setup, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer setup.Close()
	schema := fmt.Sprintf("policy_test_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, e = setup.Exec(ctx, "CREATE SCHEMA "+quoted); e != nil {
		t.Fatal(e)
	}
	defer setup.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	s := &Store{pool}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Seed(ctx, map[string][]string{"g": {"first"}}); e != nil {
		t.Fatal(e)
	}
	if e = s.Update(ctx, 1, "issuer|admin", map[string][]string{"g": {"second"}}); e != nil {
		t.Fatal(e)
	}
	if e = s.Seed(ctx, map[string][]string{"g": {"first"}}); e != nil {
		t.Fatal(e)
	}
	allowed, e := s.Allowed(ctx, []string{"g"})
	if e != nil || allowed["first"] || !allowed["second"] {
		t.Fatal(allowed, e)
	}
	if e = s.Update(ctx, 1, "other", map[string][]string{}); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	history, e := s.History(ctx)
	if e != nil || len(history) != 1 || history[0].Subject != "issuer|admin" {
		t.Fatal(history, e)
	}
	if e = s.Update(ctx, 2, "issuer|admin", map[string][]string{}); e != nil {
		t.Fatal(e)
	}
	allowed, e = s.Allowed(ctx, []string{"g"})
	if e != nil || len(allowed) != 0 {
		t.Fatal(allowed, e)
	}
}
