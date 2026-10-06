// Package postgres owns the SQL persistence boundary and migrations.
package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"portico-gateway/internal/session"
	"time"
)

type txContextKey struct{}

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	p, e := pgxpool.New(ctx, url)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return &Store{p}, nil
}
func (s *Store) Close() { s.Pool.Close() }
func (s *Store) Migrate(ctx context.Context) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(742901003)"); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS portico_rates (bucket bigint PRIMARY KEY, requests integer NOT NULL); CREATE TABLE IF NOT EXISTS portico_sessions (credential_hash text PRIMARY KEY, data bytea, expires_at timestamptz NOT NULL, idle_until timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false); CREATE INDEX IF NOT EXISTS portico_sessions_expiry ON portico_sessions(expires_at); CREATE TABLE IF NOT EXISTS portico_devices (credential_hash text PRIMARY KEY, data bytea NOT NULL, expires_at timestamptz NOT NULL, next_poll timestamptz NOT NULL); CREATE INDEX IF NOT EXISTS portico_devices_expiry ON portico_devices(expires_at);`)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) Create(ctx context.Context, h string, r session.Record) error {
	runner := interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	}(s.Pool)
	if tx, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok {
		runner = tx
	}
	_, e := runner.Exec(ctx, "INSERT INTO portico_sessions(credential_hash,data,expires_at,idle_until,revoked) VALUES($1,$2,$3,$4,$5)", h, r.Data, r.Expires, r.IdleUntil, r.Revoked)
	return e
}
func (s *Store) Locked(ctx context.Context, h string, f func(*session.Record) error) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var r session.Record
	e = tx.QueryRow(ctx, "SELECT data,expires_at,idle_until,revoked FROM portico_sessions WHERE credential_hash=$1 FOR UPDATE", h).Scan(&r.Data, &r.Expires, &r.IdleUntil, &r.Revoked)
	if errors.Is(e, pgx.ErrNoRows) {
		return session.ErrUnauthorized
	}
	if e != nil {
		return e
	}
	result := f(&r)
	if _, e = tx.Exec(ctx, "UPDATE portico_sessions SET data=$2,expires_at=$3,idle_until=$4,revoked=$5 WHERE credential_hash=$1", h, r.Data, r.Expires, r.IdleUntil, r.Revoked); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	return result
}
func (s *Store) Cleanup(ctx context.Context) error {
	if _, e := s.Pool.Exec(ctx, "DELETE FROM portico_rates WHERE bucket < $1", time.Now().Unix()/60-2); e != nil {
		return e
	}
	_, e := s.Pool.Exec(ctx, "DELETE FROM portico_sessions WHERE expires_at < $1 OR idle_until < $1;", time.Now())
	if e != nil {
		return e
	}
	_, e = s.Pool.Exec(ctx, "DELETE FROM portico_devices WHERE expires_at < $1", time.Now())
	return e
}
