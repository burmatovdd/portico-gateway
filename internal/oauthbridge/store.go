package oauthbridge

import (
	"context"
	"portico-gateway/internal/session"
	"time"
)

func (s *Server) Migrate(ctx context.Context) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(742901006)"); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS portico_oauth_flows(id text PRIMARY KEY,data bytea NOT NULL,expires_at timestamptz NOT NULL,phase text NOT NULL);
 CREATE TABLE IF NOT EXISTS portico_oauth_codes(id text PRIMARY KEY,data bytea NOT NULL,expires_at timestamptz NOT NULL,used boolean NOT NULL DEFAULT false);
 CREATE TABLE IF NOT EXISTS portico_oauth_families(id text PRIMARY KEY,client_id text NOT NULL,data bytea NOT NULL,access_hash text UNIQUE NOT NULL,access_expires timestamptz NOT NULL,expires_at timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false);
 CREATE TABLE IF NOT EXISTS portico_oauth_refresh(id text PRIMARY KEY,family text NOT NULL REFERENCES portico_oauth_families(id) ON DELETE CASCADE,used boolean NOT NULL DEFAULT false);
 CREATE INDEX IF NOT EXISTS portico_oauth_flows_expiry ON portico_oauth_flows(expires_at);
 CREATE INDEX IF NOT EXISTS portico_oauth_codes_expiry ON portico_oauth_codes(expires_at);
 CREATE INDEX IF NOT EXISTS portico_oauth_families_expiry ON portico_oauth_families(expires_at);`)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Server) AuthorizeMCP(ctx context.Context, token string) (string, time.Time, error) {
	if len(token) != 43 {
		return "", time.Time{}, errInvalid
	}
	var data []byte
	var id string
	var expiry time.Time
	e := s.pool.QueryRow(ctx, "SELECT id,data,access_expires FROM portico_oauth_families WHERE access_hash=$1 AND NOT revoked AND access_expires>now() AND expires_at>now()", session.Hash(token)).Scan(&id, &data, &expiry)
	if e != nil {
		return "", time.Time{}, errInvalid
	}
	var handle string
	if s.open(data, "family:"+id, &handle) != nil {
		return "", time.Time{}, errInvalid
	}
	return handle, expiry, nil
}

// Cleanup removes expired exchanges. Family credentials are erased only after
// the underlying session has been revoked, including retries after outages.
func (s *Server) Cleanup(ctx context.Context) error {
	_, e := s.pool.Exec(ctx, "DELETE FROM portico_oauth_flows WHERE expires_at<now(); DELETE FROM portico_oauth_codes WHERE expires_at<now();")
	if e != nil {
		return e
	}
	rows, e := s.pool.Query(ctx, "SELECT id,data FROM portico_oauth_families WHERE revoked OR expires_at<now() LIMIT 100")
	if e != nil {
		return e
	}
	type item struct {
		id   string
		data []byte
	}
	var items []item
	for rows.Next() {
		var x item
		if e = rows.Scan(&x.id, &x.data); e != nil {
			rows.Close()
			return e
		}
		items = append(items, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, x := range items {
		var handle string
		if e = s.open(x.data, "family:"+x.id, &handle); e != nil {
			return e
		}
		if e = s.sessions.Logout(ctx, handle); e != nil && e != session.ErrUnauthorized {
			return e
		}
		if _, e = s.pool.Exec(ctx, "DELETE FROM portico_oauth_families WHERE id=$1 AND (revoked OR expires_at<now())", x.id); e != nil {
			return e
		}
	}
	return nil
}
