package adminauth

import "context"

func (s *Server) Migrate(ctx context.Context) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(742901116)"); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS portico_admin_flows (
 id text PRIMARY KEY, data bytea NOT NULL, expires_at timestamptz NOT NULL
 ); CREATE INDEX IF NOT EXISTS portico_admin_flows_expiry ON portico_admin_flows(expires_at);`)
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	return s.Cleanup(ctx)
}

// Cleanup also runs on login: expired state cannot accumulate without a scheduler.
func (s *Server) Cleanup(ctx context.Context) error {
	_, e := s.pool.Exec(ctx, "DELETE FROM portico_admin_flows WHERE expires_at<=now()")
	return e
}
