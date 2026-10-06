package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"portico-gateway/internal/device"
	"time"
)

func (s *Store) DeviceCreate(ctx context.Context, h string, r device.Record) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(742901004)"); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM portico_devices WHERE expires_at > now()").Scan(&count); e != nil {
		return e
	}
	if count >= 1000 {
		return device.ErrLimited
	}
	_, e = tx.Exec(ctx, "INSERT INTO portico_devices(credential_hash,data,expires_at,next_poll) VALUES($1,$2,$3,$4)", h, r.Data, r.Expires, r.NextPoll)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) DeviceLocked(ctx context.Context, h string, f func(context.Context, *device.Record) error) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var r device.Record
	e = tx.QueryRow(ctx, "SELECT data,expires_at,next_poll FROM portico_devices WHERE credential_hash=$1 FOR UPDATE", h).Scan(&r.Data, &r.Expires, &r.NextPoll)
	if errors.Is(e, pgx.ErrNoRows) {
		return device.ErrExpired
	}
	if e != nil {
		return e
	}
	result := f(context.WithValue(ctx, txContextKey{}, tx), &r)
	if _, e = tx.Exec(ctx, "UPDATE portico_devices SET data=$2,expires_at=$3,next_poll=$4 WHERE credential_hash=$1", h, r.Data, r.Expires, r.NextPoll); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	return result
}

// AllowDeviceStart enforces a cluster-wide budget before contacting the IdP.
func (s *Store) AllowDeviceStart(ctx context.Context) error {
	var count int
	e := s.Pool.QueryRow(ctx, "INSERT INTO portico_rates(bucket,requests) VALUES($1,1) ON CONFLICT(bucket) DO UPDATE SET requests=portico_rates.requests+1 RETURNING requests", time.Now().Unix()/60).Scan(&count)
	if e != nil {
		return e
	}
	if count > 20 {
		return device.ErrLimited
	}
	return nil
}
