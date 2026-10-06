// Package session manages opaque, revocable credentials and upstream tokens.
package session

import (
	"context"
	"errors"
	"time"
)

var ErrUnauthorized = errors.New("session is not active")

type Record struct {
	Data      []byte
	Expires   time.Time
	IdleUntil time.Time
	Revoked   bool
}

// Locked serializes all mutations of a session, including logout, across replicas.
// It must persist callback mutations even when the callback returns an auth error.
// Storage failures must be returned and must never be treated as successful logout.
type Store interface {
	Create(context.Context, string, Record) error
	Locked(context.Context, string, func(*Record) error) error
}
