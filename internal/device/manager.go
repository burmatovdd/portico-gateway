// Package device implements server-held Device Authorization transactions.
package device

import (
	"context"
	"encoding/json"
	"errors"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"time"
)

var ErrPending = errors.New("authorization_pending")
var ErrExpired = errors.New("expired_token")
var ErrLimited = errors.New("too_many_requests")

type Record struct {
	Data              []byte
	Expires, NextPoll time.Time
}
type Store interface {
	DeviceCreate(context.Context, string, Record) error
	DeviceLocked(context.Context, string, func(context.Context, *Record) error) error
}
type Provider interface {
	StartDevice(context.Context) (identity.DeviceCode, error)
	PollDevice(context.Context, string) (identity.Tokens, error)
}
type Registrar interface {
	Create(context.Context, identity.Tokens) (string, error)
}
type Manager struct {
	Store    Store
	Vault    *vault.Vault
	Provider Provider
	Sessions Registrar
}
type Start struct {
	Credential      string `json:"credential"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}
type state struct {
	Code     string
	Interval int
	Result   string
	Denied   bool
}

func (m *Manager) Start(ctx context.Context) (Start, error) {
	d, e := m.Provider.StartDevice(ctx)
	if e != nil {
		return Start{}, e
	}
	c := session.NewCredential()
	h := session.Hash(c)
	plain, _ := json.Marshal(state{Code: d.DeviceCode, Interval: d.Interval})
	data, e := m.Vault.Seal(plain, h)
	if e != nil {
		return Start{}, e
	}
	now := time.Now()
	if e = m.Store.DeviceCreate(ctx, h, Record{data, now.Add(time.Duration(d.ExpiresIn) * time.Second), now.Add(time.Duration(d.Interval) * time.Second)}); e != nil {
		return Start{}, e
	}
	return Start{c, d.UserCode, d.VerificationURI, d.ExpiresIn, d.Interval}, nil
}
func (m *Manager) Poll(ctx context.Context, c string) (string, error) {
	if len(c) != 43 {
		return "", ErrExpired
	}
	h := session.Hash(c)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var result string
	e := m.Store.DeviceLocked(ctx, h, func(txctx context.Context, r *Record) error {
		now := time.Now()
		if !now.Before(r.Expires) {
			return ErrExpired
		}
		plain, e := m.Vault.Open(r.Data, h)
		if e != nil {
			return e
		}
		var s state
		if e = json.Unmarshal(plain, &s); e != nil {
			return e
		}
		if s.Denied {
			return ErrExpired
		}
		if s.Result != "" {
			result = s.Result
			return nil
		}
		if now.Before(r.NextPoll) {
			return ErrPending
		}
		tokens, pollErr := m.Provider.PollDevice(ctx, s.Code)
		if pollErr != nil {
			var oe *identity.OAuthError
			if errors.As(pollErr, &oe) {
				switch oe.Code {
				case "authorization_pending":
					pollErr = ErrPending
				case "slow_down":
					s.Interval += 5
					pollErr = ErrPending
				default:
					s.Denied = true
					s.Code = ""
					pollErr = ErrExpired
				}
			}
		} else {
			result, e = m.Sessions.Create(txctx, tokens)
			if e != nil {
				return e
			}
			s.Result = result
			s.Code = ""
			r.Expires = now.Add(time.Minute)
		}
		r.NextPoll = now.Add(time.Duration(s.Interval) * time.Second)
		plain, _ = json.Marshal(s)
		r.Data, e = m.Vault.Seal(plain, h)
		if e != nil {
			return e
		}
		return pollErr
	})
	return result, e
}
