package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/vault"
	"time"
)

type Manager struct {
	Store           Store
	Vault           *vault.Vault
	Provider        identity.Provider
	MaxAge, IdleAge time.Duration
}
type contents struct {
	Tokens  identity.Tokens `json:"tokens"`
	Issuer  string          `json:"issuer"`
	Subject string          `json:"subject"`
}

func Hash(credential string) string {
	s := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(s[:])
}
func NewCredential() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func (m *Manager) Create(ctx context.Context, t identity.Tokens) (string, error) {
	id, e := m.Provider.Verify(ctx, t.AccessToken)
	if e != nil {
		return "", ErrUnauthorized
	}
	c := NewCredential()
	plain, e := json.Marshal(contents{t, id.Issuer, id.Subject})
	if e != nil {
		return "", e
	}
	data, e := m.Vault.Seal(plain, Hash(c))
	if e != nil {
		return "", e
	}
	now := time.Now()
	e = m.Store.Create(ctx, Hash(c), Record{Data: data, Expires: now.Add(m.MaxAge), IdleUntil: now.Add(m.IdleAge)})
	if e != nil {
		return "", e
	}
	return c, nil
}
func (m *Manager) Access(ctx context.Context, c string) (identity.Identity, string, error) {
	var id identity.Identity
	var access string
	if len(c) != 43 {
		return id, "", ErrUnauthorized
	}
	h := Hash(c)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	e := m.Store.Locked(ctx, h, func(r *Record) error {
		now := time.Now()
		if r.Revoked || !now.Before(r.Expires) || !now.Before(r.IdleUntil) {
			r.Revoked = true
			r.Data = nil
			return ErrUnauthorized
		}
		plain, e := m.Vault.Open(r.Data, h)
		if e != nil {
			return e
		}
		var saved contents
		if e = json.Unmarshal(plain, &saved); e != nil {
			return e
		}
		id, e = m.Provider.Verify(ctx, saved.Tokens.AccessToken)
		if e != nil || (saved.Tokens.RefreshToken != "" && time.Until(id.Expires) < time.Minute) {
			if saved.Tokens.RefreshToken == "" {
				r.Revoked = true
				r.Data = nil
				return ErrUnauthorized
			}
			t, e := m.Provider.Refresh(ctx, saved.Tokens.RefreshToken)
			if e != nil {
				var oe *identity.OAuthError
				if errors.As(e, &oe) && (oe.Code == "invalid_grant" || oe.Code == "access_denied") {
					r.Revoked = true
					r.Data = nil
					return ErrUnauthorized
				}
				return e
			}
			id, e = m.Provider.Verify(ctx, t.AccessToken)
			if e != nil || id.Issuer != saved.Issuer || id.Subject != saved.Subject {
				r.Revoked = true
				r.Data = nil
				return ErrUnauthorized
			}
			if t.RefreshToken == "" {
				t.RefreshToken = saved.Tokens.RefreshToken
			}
			saved.Tokens = t
		}
		if id.Issuer != saved.Issuer || id.Subject != saved.Subject {
			r.Revoked = true
			r.Data = nil
			return ErrUnauthorized
		}
		plain, e = json.Marshal(saved)
		if e != nil {
			return e
		}
		r.Data, e = m.Vault.Seal(plain, h)
		if e != nil {
			return e
		}
		r.IdleUntil = now.Add(m.IdleAge)
		access = saved.Tokens.AccessToken
		return nil
	})
	return id, access, e
}
func (m *Manager) Logout(ctx context.Context, c string) error {
	if len(c) != 43 {
		return ErrUnauthorized
	}
	return m.Store.Locked(ctx, Hash(c), func(r *Record) error { r.Revoked = true; r.Data = nil; return nil })
}

// CheckActive checks local session lifetime without extending inactivity or
// refreshing upstream tokens. OAuth background refresh is not user activity.
func (m *Manager) CheckActive(ctx context.Context, c string) error {
	if len(c) != 43 {
		return ErrUnauthorized
	}
	return m.Store.Locked(ctx, Hash(c), func(r *Record) error {
		now := time.Now()
		if r.Revoked || !now.Before(r.Expires) || !now.Before(r.IdleUntil) {
			r.Revoked = true
			r.Data = nil
			return ErrUnauthorized
		}
		return nil
	})
}
