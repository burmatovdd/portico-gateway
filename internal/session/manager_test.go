package session

import (
	"context"
	"errors"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/vault"
	"sync"
	"testing"
	"time"
)

type memory struct {
	mu   sync.Mutex
	rows map[string]*Record
}

func (s *memory) Create(_ context.Context, h string, r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[h] != nil {
		return errors.New("duplicate")
	}
	s.rows[h] = &r
	return nil
}
func (s *memory) Locked(_ context.Context, h string, f func(*Record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[h]
	if r == nil {
		return ErrUnauthorized
	}
	return f(r)
}

type provider struct {
	calls            int
	started, release chan struct{}
}

func (p *provider) Verify(_ context.Context, token string) (identity.Identity, error) {
	if token == "bad" {
		return identity.Identity{}, errors.New("invalid")
	}
	exp := time.Now().Add(time.Hour)
	if token == "old" {
		exp = time.Now().Add(10 * time.Second)
	}
	return identity.Identity{Subject: "user-a", Issuer: "https://idp.example", Roles: []string{"reader"}, Expires: exp}, nil
}
func (p *provider) Refresh(ctx context.Context, r string) (identity.Tokens, error) {
	p.calls++
	if p.started != nil {
		close(p.started)
		select {
		case <-p.release:
		case <-ctx.Done():
			return identity.Tokens{}, ctx.Err()
		}
	}
	return identity.Tokens{AccessToken: "new", RefreshToken: "rotated"}, nil
}
func setup(t *testing.T, p *provider) *Manager {
	t.Helper()
	v, _ := vault.New(make([]byte, 32))
	return &Manager{Store: &memory{rows: map[string]*Record{}}, Vault: v, Provider: p, MaxAge: time.Hour, IdleAge: time.Minute}
}
func TestLogoutInvalidatesCredentialAndClearsTokens(t *testing.T) {
	ctx := context.Background()
	m := setup(t, &provider{})
	c, err := m.Create(ctx, identity.Tokens{AccessToken: "good", RefreshToken: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Access(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err = m.Logout(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Access(ctx, c); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("logout credential remained valid")
	}
	s := m.Store.(*memory)
	for _, r := range s.rows {
		if len(r.Data) != 0 {
			t.Fatal("retained encrypted tokens")
		}
	}
	if err = m.Logout(ctx, c); err != nil {
		t.Fatal(err)
	}
}
func TestConcurrentRefreshAndLogoutDoesNotResurrectSession(t *testing.T) {
	ctx := context.Background()
	p := &provider{started: make(chan struct{}), release: make(chan struct{})}
	m := setup(t, p)
	c, err := m.Create(ctx, identity.Tokens{AccessToken: "old", RefreshToken: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, e := m.Access(ctx, c); done <- e }()
	<-p.started
	logout := make(chan error, 1)
	go func() { logout <- m.Logout(ctx, c) }()
	close(p.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := <-logout; e != nil {
		t.Fatal(e)
	}
	if _, _, e := m.Access(ctx, c); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("session resurrected")
	}
}
func TestRejectsInvalidTokenAtRegistration(t *testing.T) {
	m := setup(t, &provider{})
	if _, e := m.Create(context.Background(), identity.Tokens{AccessToken: "bad"}); e == nil {
		t.Fatal("accepted bad token")
	}
}

type revokedProvider struct{ provider }

func (p *revokedProvider) Refresh(context.Context, string) (identity.Tokens, error) {
	return identity.Tokens{}, &identity.OAuthError{Code: "invalid_grant"}
}
func TestRevokedRefreshClosesSession(t *testing.T) {
	p := &provider{}
	m := setup(t, p)
	m.Provider = &revokedProvider{}
	c, e := m.Create(context.Background(), identity.Tokens{AccessToken: "old", RefreshToken: "revoked"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = m.Access(context.Background(), c); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("expected reauthentication, got", e)
	}
}

func TestAccessOnlySessionLastsUntilTokenExpiry(t *testing.T) {
	m := setup(t, &provider{})
	c, e := m.Create(context.Background(), identity.Tokens{AccessToken: "old"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = m.Access(context.Background(), c); e != nil {
		t.Fatal("revoked before expiry", e)
	}
}

type disconnectProvider struct {
	provider
	cancel context.CancelFunc
}

func (p *disconnectProvider) Refresh(ctx context.Context, r string) (identity.Tokens, error) {
	p.cancel()
	if ctx.Err() != nil {
		return identity.Tokens{}, ctx.Err()
	}
	return identity.Tokens{AccessToken: "new", RefreshToken: "rotated"}, nil
}
func TestRefreshFinishesAfterCallerDisconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := setup(t, &provider{})
	m.Provider = &disconnectProvider{cancel: cancel}
	c, e := m.Create(ctx, identity.Tokens{AccessToken: "old", RefreshToken: "old-refresh"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = m.Access(ctx, c); e != nil {
		t.Fatal(e)
	}
	_, a, e := m.Access(context.Background(), c)
	if e != nil || a != "new" {
		t.Fatal("rotation lost after disconnect", e)
	}
}

func TestCheckActiveDoesNotExtendIdleAndRejectsLogout(t *testing.T) {
	m := setup(t, &provider{})
	ctx := context.Background()
	c, e := m.Create(ctx, identity.Tokens{AccessToken: "old"})
	if e != nil {
		t.Fatal(e)
	}
	var idle time.Time
	m.Store.Locked(ctx, Hash(c), func(r *Record) error { idle = r.IdleUntil; return nil })
	if e = m.CheckActive(ctx, c); e != nil {
		t.Fatal(e)
	}
	m.Store.Locked(ctx, Hash(c), func(r *Record) error {
		if !idle.Equal(r.IdleUntil) {
			t.Error("background check extended idle lifetime")
		}
		return nil
	})
	m.Logout(ctx, c)
	if !errors.Is(m.CheckActive(ctx, c), ErrUnauthorized) {
		t.Fatal("accepted revoked session")
	}
}
