package device

import (
	"context"
	"errors"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"sync"
	"testing"
	"time"
)

type store struct {
	mu   sync.Mutex
	rows map[string]*Record
}

func (s *store) DeviceCreate(_ context.Context, h string, r Record) error { s.rows[h] = &r; return nil }
func (s *store) DeviceLocked(_ context.Context, h string, f func(context.Context, *Record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[h]
	if r == nil {
		return ErrExpired
	}
	return f(context.Background(), r)
}

type idp struct {
	calls     int
	errorCode string
}

func (p *idp) StartDevice(context.Context) (identity.DeviceCode, error) {
	return identity.DeviceCode{DeviceCode: "private-code", UserCode: "ABCD", VerificationURI: "https://idp.example/activate", ExpiresIn: 600, Interval: 5}, nil
}
func (p *idp) PollDevice(context.Context, string) (identity.Tokens, error) {
	p.calls++
	if p.errorCode != "" {
		return identity.Tokens{}, &identity.OAuthError{Code: p.errorCode}
	}
	return identity.Tokens{AccessToken: "token", RefreshToken: "refresh"}, nil
}

type registrar struct{ calls int }

func (r *registrar) Create(context.Context, identity.Tokens) (string, error) {
	r.calls++
	return session.NewCredential(), nil
}
func TestPollingRespectsIntervalAndReturnsSameSession(t *testing.T) {
	ctx := context.Background()
	v, _ := vault.New(make([]byte, 32))
	s := &store{rows: map[string]*Record{}}
	p := &idp{}
	reg := &registrar{}
	m := Manager{Store: s, Vault: v, Provider: p, Sessions: reg}
	start, e := m.Start(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Poll(ctx, start.Credential); !errors.Is(e, ErrPending) {
		t.Fatal("early poll accepted", e)
	}
	if p.calls != 0 {
		t.Fatal("polled IdP too early")
	}
	s.rows[session.Hash(start.Credential)].NextPoll = time.Now().Add(-time.Second)
	a, e := m.Poll(ctx, start.Credential)
	if e != nil {
		t.Fatal(e)
	}
	b, e := m.Poll(ctx, start.Credential)
	if e != nil || a != b || reg.calls != 1 {
		t.Fatal("replay created another session")
	}
}
