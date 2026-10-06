package postgres

import (
	"context"
	"os"
	"portico-gateway/internal/device"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"testing"
	"time"
)

func TestLockedPersistsRevocationOnAuthError(t *testing.T) {
	url := os.Getenv("PORTICO_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set PORTICO_TEST_DATABASE_URL for PostgreSQL tests")
	}
	ctx := context.Background()
	s, e := Open(ctx, url)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	h := session.Hash(session.NewCredential())
	if e = s.Create(ctx, h, session.Record{Data: []byte("encrypted"), Expires: time.Now().Add(time.Hour), IdleUntil: time.Now().Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	e = s.Locked(ctx, h, func(r *session.Record) error { r.Data = nil; r.Revoked = true; return session.ErrUnauthorized })
	if e != session.ErrUnauthorized {
		t.Fatal(e)
	}
	e = s.Locked(ctx, h, func(r *session.Record) error {
		if !r.Revoked || len(r.Data) > 0 {
			t.Fatal("revocation was rolled back")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

type testProvider struct{}

func (testProvider) Verify(context.Context, string) (identity.Identity, error) {
	return identity.Identity{Issuer: "https://test.example", Subject: "user", Roles: []string{"r"}, Expires: time.Now().Add(time.Hour)}, nil
}
func (testProvider) Refresh(context.Context, string) (identity.Tokens, error) {
	return identity.Tokens{AccessToken: "access", RefreshToken: "refresh"}, nil
}
func (testProvider) StartDevice(context.Context) (identity.DeviceCode, error) {
	return identity.DeviceCode{DeviceCode: "private", UserCode: "CODE", VerificationURI: "https://test.example/activate", Interval: 5, ExpiresIn: 600}, nil
}
func (testProvider) PollDevice(context.Context, string) (identity.Tokens, error) {
	return identity.Tokens{AccessToken: "access", RefreshToken: "refresh"}, nil
}
func TestDeviceCompletionUsesOneTransactionAndConnection(t *testing.T) {
	dsn := os.Getenv("PORTICO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, e := Open(ctx, dsn+"&pool_max_conns=1")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	v, _ := vault.New(make([]byte, 32))
	sessions := &session.Manager{Store: s, Vault: v, Provider: testProvider{}, MaxAge: time.Hour, IdleAge: time.Minute}
	m := &device.Manager{Store: s, Vault: v, Provider: testProvider{}, Sessions: sessions}
	start, e := m.Start(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Pool.Exec(ctx, "UPDATE portico_devices SET next_poll=now()-interval '1 second' WHERE credential_hash=$1", session.Hash(start.Credential)); e != nil {
		t.Fatal(e)
	}
	c, e := m.Poll(ctx, start.Credential)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = sessions.Access(ctx, c); e != nil {
		t.Fatal("device session missing", e)
	}
	again, e := m.Poll(ctx, start.Credential)
	if e != nil || again != c {
		t.Fatal("retry changed session", e)
	}
}
