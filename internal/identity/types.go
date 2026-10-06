// Package identity verifies user credentials issued by the configured identity provider.
package identity

import (
	"context"
	"time"
)

type Identity struct {
	Issuer  string    `json:"issuer"`
	Subject string    `json:"subject"`
	Roles   []string  `json:"roles"`
	Expires time.Time `json:"expires_at"`
}
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
type Provider interface {
	Verify(context.Context, string) (Identity, error)
	Refresh(context.Context, string) (Tokens, error)
}
