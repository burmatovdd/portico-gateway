package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
)

// AuthorizationURL starts a server-side OIDC login with PKCE and a nonce.
func (p *OIDC) AuthorizationURL(state, nonce, challenge, redirectURI string) (string, error) {
	if p.AuthorizationEndpoint == "" || state == "" || nonce == "" || challenge == "" {
		return "", errors.New("authorization configuration incomplete")
	}
	u, err := url.Parse(p.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", p.options.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", p.Scopes())
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode verifies the login ID token and binds it to the downstream access identity.
func (p *OIDC) ExchangeCode(ctx context.Context, code, verifier, redirectURI, nonce string) (Tokens, error) {
	if code == "" || verifier == "" || nonce == "" {
		return Tokens{}, errors.New("incomplete authorization response")
	}
	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	err := p.Post(ctx, p.TokenEndpoint, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirectURI}}, &result)
	if err != nil {
		cause := "upstream_request_failed"
		var oe *OAuthError
		if errors.As(err, &oe) {
			switch oe.Code {
			case "invalid_grant", "invalid_client", "access_denied", "unauthorized_client", "invalid_scope":
				cause = oe.Code
			}
		}
		slog.Warn("OIDC authorization failed", "stage", "token_exchange", "reason", cause)
		return Tokens{}, err
	}
	if result.IDToken == "" || result.AccessToken == "" {
		slog.Warn("OIDC authorization failed", "stage", "token_response", "reason", "missing_tokens")
		return Tokens{}, errors.New("missing OIDC tokens")
	}
	login, err := p.loginVerifier.Verify(oidc.ClientContext(ctx, p.client), result.IDToken)
	if err != nil {
		slog.Warn("OIDC authorization failed", "stage", "id_token", "reason", "verification_failed")
		return Tokens{}, errors.New("invalid login identity")
	}
	if login.Subject == "" {
		slog.Warn("OIDC authorization failed", "stage", "id_token", "reason", "missing_subject")
		return Tokens{}, errors.New("invalid login identity")
	}
	if subtle.ConstantTimeCompare([]byte(login.Nonce), []byte(nonce)) != 1 {
		slog.Warn("OIDC authorization failed", "stage", "id_token", "reason", "nonce_mismatch")
		return Tokens{}, errors.New("invalid login identity")
	}
	access, err := p.Verify(ctx, result.AccessToken)
	if err != nil {
		slog.Warn("OIDC authorization failed", "stage", "access_token", "reason", "verification_failed")
		return Tokens{}, errors.New("access identity does not match login")
	}
	if login.Subject != access.Subject || login.Issuer != access.Issuer {
		slog.Warn("OIDC authorization failed", "stage", "identity_binding", "reason", "identity_mismatch")
		return Tokens{}, errors.New("access identity does not match login")
	}
	return Tokens{AccessToken: result.AccessToken, RefreshToken: result.RefreshToken}, nil
}
