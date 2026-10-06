package identity

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Options struct {
	Issuer, ClientID, ClientSecret, Audience, RolesClaim, RolesFormat string
	RequiredOrganization                                              string
	Scopes                                                            []string
}
type OIDC struct {
	options                       Options
	client                        *http.Client
	verifier                      *oidc.IDTokenVerifier
	loginVerifier                 *oidc.IDTokenVerifier
	AuthorizationEndpoint         string
	TokenEndpoint, DeviceEndpoint string
}

func NewOIDC(ctx context.Context, o Options, client *http.Client) (*OIDC, error) {
	u, e := url.Parse(o.Issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("OIDC issuer must be HTTPS")
	}
	copyClient := *client
	copyClient.Timeout = 10 * time.Second
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx = oidc.ClientContext(ctx, &copyClient)
	p, e := oidc.NewProvider(ctx, o.Issuer)
	if e != nil {
		return nil, e
	}
	var discovery struct {
		Token         string `json:"token_endpoint"`
		Authorization string `json:"authorization_endpoint"`
		Device        string `json:"device_authorization_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	if e = p.Claims(&discovery); e != nil {
		return nil, e
	}
	for _, raw := range []string{discovery.Token, discovery.JWKS, discovery.Device, discovery.Authorization} {
		if raw == "" {
			continue
		}
		v, e := url.Parse(raw)
		if e != nil || v.Scheme != "https" || v.Host != u.Host || v.User != nil || v.Fragment != "" {
			return nil, errors.New("OIDC endpoint must use issuer origin")
		}
	}
	if discovery.Token == "" || discovery.JWKS == "" || o.Audience == "" || o.ClientID == "" {
		return nil, errors.New("missing OIDC configuration")
	}
	return &OIDC{options: o, client: &copyClient, AuthorizationEndpoint: discovery.Authorization, loginVerifier: p.Verifier(&oidc.Config{ClientID: o.ClientID, SupportedSigningAlgs: []string{"RS256", "ES256"}}), verifier: p.Verifier(&oidc.Config{ClientID: o.Audience, SupportedSigningAlgs: []string{"RS256", "ES256"}}), TokenEndpoint: discovery.Token, DeviceEndpoint: discovery.Device}, nil
}
func (p *OIDC) Verify(ctx context.Context, raw string) (Identity, error) {
	token, e := p.verifier.Verify(oidc.ClientContext(ctx, p.client), raw)
	if e != nil {
		return Identity{}, e
	}
	if token.Subject == "" || token.IssuedAt.IsZero() || token.IssuedAt.After(time.Now().Add(30*time.Second)) {
		return Identity{}, errors.New("missing or invalid identity claims")
	}
	var claims map[string]any
	if e = token.Claims(&claims); e != nil {
		return Identity{}, e
	}
	if p.options.RequiredOrganization != "" && claims["owner"] != p.options.RequiredOrganization {
		return Identity{}, errors.New("organization not allowed")
	}
	if raw, present := claims["nbf"]; present {
		nbf, ok := raw.(float64)
		if !ok || nbf > float64(time.Now().Unix()) {
			return Identity{}, errors.New("token not active")
		}
	}
	var value any = claims
	for _, part := range strings.Split(p.options.RolesClaim, ".") {
		m, ok := value.(map[string]any)
		if !ok {
			value = nil
			break
		}
		value = m[part]
	}
	var roles []string
	if list, ok := value.([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok && s != "" {
				roles = append(roles, s)
			} else if p.options.RolesFormat == "casdoor" {
				if m, ok := item.(map[string]any); ok && m["isEnabled"] != false {
					a, aok := m["owner"].(string)
					b, bok := m["name"].(string)
					if aok && bok && a != "" && b != "" {
						roles = append(roles, a+"/"+b)
					}
				}
			}
		}
	}
	return Identity{token.Issuer, token.Subject, roles, token.Expiry}, nil
}

// OAuthError contains only the protocol error code, never the response body or tokens.
type OAuthError struct{ Code string }

func (e *OAuthError) Error() string { return "identity provider rejected request: " + e.Code }
func (p *OIDC) Post(ctx context.Context, endpoint string, form url.Values, out any) error {
	form.Set("client_id", p.options.ClientID)
	if p.options.ClientSecret != "" {
		form.Set("client_secret", p.options.ClientSecret)
	}
	r, e := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, e := p.client.Do(r)
	if e != nil {
		return errors.New("identity provider unavailable")
	}
	defer res.Body.Close()
	data, e := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if e != nil || len(data) > 1<<20 {
		return errors.New("invalid identity provider response")
	}
	if res.StatusCode != http.StatusOK {
		var body struct {
			Code string `json:"error"`
		}
		_ = json.Unmarshal(data, &body)
		switch body.Code {
		case "authorization_pending", "slow_down", "access_denied", "expired_token", "invalid_grant", "invalid_client", "unauthorized_client", "invalid_scope":
			return &OAuthError{body.Code}
		default:
			return errors.New("identity provider rejected request")
		}
	}
	return json.Unmarshal(data, out)
}
func (p *OIDC) Refresh(ctx context.Context, refresh string) (Tokens, error) {
	var t Tokens
	e := p.Post(ctx, p.TokenEndpoint, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, &t)
	if e == nil && t.AccessToken == "" {
		e = errors.New("missing access token")
	}
	return t, e
}
func (p *OIDC) Scopes() string { return strings.Join(p.options.Scopes, " ") }
