package identity

import (
	"context"
	"errors"
	"net/url"
)

type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (p *OIDC) StartDevice(ctx context.Context) (DeviceCode, error) {
	var d DeviceCode
	if p.DeviceEndpoint == "" {
		return d, errors.New("IdP does not advertise device authorization")
	}
	e := p.Post(ctx, p.DeviceEndpoint, url.Values{"scope": {p.Scopes()}}, &d)
	if e != nil {
		return d, e
	}
	u, e := url.Parse(d.VerificationURI)
	issuer, _ := url.Parse(p.options.Issuer)
	if e != nil || u.Scheme != "https" || u.Host != issuer.Host || u.User != nil || d.DeviceCode == "" || d.UserCode == "" || d.ExpiresIn <= 0 || d.ExpiresIn > 1800 {
		return d, errors.New("invalid device authorization response")
	}
	if d.Interval < 5 {
		d.Interval = 5
	}
	return d, nil
}
func (p *OIDC) PollDevice(ctx context.Context, code string) (Tokens, error) {
	var t Tokens
	e := p.Post(ctx, p.TokenEndpoint, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {code}}, &t)
	if e == nil && (t.AccessToken == "" || t.RefreshToken == "") {
		e = errors.New("device flow requires access and refresh tokens")
	}
	return t, e
}
