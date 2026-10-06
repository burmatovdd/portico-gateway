package config

import (
	"errors"
	"net/url"
	"strings"
)

func httpsOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.ContainsAny(raw, "\r\n\x00")
}
func validateMCP(c Config) error {
	if !httpsOrigin(c.PublicURL) {
		return errors.New("public_url must be an HTTPS origin without a path or trailing slash")
	}
	for _, origin := range c.OAuth.AllowedOrigins {
		if !httpsOrigin(origin) {
			return errors.New("allowed_origins must contain exact HTTPS origins")
		}
	}
	if len(c.OAuth.Clients) == 0 {
		return errors.New("configure at least one OAuth client")
	}
	clients := map[string]bool{}
	for _, client := range c.OAuth.Clients {
		if client.ID == "" || len(client.ID) > 256 || clients[client.ID] || len(client.RedirectURIs) == 0 {
			return errors.New("invalid OAuth client registration")
		}
		clients[client.ID] = true
	}
	names := map[string]bool{}
	for service, s := range c.Services {
		for operation := range s.Operations {
			name := service + "__" + operation
			if len(name) > 128 || names[name] {
				return errors.New("MCP tool names must be unique and at most 128 characters")
			}
			names[name] = true
		}
	}
	return nil
}
