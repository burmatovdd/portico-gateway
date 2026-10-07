// Package config loads public settings separately from runtime secrets.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/url"
	"os"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/oauthbridge"
	"portico-gateway/internal/proxy"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Portal struct {
		Enabled bool   `yaml:"enabled"`
		Service string `yaml:"service"`
	} `yaml:"portal"`
	Admin struct {
		Enabled    bool     `yaml:"enabled"`
		Groups     []string `yaml:"groups"`
		CatalogURL string   `yaml:"catalog_url"`
		AllowHTTP  bool     `yaml:"allow_http"`
		Local      struct {
			Enabled  bool   `yaml:"enabled"`
			Username string `yaml:"username"`
		} `yaml:"local"`
	} `yaml:"admin"`
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
	OAuth     struct {
		Clients        []oauthbridge.Client `yaml:"clients"`
		AllowedOrigins []string             `yaml:"allowed_origins"`
	} `yaml:"oauth"`
	OIDC struct {
		Issuer      string   `yaml:"issuer"`
		ClientID    string   `yaml:"client_id"`
		Audience    string   `yaml:"audience"`
		RolesClaim  string   `yaml:"roles_claim"`
		RolesFormat string   `yaml:"roles_format"`
		Scopes      []string `yaml:"scopes"`
	} `yaml:"oidc"`
	Session struct {
		MaxAgeSeconds int `yaml:"max_age_seconds"`
		IdleSeconds   int `yaml:"idle_seconds"`
	} `yaml:"session"`
	Services map[string]proxy.Service `yaml:"services"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Session.MaxAgeSeconds == 0 {
		c.Session.MaxAgeSeconds = 43200
	}
	if c.Session.IdleSeconds == 0 {
		c.Session.IdleSeconds = 1800
	}
	if c.Session.IdleSeconds < 60 || c.Session.MaxAgeSeconds < c.Session.IdleSeconds || c.Session.MaxAgeSeconds > 86400 {
		return c, errors.New("invalid session lifetimes")
	}
	if c.OIDC.RolesClaim == "" || c.OIDC.RolesFormat != "strings" && c.OIDC.RolesFormat != "casdoor" {
		return c, errors.New("configure roles_claim and roles_format")
	}
	if c.Portal.Enabled {
		if _, ok := c.Services[c.Portal.Service]; !ok {
			return c, errors.New("portal service is not configured")
		}
	}
	if c.Admin.Enabled {
		u, err := url.Parse(c.Admin.CatalogURL)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(c.Admin.AllowHTTP && u.Scheme == "http")) || (!c.Admin.Local.Enabled && len(c.Admin.Groups) == 0) {
			return c, errors.New("invalid admin configuration")
		}
		if c.Admin.Local.Enabled && (c.Admin.Local.Username == "" || len(c.Admin.Local.Username) > 128 || c.Admin.Local.Username != strings.TrimSpace(c.Admin.Local.Username) || strings.ContainsAny(c.Admin.Local.Username, "\r\n\x00")) {
			return c, errors.New("invalid local admin username")
		}
		for _, group := range c.Admin.Groups {
			if group == "" || group == "*" {
				return c, errors.New("explicit admin groups required")
			}
		}
	}
	if e = validateMCP(c); e != nil {
		return c, e
	}
	return c, proxy.Validate(c.Services)
}
func (c Config) OIDCOptions() identity.Options {
	return identity.Options{Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, Audience: c.OIDC.Audience, RolesClaim: c.OIDC.RolesClaim, RolesFormat: c.OIDC.RolesFormat, Scopes: c.OIDC.Scopes, ClientSecret: os.Getenv("PORTICO_OIDC_CLIENT_SECRET")}
}
func HTTPClient() (*http.Client, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if path := os.Getenv("PORTICO_CA_FILE"); path != "" {
		data, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, nil
}
func EncryptionKey() ([]byte, error) {
	key, e := base64.StdEncoding.DecodeString(os.Getenv("PORTICO_ENCRYPTION_KEY"))
	if e != nil || len(key) != 32 {
		return nil, errors.New("PORTICO_ENCRYPTION_KEY must be a base64-encoded 32-byte key")
	}
	return key, nil
}
func DatabaseURL() (string, error) {
	host := os.Getenv("PORTICO_DATABASE_HOST")
	user := os.Getenv("PORTICO_DATABASE_USER")
	name := os.Getenv("PORTICO_DATABASE_NAME")
	port := os.Getenv("PORTICO_DATABASE_PORT")
	if port == "" {
		port = "5432"
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 || host == "" || user == "" || name == "" {
		return "", errors.New("invalid database configuration")
	}
	u := url.URL{Scheme: "postgres", Host: fmt.Sprintf("%s:%s", host, port), User: url.UserPassword(user, os.Getenv("PORTICO_DATABASE_PASSWORD")), Path: "/" + name}
	q := url.Values{}
	ssl := os.Getenv("PORTICO_DATABASE_SSLMODE")
	if ssl == "" {
		ssl = "verify-full"
	}
	q.Set("sslmode", ssl)
	if ca := os.Getenv("PORTICO_DATABASE_CA_FILE"); ca != "" {
		q.Set("sslrootcert", ca)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
