package modelaccess

import (
	"errors"
	"gopkg.in/yaml.v3"
	"net/url"
	"os"
	"time"
)

type Config struct {
	ContextBudgets     map[string]ContextBudget `yaml:"context_budgets"`
	PolicyStore        string                   `yaml:"policy_store"`
	Listen             string                   `yaml:"listen"`
	Issuer             string                   `yaml:"issuer"`
	Audience           string                   `yaml:"audience"`
	Organization       string                   `yaml:"organization"`
	GroupsClaim        string                   `yaml:"groups_claim"`
	Upstream           string                   `yaml:"upstream"`
	AllowHTTP          bool                     `yaml:"allow_http"`
	Rules              map[string][]string      `yaml:"rules"`
	MaxRequestBytes    int64                    `yaml:"max_request_bytes"`
	MaxDurationSeconds int                      `yaml:"max_duration_seconds"`
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
	if c.PolicyStore != "" && c.PolicyStore != "postgres" {
		return c, errors.New("unsupported policy_store")
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.GroupsClaim == "" {
		c.GroupsClaim = "groups"
	}
	if c.MaxRequestBytes == 0 {
		c.MaxRequestBytes = 4 << 20
	}
	if c.MaxDurationSeconds == 0 {
		c.MaxDurationSeconds = 600
	}
	u, e := url.Parse(c.Upstream)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(c.AllowHTTP && u.Scheme == "http")) {
		return c, errors.New("invalid fixed upstream")
	}
	if c.Issuer == "" || c.Audience == "" || c.MaxRequestBytes < 1024 || c.MaxRequestBytes > 32<<20 || c.MaxDurationSeconds < 1 || c.MaxDurationSeconds > 1800 {
		return c, errors.New("invalid model gateway configuration")
	}
	for model, b := range c.ContextBudgets {
		if model == "" || b.WindowTokens < 1024 || b.WindowTokens > 1048576 || b.ReserveTokens < 1 || b.ReserveTokens >= b.WindowTokens {
			return c, errors.New("invalid context budget")
		}
	}
	for group, models := range c.Rules {
		if group == "" || len(models) == 0 {
			return c, errors.New("empty model policy")
		}
		for _, m := range models {
			if m == "" || m == "*" {
				return c, errors.New("explicit model identifiers required")
			}
		}
	}
	return c, nil
}
func (c Config) Duration() time.Duration { return time.Duration(c.MaxDurationSeconds) * time.Second }
