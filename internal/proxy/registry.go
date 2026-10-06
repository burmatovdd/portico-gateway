// Package proxy dispatches approved operations; it is not an open HTTP proxy.
package proxy

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

type Parameter struct {
	Kind     string `yaml:"kind" json:"kind"`
	In       string `yaml:"in" json:"in"`
	Required bool   `yaml:"required" json:"required"`
}
type Operation struct {
	Description string               `yaml:"description"`
	Method      string               `yaml:"method"`
	Path        string               `yaml:"path"`
	Parameters  map[string]Parameter `yaml:"parameters"`
}
type Service struct {
	BaseURL    string               `yaml:"base_url"`
	Roles      []string             `yaml:"roles"`
	Operations map[string]Operation `yaml:"operations"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func Validate(services map[string]Service) error {
	for name, s := range services {
		u, e := url.Parse(s.BaseURL)
		if !identifier.MatchString(name) || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || len(s.Roles) == 0 {
			return errors.New("invalid service configuration")
		}
		for op, v := range s.Operations {
			if !identifier.MatchString(op) || v.Method != "GET" && v.Method != "POST" && v.Method != "DELETE" || !strings.HasPrefix(v.Path, "/") || strings.ContainsAny(v.Path, "?#%\\") || strings.HasPrefix(v.Path, "//") {
				return errors.New("invalid operation")
			}
			path := v.Path
			for n, p := range v.Parameters {
				if !identifier.MatchString(n) || p.In != "path" && p.In != "query" && p.In != "body" {
					return errors.New("invalid parameter")
				}
				if p.Kind != "id" && p.Kind != "integer" && p.Kind != "url" && p.Kind != "string" {
					return errors.New("invalid parameter type")
				}
				if p.In == "path" {
					if p.Kind != "id" || !p.Required || !strings.Contains(path, "{"+n+"}") {
						return errors.New("path parameters must be required IDs")
					}
					path = strings.ReplaceAll(path, "{"+n+"}", "id")
				}
			}
			if strings.ContainsAny(path, "{}") || strings.Contains(path, "..") {
				return errors.New("invalid path template")
			}
		}
	}
	return nil
}
