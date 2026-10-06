package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"portico-gateway/internal/identity"
	"strings"
	"time"
)

var ErrForbidden = errors.New("operation is not permitted")
var ErrArguments = errors.New("invalid operation arguments")

type Proxy struct {
	Client   *http.Client
	Services map[string]Service
}
type Result struct {
	Status      int
	ContentType string
	Body        []byte
}

func (p *Proxy) Call(ctx context.Context, id identity.Identity, token, service, operation string, args map[string]any) (Result, error) {
	s, ok := p.Services[service]
	if !ok {
		return Result{}, ErrForbidden
	}
	allowed := false
	for _, a := range s.Roles {
		for _, b := range id.Roles {
			if a == b {
				allowed = true
			}
		}
	}
	op, ok := s.Operations[operation]
	if !allowed || !ok {
		return Result{}, ErrForbidden
	}
	for k := range args {
		if _, ok := op.Parameters[k]; !ok {
			return Result{}, ErrArguments
		}
	}
	path := op.Path
	query := url.Values{}
	body := map[string]any{}
	for name, param := range op.Parameters {
		v, ok := args[name]
		if !ok {
			if param.Required {
				return Result{}, ErrArguments
			}
			continue
		}
		text := ""
		switch param.Kind {
		case "integer":
			n, ok := v.(float64)
			if !ok || n < 0 || n > 10000000 || math.Trunc(n) != n {
				return Result{}, ErrArguments
			}
			text = fmt.Sprintf("%.0f", n)
		case "id", "string", "url":
			var ok bool
			text, ok = v.(string)
			if !ok || len(text) > 4096 || strings.ContainsAny(text, "\r\n\x00") {
				return Result{}, ErrArguments
			}
			if param.Kind == "id" && !identifier.MatchString(text) {
				return Result{}, ErrArguments
			}
			if param.Kind == "url" {
				u, e := url.Parse(text)
				if e != nil || u.Host == "" || u.User != nil || u.Scheme != "https" && u.Scheme != "http" {
					return Result{}, ErrArguments
				}
			}
		default:
			return Result{}, ErrArguments
		}
		switch param.In {
		case "path":
			path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(text))
		case "query":
			query.Set(name, text)
		case "body":
			body[name] = v
		default:
			return Result{}, ErrArguments
		}
	}
	u, e := url.Parse(strings.TrimRight(s.BaseURL, "/") + path)
	if e != nil {
		return Result{}, ErrArguments
	}
	u.RawQuery = query.Encode()
	var data []byte
	if len(body) > 0 {
		data, e = json.Marshal(body)
		if e != nil {
			return Result{}, ErrArguments
		}
	}
	req, e := http.NewRequestWithContext(ctx, op.Method, u.String(), bytes.NewReader(data))
	if e != nil {
		return Result{}, e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	accept := "application/json"
	if operation == "downloadReport" {
		switch query.Get("format") {
		case "pdf":
			accept = "application/pdf"
		case "html":
			accept = "text/html"
		case "markdown":
			accept = "text/markdown"
		default:
			return Result{}, ErrArguments
		}
	}
	req.Header.Set("Accept", accept)
	if len(data) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	client := *p.Client
	client.Timeout = 30 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, e := client.Do(req)
	if e != nil {
		return Result{}, errors.New("upstream unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return Result{}, errors.New("upstream redirect rejected")
	}
	limit := 2 << 20
	if operation == "downloadReport" {
		limit = 8 << 20
	}
	payload, e := io.ReadAll(io.LimitReader(res.Body, int64(limit)+1))
	if e != nil || len(payload) > limit {
		return Result{}, errors.New("upstream response too large")
	}
	contentType := "application/json"
	if operation == "downloadReport" && res.StatusCode == http.StatusOK {
		contentType = strings.TrimSpace(strings.Split(res.Header.Get("Content-Type"), ";")[0])
		if contentType != accept || len(payload) == 0 {
			return Result{}, errors.New("invalid report response")
		}
	}
	return Result{res.StatusCode, contentType, payload}, nil
}
