// Package api exposes the authenticated Portico HTTP boundary.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"portico-gateway/internal/device"
	"portico-gateway/internal/proxy"
	"portico-gateway/internal/session"
	"strings"
	"time"
)

type Server struct {
	Sessions         *session.Manager
	Device           *device.Manager
	Proxy            *proxy.Proxy
	AdapterKey       string
	Ready            func(context.Context) error
	AllowDeviceStart func(context.Context) error
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.Ready == nil || s.Ready(r.Context()) != nil {
			reply(w, 503, map[string]string{"error": "not_ready"})
			return
		}
		reply(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /v1/sessions", s.register)
	mux.HandleFunc("GET /v1/session", s.current)
	mux.HandleFunc("DELETE /v1/session", s.logout)
	mux.HandleFunc("POST /v1/device/start", s.startDevice)
	mux.HandleFunc("POST /v1/device/poll", s.pollDevice)
	mux.HandleFunc("POST /v1/services/{service}/operations/{operation}", s.operation)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Header.Get("Origin") != "" {
			reply(w, 403, map[string]string{"error": "browser_origin_not_allowed"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}
func fail(w http.ResponseWriter, e error) {
	status, code := 503, "service_unavailable"
	switch {
	case errors.Is(e, session.ErrUnauthorized):
		status, code = 401, "invalid_session"
	case errors.Is(e, proxy.ErrForbidden):
		status, code = 403, "forbidden"
	case errors.Is(e, proxy.ErrArguments):
		status, code = 400, "invalid_arguments"
	case errors.Is(e, device.ErrPending):
		status, code = 202, "authorization_pending"
	case errors.Is(e, device.ErrExpired):
		status, code = 401, "expired_token"
	case errors.Is(e, device.ErrLimited):
		status, code = 429, "too_many_requests"
	}
	reply(w, status, map[string]string{"error": code})
}
func (s *Server) adapter(r *http.Request) bool {
	a := sha256.Sum256([]byte(s.AdapterKey))
	b := sha256.Sum256([]byte(r.Header.Get("X-Portico-Adapter-Key")))
	return len(s.AdapterKey) >= 24 && subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
