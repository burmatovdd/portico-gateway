package api

import (
	"net/http"
	"portico-gateway/internal/identity"
)

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.adapter(r) {
		reply(w, 401, map[string]string{"error": "invalid_adapter"})
		return
	}
	var tokens identity.Tokens
	if e := decode(r, &tokens); e != nil {
		reply(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	c, e := s.Sessions.Create(r.Context(), tokens)
	if e != nil {
		fail(w, e)
		return
	}
	reply(w, 201, map[string]string{"credential": c})
}
func (s *Server) current(w http.ResponseWriter, r *http.Request) {
	id, _, e := s.Sessions.Access(r.Context(), bearer(r))
	if e != nil {
		fail(w, e)
		return
	}
	reply(w, 200, id)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if e := s.Sessions.Logout(r.Context(), bearer(r)); e != nil {
		fail(w, e)
		return
	}
	w.WriteHeader(204)
}
func (s *Server) startDevice(w http.ResponseWriter, r *http.Request) {
	if s.AllowDeviceStart != nil {
		if e := s.AllowDeviceStart(r.Context()); e != nil {
			fail(w, e)
			return
		}
	}
	result, e := s.Device.Start(r.Context())
	if e != nil {
		fail(w, e)
		return
	}
	reply(w, 201, result)
}
func (s *Server) pollDevice(w http.ResponseWriter, r *http.Request) {
	c, e := s.Device.Poll(r.Context(), bearer(r))
	if e != nil {
		fail(w, e)
		return
	}
	reply(w, 200, map[string]string{"credential": c})
}
func (s *Server) operation(w http.ResponseWriter, r *http.Request) {
	id, token, e := s.Sessions.Access(r.Context(), bearer(r))
	if e != nil {
		fail(w, e)
		return
	}
	var args map[string]any
	if e = decode(r, &args); e != nil {
		reply(w, 400, map[string]string{"error": "invalid_arguments"})
		return
	}
	result, e := s.Proxy.Call(r.Context(), id, token, r.PathValue("service"), r.PathValue("operation"), args)
	if e != nil {
		fail(w, e)
		return
	}
	w.Header().Set("Content-Type", result.ContentType)
	w.WriteHeader(result.Status)
	_, _ = w.Write(result.Body)
}
