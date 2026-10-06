package modelaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"portico-gateway/internal/identity"
	"strconv"
	"strings"
	"time"
)

func (s *Server) complete(w http.ResponseWriter, r *http.Request, id identity.Identity, allowed map[string]bool) {
	started := time.Now()
	kind, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || kind != "application/json" || r.Header.Get("Content-Encoding") != "" {
		failure(w, 415, "unsupported_content_type")
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, s.Config.MaxRequestBytes))
	if e != nil {
		failure(w, 413, "request_too_large")
		return
	}
	model, stream, e := validateRequest(body)
	if e != nil {
		failure(w, 400, "invalid_request")
		return
	}
	if !allowed[model] {
		failure(w, 403, "model_not_allowed")
		return
	}
	deadline := time.Now().Add(s.Config.Duration())
	if id.Expires.Before(deadline) {
		deadline = id.Expires
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	budget := s.Config.ContextBudgets[model]
	dropped := 0
	if budget.WindowTokens > 0 {
		prepared, n, err := PrepareContext(body, budget, false)
		if err == ErrContextTooLarge {
			respond(w, 400, map[string]any{"error": map[string]string{"code": "context_length_exceeded", "message": contextLengthMessage}})
			return
		}
		// Unsupported message formats pass through unchanged; the backend remains
		// authoritative. We never partially rewrite an unsafe tool conversation.
		if err == nil {
			body = prepared
			dropped = n
		}
	}
	var res *http.Response
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(s.Config.Upstream, "/")+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			failure(w, 502, "upstream_unavailable")
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+s.Key)
		if stream {
			req.Header.Set("Accept", "text/event-stream")
		}
		res, e = s.Client.Do(req)
		if e != nil {
			failure(w, 502, "upstream_unavailable")
			return
		}
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			break
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, maxUpstreamErrorBytes))
		res.Body.Close()
		overflow := readErr == nil && len(data) < maxUpstreamErrorBytes && res.StatusCode == 400 && isContextLengthError(data)
		if overflow && budget.WindowTokens > 0 && attempt < 2 {
			prepared, n, err := PrepareContext(body, budget, true)
			if err == nil && n > 0 {
				body = prepared
				dropped += n
				continue
			}
		}
		slog.Info("model request failed", "model", model, "upstream_status", res.StatusCode, "context_overflow", overflow, "duration_ms", time.Since(started).Milliseconds())
		upstreamFailure(w, res.StatusCode, bytes.NewReader(data))
		return
	}
	defer res.Body.Close()
	defer func() {
		slog.Info("model request completed", "subject", id.Subject, "model", model, "upstream_status", res.StatusCode, "duration_ms", time.Since(started).Milliseconds(), "context_turns_removed", dropped)
	}()
	if dropped > 0 {
		w.Header().Set("X-Portico-Context-Turns-Removed", strconv.Itoa(dropped))
	}
	contentType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if stream && contentType != "text/event-stream" || !stream && contentType != "application/json" {
		failure(w, 502, "invalid_upstream_response")
		return
	}
	w.Header().Set("Content-Type", res.Header.Get("Content-Type"))
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	controller := http.NewResponseController(w)
	buf := make([]byte, 32768)
	for {
		n, err := res.Body.Read(buf)
		if n > 0 {
			_ = controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, e = w.Write(buf[:n]); e != nil {
				return
			}
			if stream {
				if controller.Flush() != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

const maxUpstreamErrorBytes = 64 * 1024

const toolArgumentsMessage = "Модель сформировала некорректные аргументы инструмента. Повторите запрос с одним небольшим действием; проверьте результаты уже выполненных действий."

const contextLengthMessage = "Превышен допустимый объём контекста модели. Начните новый диалог или сократите историю и набор инструментов."

// upstreamFailure never copies upstream error fields into the public response.
// Only a bounded, valid JSON error with a recognized context-limit marker may
// change the generic classification. Authentication failures belong to the
// service credential boundary and must not become a user-facing 401/403.
func upstreamFailure(w http.ResponseWriter, upstreamStatus int, body io.Reader) {
	status := http.StatusBadGateway
	if upstreamStatus == http.StatusTooManyRequests {
		status = http.StatusTooManyRequests
	}
	if upstreamStatus == http.StatusBadRequest || upstreamStatus == http.StatusInternalServerError {
		data, err := io.ReadAll(io.LimitReader(body, maxUpstreamErrorBytes))
		if err == nil && len(data) < maxUpstreamErrorBytes {
			code, message := "", ""
			if upstreamStatus == http.StatusBadRequest && isContextLengthError(data) {
				status, code, message = http.StatusBadRequest, "context_length_exceeded", contextLengthMessage
			} else if isToolArgumentsError(data) {
				code, message = "tool_arguments_invalid", toolArgumentsMessage
			}
			if code != "" {
				respond(w, status, map[string]any{"error": map[string]string{
					"message": message, "type": "portico_error", "code": code,
				}})
				return
			}
		}
	}
	failure(w, status, "upstream_request_failed")
}

func isContextLengthError(data []byte) bool {
	var envelope struct {
		Error struct {
			Code    json.RawMessage `json:"code"`
			Type    string          `json:"type"`
			Message string          `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return false
	}
	var code string
	_ = json.Unmarshal(envelope.Error.Code, &code)
	return code == "context_length_exceeded" ||
		envelope.Error.Type == "ContextWindowExceededError" ||
		strings.Contains(envelope.Error.Message, "ContextWindowExceededError")
}

// Match only a known provider parser failure, never arbitrary non-JSON text.
func isToolArgumentsError(data []byte) bool {
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	return json.Unmarshal(data, &envelope) == nil &&
		strings.Contains(envelope.Error.Message, "Failed to parse tool call arguments as JSON")
}
