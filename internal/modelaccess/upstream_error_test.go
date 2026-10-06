package modelaccess

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpstreamErrorSanitization(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantStatus int
		wantCode   string
	}{
		{"litellm context", 400, `{"error":{"message":"litellm.ContextWindowExceededError: request (17175 tokens) exceeds the available context size (16384 tokens), try increasing it","type":"invalid_request_error","param":null,"code":400}}`, 400, "context_length_exceeded"},
		{"tool json", 500, `{"error":{"message":"Failed to parse tool call arguments as JSON: secret-prompt"}}`, 502, "tool_arguments_invalid"},
		{"tool json bad request", 400, `{"error":{"message":"Failed to parse tool call arguments as JSON"}}`, 502, "tool_arguments_invalid"},
		{"canonical code", 400, `{"error":{"code":"context_length_exceeded"}}`, 400, "context_length_exceeded"},
		{"exception type", 400, `{"error":{"type":"ContextWindowExceededError"}}`, 400, "context_length_exceeded"},
		{"malicious recognized error", 400, `{"error":{"message":"ContextWindowExceededError: secret-prompt api_key=sk-secret https://private.example","code":"secret-key","url":"https://private.example"},"private":"secret"}`, 400, "context_length_exceeded"},
		{"arbitrary message", 400, `{"error":{"message":"secret-prompt api_key=sk-secret https://private.example","code":"secret-key"}}`, 502, "upstream_request_failed"},
		{"malformed", 400, `{"error":{"message":"ContextWindowExceededError"}`, 502, "upstream_request_failed"},
		{"html", 400, `<html>ContextWindowExceededError secret</html>`, 502, "upstream_request_failed"},
		{"wrong shape", 400, `{"error":"ContextWindowExceededError"}`, 502, "upstream_request_failed"},
		{"oversized", 400, `{"error":{"message":"ContextWindowExceededError ` + strings.Repeat("x", maxUpstreamErrorBytes) + `"}}`, 502, "upstream_request_failed"},
		{"oversized trailing whitespace", 400, `{"error":{"code":"context_length_exceeded"}}` + strings.Repeat(" ", maxUpstreamErrorBytes), 502, "upstream_request_failed"},
		{"rate limited", 429, `{"error":{"message":"secret"}}`, 429, "upstream_request_failed"},
		{"upstream unauthorized", 401, `{"error":{"message":"secret"}}`, 502, "upstream_request_failed"},
		{"upstream forbidden", 403, `{"error":{"message":"secret"}}`, 502, "upstream_request_failed"},
		{"unavailable", 503, `{"error":{"code":"context_length_exceeded"}}`, 502, "upstream_request_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			upstreamFailure(w, tc.status, strings.NewReader(tc.body))
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			var response map[string]map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			expectedMessage := tc.wantCode
			if tc.wantCode == "context_length_exceeded" {
				expectedMessage = contextLengthMessage
			} else if tc.wantCode == "tool_arguments_invalid" {
				expectedMessage = toolArgumentsMessage
			}
			errBody := response["error"]
			if len(response) != 1 || len(errBody) != 3 || errBody["code"] != tc.wantCode || errBody["message"] != expectedMessage || errBody["type"] != "portico_error" {
				t.Fatalf("unsanitized or wrong response: %s", w.Body.String())
			}
		})
	}
}

type countedErrorReader struct{ read int }

func (r *countedErrorReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.read += len(p)
	return len(p), nil
}
func TestUpstreamErrorReadBound(t *testing.T) {
	body := &countedErrorReader{}
	upstreamFailure(httptest.NewRecorder(), 400, body)
	if body.read > maxUpstreamErrorBytes {
		t.Fatalf("read %d bytes", body.read)
	}
}

func TestCompletionContextErrorIntegration(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":{"message":"litellm.ContextWindowExceededError: request (17175 tokens) exceeds the available context size (16384 tokens), try increasing it"}}`)
	}))
	defer upstream.Close()
	s := New(verifier{[]string{"g"}}, Config{Upstream: upstream.URL, Rules: map[string][]string{"g": {"pentest"}}, MaxRequestBytes: 4096, MaxDurationSeconds: 30}, "service-key", upstream.Client())
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"pentest","messages":[]}`))
	r.Header.Set("Authorization", "Bearer user-token")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"context_length_exceeded"`) || !strings.Contains(w.Body.String(), contextLengthMessage) {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}
