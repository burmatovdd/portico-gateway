package modelaccess

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func contextRequest(t *testing.T, messages []map[string]any, extra map[string]any) []byte {
	t.Helper()
	request := map[string]any{"model": "pentest", "messages": messages}
	for key, value := range extra {
		request[key] = value
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func contextMessage(role, content string) map[string]any {
	return map[string]any{"role": role, "content": content}
}
func decodeContext(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPrepareContextDisabledIsExactNoop(t *testing.T) {
	body := []byte("invalid but disabled")
	got, dropped, err := PrepareContext(body, ContextBudget{}, true)
	if err != nil || dropped != 0 || string(got) != string(body) {
		t.Fatalf("%q %d %v", got, dropped, err)
	}
}

func TestPrepareContextPreservesInstructionsAndLatestToolTurn(t *testing.T) {
	call := func(id string) map[string]any {
		return map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{"id": id, "type": "function", "function": map[string]any{"name": "read", "arguments": "{}"}}}}
	}
	result := func(id string) map[string]any {
		return map[string]any{"role": "tool", "tool_call_id": id, "content": "unchanged result"}
	}
	system := contextMessage("system", "keep system")
	developer := contextMessage("developer", "keep developer inside old turn")
	latest := contextMessage("user", "latest instruction")
	messages := []map[string]any{system, contextMessage("user", "old"), call("old-call"), developer, result("old-call"), latest, call("new-call"), result("new-call")}
	tools := []any{map[string]any{"type": "function", "function": map[string]any{"name": "read", "description": "unchanged schema", "parameters": map[string]any{"type": "object"}}}}
	body := contextRequest(t, messages, map[string]any{"tools": tools})
	prepared, dropped, err := PrepareContext(body, ContextBudget{WindowTokens: 10000, ReserveTokens: 500}, true)
	if err != nil || dropped != 1 {
		t.Fatalf("dropped=%d err=%v", dropped, err)
	}
	expected := contextRequest(t, []map[string]any{system, developer, latest, call("new-call"), result("new-call")}, map[string]any{"tools": tools, "max_tokens": 500})
	if !reflect.DeepEqual(decodeContext(t, prepared), decodeContext(t, expected)) {
		t.Fatalf("unexpected rewrite: %s", prepared)
	}
	if len(prepared) >= len(body) {
		t.Fatal("forced compaction did not reduce request")
	}
}

func TestPrepareContextEstimateCompactsOldestWholeTurns(t *testing.T) {
	messages := []map[string]any{contextMessage("user", strings.Repeat("old", 3000)), contextMessage("assistant", "old reply"), contextMessage("user", "newer"), contextMessage("assistant", "newer reply"), contextMessage("user", "current")}
	body := contextRequest(t, messages, nil)
	prepared, dropped, err := PrepareContext(body, ContextBudget{WindowTokens: 1200, ReserveTokens: 200}, false)
	if err != nil || dropped != 1 {
		t.Fatalf("dropped=%d err=%v", dropped, err)
	}
	got := decodeContext(t, prepared)["messages"].([]any)
	if len(got) != 3 || got[0].(map[string]any)["content"] != "newer" {
		t.Fatalf("wrong turn removed: %s", prepared)
	}
}

func TestPrepareContextIrreducibleHeuristicDefersToBackend(t *testing.T) {
	for _, tools := range []bool{false, true} {
		messages := []map[string]any{contextMessage("user", strings.Repeat("current", 1000))}
		extra := map[string]any{}
		if tools {
			extra["tools"] = []any{map[string]any{"type": "function", "function": map[string]any{"name": "read", "description": strings.Repeat("schema", 1000)}}}
		}
		body := contextRequest(t, messages, extra)
		prepared, dropped, err := PrepareContext(body, ContextBudget{WindowTokens: 1000, ReserveTokens: 100}, false)
		if err != nil || dropped != 0 {
			t.Fatalf("dropped=%d err=%v", dropped, err)
		}
		got := decodeContext(t, prepared)
		delete(got, "max_tokens")
		if !reflect.DeepEqual(got, decodeContext(t, body)) {
			t.Fatal("irreducible content changed")
		}
		if _, _, err := PrepareContext(body, ContextBudget{WindowTokens: 1000, ReserveTokens: 100}, true); !errors.Is(err, ErrContextTooLarge) {
			t.Fatalf("force err=%v", err)
		}
	}
}

func TestPrepareContextOutputReservation(t *testing.T) {
	body := contextRequest(t, []map[string]any{contextMessage("user", strings.Repeat("x", 600)), contextMessage("user", "latest")}, map[string]any{"max_completion_tokens": 700})
	prepared, dropped, err := PrepareContext(body, ContextBudget{WindowTokens: 1200, ReserveTokens: 100}, false)
	if err != nil || dropped != 1 {
		t.Fatalf("dropped=%d err=%v", dropped, err)
	}
	got := decodeContext(t, prepared)
	if got["max_completion_tokens"] != float64(700) {
		t.Fatal("requested limit changed")
	}
	if _, ok := got["max_tokens"]; ok {
		t.Fatal("second output limit added")
	}
	for _, limit := range []any{0, -1, 1.5, "100", nil, 1200, 1300} {
		body := contextRequest(t, []map[string]any{contextMessage("user", "latest")}, map[string]any{"max_tokens": limit})
		_, _, err := PrepareContext(body, ContextBudget{WindowTokens: 1200, ReserveTokens: 100}, false)
		if err == nil {
			t.Fatalf("accepted invalid limit %v", limit)
		}
	}
}

func TestPrepareContextRejectsUnsafeToolBoundaries(t *testing.T) {
	call := map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "call", "type": "function", "function": map[string]any{"name": "read", "arguments": "{}"}}}}
	result := map[string]any{"role": "tool", "tool_call_id": "call", "content": "result"}
	for name, messages := range map[string][]map[string]any{
		"unanswered":              {contextMessage("user", "old"), call},
		"cross user boundary":     {contextMessage("user", "old"), call, contextMessage("user", "latest"), result},
		"orphan result":           {contextMessage("user", "latest"), result},
		"duplicate result":        {contextMessage("user", "latest"), call, result, result},
		"assistant before result": {contextMessage("user", "latest"), call, contextMessage("assistant", "bad"), result},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := PrepareContext(contextRequest(t, messages, nil), ContextBudget{WindowTokens: 10000, ReserveTokens: 100}, true)
			if !errors.Is(err, ErrContextInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestPrepareContextInvalidInputIsSanitized(t *testing.T) {
	for _, body := range []string{`{"model":"x","messages":null}`, `{"model":"x","messages":[{"role":"bad","content":"secret"}]}`, `{"model":"x","messages":[],"tools":{}}`, `{"model":"x","messages":[],"model":"y"}`, `secret invalid JSON`} {
		_, _, err := PrepareContext([]byte(body), ContextBudget{WindowTokens: 10000, ReserveTokens: 100}, false)
		if err != ErrContextInvalid {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestPrepareContextLargeHistoryPreservesPinnedMessages(t *testing.T) {
	messages := make([]map[string]any, 0, 10002)
	messages = append(messages, contextMessage("system", "pinned <system>"))
	for i := 0; i < 10000; i++ {
		messages = append(messages, contextMessage("user", "<>&\u2028 historical turn"))
	}
	messages = append(messages, contextMessage("user", "current"))
	prepared, dropped, err := PrepareContext(contextRequest(t, messages, nil), ContextBudget{WindowTokens: 1024, ReserveTokens: 100}, false)
	if err != nil || dropped < 9900 {
		t.Fatalf("dropped=%d err=%v", dropped, err)
	}
	got := decodeContext(t, prepared)["messages"].([]any)
	if got[0].(map[string]any)["content"] != "pinned <system>" || got[len(got)-1].(map[string]any)["content"] != "current" {
		t.Fatal("pinned messages changed")
	}
	estimate := (len(prepared)+2)/3 + len(got)*32 + 256
	if estimate > 924 {
		t.Fatalf("estimated budget exceeded: %d", estimate)
	}
}
