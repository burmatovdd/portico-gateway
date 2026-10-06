package modelaccess

import (
	"encoding/json"
	"errors"
)

// ContextBudget applies a planning heuristic, not a tokenizer measurement.
// ReserveTokens must be positive when WindowTokens enables the budget.
type ContextBudget struct {
	WindowTokens  int `yaml:"window_tokens"`
	ReserveTokens int `yaml:"reserve_tokens"`
}

var (
	ErrContextTooLarge = errors.New("context cannot fit without removing current instructions")
	ErrContextInvalid  = errors.New("invalid context request or budget")
)

// PrepareContext removes only whole oldest user turns. Serialized JSON bytes / 3
// (rounded up), plus 32 per message and 256 framing tokens, are a planning
// heuristic including tool schemas, not a tokenizer measurement or guaranteed
// fit. An irreducible request is sent intact for actual backend validation;
// force requires at least one removable turn. Image/audio content is rejected
// because its cost cannot be estimated from URL bytes. System/developer messages
// and the latest user turn are never removed.
func PrepareContext(body []byte, budget ContextBudget, force bool) ([]byte, int, error) {
	if budget.WindowTokens == 0 {
		return body, 0, nil
	}
	if budget.WindowTokens < 0 || budget.ReserveTokens <= 0 || budget.ReserveTokens >= budget.WindowTokens {
		return nil, 0, ErrContextInvalid
	}
	if _, _, err := validateRequest(body); err != nil {
		return nil, 0, ErrContextInvalid
	}
	var request map[string]json.RawMessage
	if json.Unmarshal(body, &request) != nil {
		return nil, 0, ErrContextInvalid
	}
	var messages []json.RawMessage
	if json.Unmarshal(request["messages"], &messages) != nil || messages == nil {
		return nil, 0, ErrContextInvalid
	}
	if raw, ok := request["tools"]; ok {
		var tools []map[string]json.RawMessage
		if json.Unmarshal(raw, &tools) != nil || tools == nil {
			return nil, 0, ErrContextInvalid
		}
		for _, tool := range tools {
			var kind string
			var function map[string]json.RawMessage
			var name string
			if json.Unmarshal(tool["type"], &kind) != nil || kind != "function" || json.Unmarshal(tool["function"], &function) != nil ||
				json.Unmarshal(function["name"], &name) != nil || name == "" {
				return nil, 0, ErrContextInvalid
			}
		}
	}
	reserve := budget.ReserveTokens
	hasOutputLimit := false
	for _, key := range []string{"max_tokens", "max_completion_tokens"} {
		if raw, ok := request[key]; ok {
			hasOutputLimit = true
			var value int
			if json.Unmarshal(raw, &value) != nil || value <= 0 {
				return nil, 0, ErrContextInvalid
			}
			if value >= budget.WindowTokens {
				return nil, 0, ErrContextTooLarge
			}
			if value > reserve {
				reserve = value
			}
		}
	}
	if !hasOutputLimit {
		request["max_tokens"], _ = json.Marshal(budget.ReserveTokens)
	}
	roles := make([]string, len(messages))
	userStarts := []int{}
	pending := map[string]bool{}
	seenCalls := map[string]bool{}
	for i, raw := range messages {
		var message map[string]json.RawMessage
		if json.Unmarshal(raw, &message) != nil || message == nil || json.Unmarshal(message["role"], &roles[i]) != nil {
			return nil, 0, ErrContextInvalid
		}
		role := roles[i]
		if role != "system" && role != "developer" && role != "user" && role != "assistant" && role != "tool" {
			return nil, 0, ErrContextInvalid
		}
		if role == "user" {
			if len(pending) != 0 {
				return nil, 0, ErrContextInvalid
			}
			userStarts = append(userStarts, i)
		}
		if raw, ok := message["content"]; ok && string(raw) != "null" {
			var text string
			if json.Unmarshal(raw, &text) != nil {
				var parts []map[string]json.RawMessage
				if json.Unmarshal(raw, &parts) != nil || parts == nil {
					return nil, 0, ErrContextInvalid
				}
				for _, part := range parts {
					var kind, text string
					if json.Unmarshal(part["type"], &kind) != nil || kind != "text" || json.Unmarshal(part["text"], &text) != nil {
						return nil, 0, ErrContextInvalid
					}
				}
			}
		} else if role != "assistant" {
			return nil, 0, ErrContextInvalid
		}
		if raw, ok := message["function_call"]; ok && string(raw) != "null" {
			return nil, 0, ErrContextInvalid
		}
		if role == "tool" {
			var id string
			if json.Unmarshal(message["tool_call_id"], &id) != nil || !pending[id] {
				return nil, 0, ErrContextInvalid
			}
			delete(pending, id)
		} else if _, ok := message["tool_call_id"]; ok {
			return nil, 0, ErrContextInvalid
		}
		if raw, ok := message["tool_calls"]; ok && string(raw) != "null" {
			if role != "assistant" || len(pending) != 0 {
				return nil, 0, ErrContextInvalid
			}
			var calls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			}
			if json.Unmarshal(raw, &calls) != nil || calls == nil {
				return nil, 0, ErrContextInvalid
			}
			for _, call := range calls {
				if call.ID == "" || seenCalls[call.ID] || call.Type != "function" || call.Function.Name == "" {
					return nil, 0, ErrContextInvalid
				}
				pending[call.ID], seenCalls[call.ID] = true, true
			}
		} else if role == "assistant" && len(pending) != 0 {
			return nil, 0, ErrContextInvalid
		}
	}
	if len(pending) != 0 {
		return nil, 0, ErrContextInvalid
	}
	// Marshal once for the initial estimate. Per-message lengths use the same
	// encoder (including HTML escaping); removing a message removes its comma
	// too because at least the latest user message always remains.
	encodedLengths := make([]int64, len(messages))
	for i, message := range messages {
		encoded, err := json.Marshal(message)
		if err != nil {
			return nil, 0, ErrContextInvalid
		}
		encodedLengths[i] = int64(len(encoded))
	}
	request["messages"], _ = json.Marshal(messages)
	prepared, err := json.Marshal(request)
	if err != nil {
		return nil, 0, ErrContextInvalid
	}
	remainingBytes, remainingMessages := int64(len(prepared)), int64(len(messages))
	removed := make([]bool, len(messages))
	dropped := 0
	for {
		estimate := (remainingBytes+2)/3 + remainingMessages*32 + 256
		if estimate <= int64(budget.WindowTokens)-int64(reserve) && (!force || dropped > 0) {
			break
		}
		if dropped+1 >= len(userStarts) {
			if force && dropped == 0 {
				return nil, 0, ErrContextTooLarge
			}
			break // The backend decides whether an irreducible request fits.
		}
		for i := userStarts[dropped]; i < userStarts[dropped+1]; i++ {
			if roles[i] != "system" && roles[i] != "developer" {
				removed[i] = true
				remainingBytes -= encodedLengths[i] + 1
				remainingMessages--
			}
		}
		dropped++
	}
	if dropped == 0 {
		return prepared, 0, nil
	}
	kept := make([]json.RawMessage, 0, remainingMessages)
	for i, message := range messages {
		if !removed[i] {
			kept = append(kept, message)
		}
	}
	request["messages"], _ = json.Marshal(kept)
	prepared, err = json.Marshal(request)
	if err != nil {
		return nil, 0, ErrContextInvalid
	}
	return prepared, dropped, nil
}
