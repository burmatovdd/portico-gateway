package modelaccess

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var allowedFields = map[string]bool{}

func init() {
	for _, k := range []string{"model", "messages", "stream", "stream_options", "tools", "tool_choice", "parallel_tool_calls", "temperature", "top_p", "n", "stop", "max_tokens", "max_completion_tokens", "presence_penalty", "frequency_penalty", "logit_bias", "logprobs", "top_logprobs", "seed", "response_format", "reasoning_effort", "user"} {
		allowedFields[k] = true
	}
}

// Walk every object before unmarshalling so duplicate keys cannot bypass validation.
func walk(d *json.Decoder) error { return walkDepth(d, 0) }
func walkDepth(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit exceeded")
	}
	tok, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return errors.New("duplicate JSON field")
			}
			seen[s] = true
			if e = walkDepth(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = walkDepth(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, e = d.Token()
	return e
}
func validateRequest(body []byte) (string, bool, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if e := walk(d); e != nil {
		return "", false, e
	}
	if _, e := d.Token(); e != io.EOF {
		return "", false, errors.New("trailing JSON")
	}
	var v map[string]json.RawMessage
	if e := json.Unmarshal(body, &v); e != nil {
		return "", false, e
	}
	for k := range v {
		if !allowedFields[k] {
			return "", false, errors.New("unsupported field")
		}
	}
	var model string
	var stream bool
	if json.Unmarshal(v["model"], &model) != nil || model == "" {
		return "", false, errors.New("model required")
	}
	if raw, ok := v["stream"]; ok {
		if string(raw) == "null" || json.Unmarshal(raw, &stream) != nil {
			return "", false, errors.New("invalid stream")
		}
	}
	var messages []json.RawMessage
	if json.Unmarshal(v["messages"], &messages) != nil || messages == nil {
		return "", false, errors.New("messages required")
	}
	return model, stream, nil
}
