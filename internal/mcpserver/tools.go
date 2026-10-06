package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"portico-gateway/internal/proxy"
	"portico-gateway/internal/session"
)

func server(p principal, sessions *session.Manager, upstream *proxy.Proxy, portalBase ...string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "Portico", Version: "1.0.0"}, nil)
	// Ambiguous concatenations and names exceeding MCP's length limit fail closed.
	counts := map[string]int{}
	for service, v := range upstream.Services {
		for operation := range v.Operations {
			counts[service+"__"+operation]++
		}
	}
	for service, v := range upstream.Services {
		if !hasRole(p.identity.Roles, v.Roles) {
			continue
		}
		for operation, op := range v.Operations {
			name := service + "__" + operation
			if len(name) > 128 || counts[name] != 1 {
				continue
			}
			description := strings.TrimSpace(op.Description)
			if description == "" {
				description = fmt.Sprintf("%s operation %s", service, operation)
			}
			s.AddTool(&mcp.Tool{Name: name, Description: description, InputSchema: inputSchema(op)}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args, err := arguments(r.Params.Arguments)
				if err != nil {
					return failure("invalid operation arguments"), nil
				}
				id, token, err := sessions.Access(ctx, p.credential)
				if err != nil || id.Issuer != p.identity.Issuer || id.Subject != p.identity.Subject {
					return failure("session is not active; authenticate again"), nil
				}
				result, err := upstream.Call(ctx, id, token, service, operation, args)
				if err != nil {
					if errors.Is(err, proxy.ErrArguments) {
						return failure("invalid operation arguments"), nil
					}
					if errors.Is(err, proxy.ErrForbidden) {
						return failure("operation is not permitted"), nil
					}
					return failure("upstream unavailable"), nil
				}
				if len(portalBase) > 0 && portalBase[0] != "" && (operation == "startScan" || operation == "getStatus" || operation == "retestFinding") && result.Status >= 200 && result.Status < 300 {
					var data map[string]any
					if json.Unmarshal(result.Body, &data) == nil {
						if scanID, ok := data["scan_id"].(string); ok && validScanID(scanID) {
							data["status_page_url"] = strings.TrimRight(portalBase[0], "/") + "/portal/scans/" + scanID
							result.Body, _ = json.Marshal(data)
						}
					}
				}
				// Upstream content is tool data, never protocol instructions or credentials.
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result.Body)}}, IsError: result.Status < 200 || result.Status >= 300}, nil
			})
		}
	}
	s.AddTool(&mcp.Tool{Name: "portico_logout", Description: "Revoke your current Portico session. Already accepted upstream scans are not canceled.", InputSchema: inputSchema(proxy.Operation{})}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := arguments(r.Params.Arguments)
		if err != nil || len(args) != 0 {
			return failure("logout accepts no arguments"), nil
		}
		if err = sessions.Logout(ctx, p.credential); err != nil {
			return failure("logout failed; session revocation was not confirmed"), nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Your Portico session has been revoked. Already accepted upstream scans are not canceled."}}}, nil
	})
	return s
}
func hasRole(roles, allowed []string) bool {
	for _, a := range allowed {
		for _, r := range roles {
			if a == r {
				return true
			}
		}
	}
	return false
}
func failure(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}
func arguments(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil || args == nil {
		return nil, proxy.ErrArguments
	}
	return args, nil
}
func inputSchema(op proxy.Operation) map[string]any {
	properties := map[string]any{}
	required := []string{}
	for name, p := range op.Parameters {
		schema := map[string]any{"type": "string", "maxLength": 4096, "pattern": `^[^\r\n\u0000]*$`}
		switch p.Kind {
		case "integer":
			schema = map[string]any{"type": "integer", "minimum": 0, "maximum": 10000000}
		case "id":
			schema = map[string]any{"type": "string", "pattern": `^[A-Za-z0-9_-]{1,128}$`}
		case "url":
			schema["format"] = "uri"
		}
		properties[name] = schema
		if p.Required {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}

func validScanID(id string) bool {
	if len(id) != 37 || !strings.HasPrefix(id, "scan-") {
		return false
	}
	for _, c := range id[5:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
