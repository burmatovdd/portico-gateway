// Package mcpserver exposes the approved Portico operations over remote MCP.
package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/proxy"
	"portico-gateway/internal/session"
)

type Authorizer interface {
	AuthorizeMCP(ctx context.Context, token string) (sessionCredential string, expires time.Time, err error)
}
type principal struct {
	credential string
	identity   identity.Identity
}

// Handler is stateless: the database-backed Portico session, not an MCP transport
// session, is the authority for every request, including initialization and lists.
func Handler(publicURL string, allowedOrigins []string, authz Authorizer, sessions *session.Manager, upstream *proxy.Proxy, portalEnabled ...bool) http.Handler {
	verify := func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		c, expires, err := authz.AuthorizeMCP(ctx, token)
		if err != nil || !time.Now().Before(expires) {
			return nil, auth.ErrInvalidToken
		}
		id, _, err := sessions.Access(ctx, c)
		if err != nil {
			return nil, auth.ErrInvalidToken
		}
		binding, _ := json.Marshal([]string{id.Issuer, id.Subject, session.Hash(c)})
		return &auth.TokenInfo{Scopes: []string{"mcp"}, Expiration: expires, UserID: session.Hash(string(binding)), Extra: map[string]any{"principal": principal{c, id}}}, nil
	}
	transport := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		p := auth.TokenInfoFromContext(r.Context()).Extra["principal"].(principal)
		if len(portalEnabled) > 0 && portalEnabled[0] {
			return server(p, sessions, upstream, publicURL)
		}
		return server(p, sessions, upstream)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 64 << 10})
	authenticated := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{ResourceMetadataURL: strings.TrimRight(publicURL, "/") + "/.well-known/oauth-protected-resource/mcp", Scopes: []string{"mcp"}})(transport)
	bounded := http.TimeoutHandler(authenticated, 35*time.Second, "request timed out")
	origins := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o != "" && o != "null" && o != "*" {
			origins[o] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		origin := r.Header.Get("Origin")
		if len(r.Header.Values("Origin")) > 1 || (origin != "" && !origins[origin]) {
			http.Error(w, "origin is not allowed", http.StatusForbidden)
			return
		}
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate, MCP-Protocol-Version")
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version, Mcp-Session-Id, Last-Event-ID")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// The deadline also bounds slow body reads; TimeoutHandler bounds processing.
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(10 * time.Second))
		defer rc.SetReadDeadline(time.Time{})
		bounded.ServeHTTP(w, r)
	})
}
