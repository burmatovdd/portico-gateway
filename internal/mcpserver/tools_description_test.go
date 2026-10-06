package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/proxy"
)

func TestConfiguredDescriptionReachesToolsList(t *testing.T) {
	var configured proxy.Operation
	if err := yaml.Unmarshal([]byte("method: POST\npath: /plugin/start\ndescription: >-\n  Start asynchronously; report scan_id and finish the turn.\n"), &configured); err != nil {
		t.Fatal(err)
	}
	services := map[string]proxy.Service{"strix": {Roles: []string{"reader"}, Operations: map[string]proxy.Operation{
		"startScan":   configured,
		"getStatus":   {Method: "GET", Path: "/scans", Description: "  "},
		"listReports": {Method: "GET", Path: "/reports"},
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := server(principal{identity: identity.Identity{Roles: []string{"reader"}}}, nil, &proxy.Proxy{Services: services})
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "description-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	listed, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tool := range listed.Tools {
		got[tool.Name] = tool.Description
	}
	for name, want := range map[string]string{
		"strix__startScan":   "Start asynchronously; report scan_id and finish the turn.",
		"strix__getStatus":   "strix operation getStatus",
		"strix__listReports": "strix operation listReports",
	} {
		if got[name] != want {
			t.Errorf("%s description=%q, want %q", name, got[name], want)
		}
	}
}
