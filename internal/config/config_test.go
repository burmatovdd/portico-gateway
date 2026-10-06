package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `public_url: https://portico.example
oidc:
  roles_claim: roles
  roles_format: strings
oauth:
  clients:
    - id: trusted-chat
      redirect_uris: [https://chat.example/callback]
  allowed_origins: [https://chat.example]
services:
  scanner:
    base_url: https://scanner.example
    roles: [reader]
    operations:
      read:
        method: GET
        path: /scans
`

func loadText(t *testing.T, text string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}
func TestRemoteMCPConfig(t *testing.T) {
	c, e := loadText(t, validConfig)
	if e != nil {
		t.Fatal(e)
	}
	if c.Listen != ":8080" || c.Session.MaxAgeSeconds != 43200 {
		t.Fatal("defaults missing")
	}
}
func TestRejectsInvalidMCPConfig(t *testing.T) {
	for _, text := range []string{
		strings.Replace(validConfig, "https://portico.example", "http://portico.example", 1),
		strings.Replace(validConfig, "https://portico.example", "https://portico.example/hidden", 1),
		strings.Replace(validConfig, "https://portico.example", "https://user@portico.example", 1),
		strings.Replace(validConfig, "allowed_origins: [https://chat.example]", "allowed_origins: ['*']", 1),
		strings.Replace(validConfig, "allowed_origins: [https://chat.example]", "allowed_origins: [https://chat.example/callback]", 1),
		strings.Replace(validConfig, "scanner:", strings.Repeat("a", 125)+":", 1),
		strings.Replace(validConfig, "- id: trusted-chat", "- id: ''", 1),
		strings.Replace(validConfig, "redirect_uris: [https://chat.example/callback]", "redirect_uris: []", 1),
	} {
		if _, e := loadText(t, text); e == nil {
			t.Fatalf("accepted invalid configuration: %s", text)
		}
	}
}
func TestRejectsCollidingMCPToolNames(t *testing.T) {
	text := strings.Replace(validConfig, "scanner:", "a__b:", 1)
	text = strings.Replace(text, "      read:", "      c:", 1)
	text += `  a:
    base_url: https://scanner.example
    roles: [reader]
    operations:
      b__c:
        method: GET
        path: /scans
`
	if _, e := loadText(t, text); e == nil {
		t.Fatal("accepted ambiguous MCP tool names")
	}
}
