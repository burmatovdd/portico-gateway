package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"portico-gateway/internal/identity"
	"strings"
	"testing"
)

func TestRoutesOnlyRegisteredOperations(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/reports/scan-1" || r.Header.Get("Authorization") != "Bearer upstream-token" {
			t.Error("incorrect upstream request")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	p := &Proxy{Client: srv.Client(), Services: map[string]Service{"reports": {BaseURL: srv.URL, Roles: []string{"reader"}, Operations: map[string]Operation{"get": {Method: "GET", Path: "/reports/{id}", Parameters: map[string]Parameter{"id": {Kind: "id", In: "path", Required: true}}}}}}}
	id := identity.Identity{Roles: []string{"reader"}}
	if _, e := p.Call(context.Background(), id, "upstream-token", "reports", "get", map[string]any{"id": "../admin"}); e == nil {
		t.Fatal("accepted traversal")
	}
	if _, e := p.Call(context.Background(), identity.Identity{}, "upstream-token", "reports", "get", map[string]any{"id": "scan-1"}); e == nil {
		t.Fatal("accepted missing role")
	}
	if _, e := p.Call(context.Background(), id, "upstream-token", "reports", "get", map[string]any{"id": "scan-1", "url": "https://evil.example"}); e == nil {
		t.Fatal("accepted unregistered argument")
	}
	r, e := p.Call(context.Background(), id, "upstream-token", "reports", "get", map[string]any{"id": "scan-1"})
	if e != nil || r.Status != 200 {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatalf("unexpected upstream calls: %d", calls)
	}
}
func TestNeverFollowsRedirectWithToken(t *testing.T) {
	leaked := false
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer srv.Close()
	p := &Proxy{Client: srv.Client(), Services: map[string]Service{"s": {BaseURL: srv.URL, Roles: []string{"r"}, Operations: map[string]Operation{"get": {Method: "GET", Path: "/"}}}}}
	if _, e := p.Call(context.Background(), identity.Identity{Roles: []string{"r"}}, "secret", "s", "get", nil); e == nil {
		t.Fatal("accepted redirect")
	}
	if leaked {
		t.Fatal("token sent to another origin")
	}
}

func TestDownloadReportChecksFormatAndMediaType(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/reports/scan-1/download" || r.URL.Query().Get("format") != "pdf" ||
			r.Header.Get("Accept") != "application/pdf" || r.Header.Get("Authorization") != "Bearer reader" {
			t.Fatal("unexpected report request")
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Write([]byte("%PDF-1.4\n"))
	}))
	defer srv.Close()
	op := Operation{Method: "GET", Path: "/reports/{scan_id}/download", Parameters: map[string]Parameter{
		"scan_id": {Kind: "id", In: "path", Required: true},
		"format":  {Kind: "string", In: "query", Required: true},
	}}
	p := &Proxy{Client: srv.Client(), Services: map[string]Service{"strix": {
		BaseURL: srv.URL, Roles: []string{"reader"}, Operations: map[string]Operation{"downloadReport": op},
	}}}
	id := identity.Identity{Roles: []string{"reader"}}
	if _, err := p.Call(context.Background(), id, "reader", "strix", "downloadReport",
		map[string]any{"scan_id": "scan-1", "format": "evil"}); err == nil || calls != 0 {
		t.Fatal("invalid report format reached upstream")
	}
	result, err := p.Call(context.Background(), id, "reader", "strix", "downloadReport",
		map[string]any{"scan_id": "scan-1", "format": "pdf"})
	if err != nil || result.ContentType != "application/pdf" || string(result.Body) != "%PDF-1.4\n" || calls != 1 {
		t.Fatalf("report response: %+v %v", result, err)
	}
}

func TestSaveReportTranslationAcceptsBoundedMarkdown(t *testing.T) {
	called := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/reports/scan-1/translations/ru" || r.Method != "POST" {
			t.Fatal("unexpected translation request")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["markdown"] != "# Отчёт\nПроверено" {
			t.Fatal("translation body was changed")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	op := Operation{Method: "POST", Path: "/reports/{scan_id}/translations/ru", Parameters: map[string]Parameter{
		"scan_id":         {Kind: "id", In: "path", Required: true},
		"source_revision": {Kind: "string", In: "body", Required: true},
		"markdown":        {Kind: "string", In: "body", Required: true},
	}}
	p := &Proxy{Client: srv.Client(), Services: map[string]Service{"strix": {
		BaseURL: srv.URL, Roles: []string{"reader"}, Operations: map[string]Operation{"saveReportTranslation": op},
	}}}
	args := map[string]any{"scan_id": "scan-1", "source_revision": strings.Repeat("a", 32),
		"markdown": "# Отчёт\nПроверено"}
	if _, err := p.Call(context.Background(), identity.Identity{Roles: []string{"reader"}},
		"reader", "strix", "saveReportTranslation", args); err != nil || !called {
		t.Fatalf("translation did not reach service: %v", err)
	}
	args["markdown"] = strings.Repeat("x", 65537)
	if _, err := p.Call(context.Background(), identity.Identity{Roles: []string{"reader"}},
		"reader", "strix", "saveReportTranslation", args); err == nil {
		t.Fatal("oversized translation accepted")
	}
}
