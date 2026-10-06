package mcpserver

import (
	"encoding/json"
	"portico-gateway/internal/proxy"
	"strings"
	"testing"
)

func TestReportFileIsBinaryResourceOutsideModelText(t *testing.T) {
	id := "scan-12345678901234567890123456789012"
	result := reportFile(proxy.Result{Status: 200, ContentType: "application/pdf", Body: []byte("%PDF-1.4\nreport")},
		map[string]any{"scan_id": id, "format": "pdf"})
	if result.IsError || len(result.Content) != 2 {
		t.Fatal("report was not attached")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"type":"resource"`) ||
		!strings.Contains(string(encoded), `"mimeType":"application/pdf"`) ||
		!strings.Contains(string(encoded), `"blob":"JVBERi0`) {
		t.Fatalf("invalid MCP resource: %s", encoded)
	}
}

func TestReportFileRejectsInvalidPDF(t *testing.T) {
	result := reportFile(proxy.Result{Status: 200, ContentType: "application/pdf", Body: []byte("not a pdf")},
		map[string]any{"scan_id": "scan-12345678901234567890123456789012", "format": "pdf"})
	if !result.IsError {
		t.Fatal("invalid PDF accepted")
	}
}
