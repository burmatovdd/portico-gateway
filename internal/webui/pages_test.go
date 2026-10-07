package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsentEscapesClientAndPreservesForm(t *testing.T) {
	w := httptest.NewRecorder()
	Consent(w, `<script>alert(1)</script>`, "transaction", "csrf", "https://chat.example/")
	b := w.Body.String()
	if strings.Contains(b, "<script>") || !strings.Contains(b, `action="/oauth/login"`) || !strings.Contains(b, `name="csrf" value="csrf"`) || !strings.Contains(b, `href="https://chat.example/"`) || !strings.Contains(b, "Вернуться в приложение") {
		t.Fatal(b)
	}
}
func TestErrorPages(t *testing.T) {
	for _, status := range []int{400, 403, 404, 429, 503} {
		w := httptest.NewRecorder()
		Error(w, status, "access_denied")
		if w.Code != status || !strings.Contains(w.Body.String(), `href="/"`) || strings.Contains(w.Body.String(), "<script") {
			t.Fatal(w.Body.String())
		}
	}
}
func TestAssetsDoNotExposeTemplates(t *testing.T) {
	w := httptest.NewRecorder()
	Assets().ServeHTTP(w, httptest.NewRequest("GET", "/assets/../page.html", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
