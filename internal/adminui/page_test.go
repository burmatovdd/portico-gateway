package adminui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFormFieldsAndSavedModels(t *testing.T) {
	var out bytes.Buffer
	err := Render(&out, Page{Subject: "admin", CSRF: "token", Revision: 42, Rules: map[string][]string{"z-group": {"unavailable/model", "known/model"}, "a-group": {"known/model"}}, Models: []string{"known/model"}})
	if err != nil {
		t.Fatal(err)
	}
	body := out.String()
	for _, want := range []string{`method="post" action="/admin/models"`, `name="csrf" value="token"`, `name="revision" value="42"`, `value="unavailable/model, known/model"`, `method="post" action="/admin/logout"`, `href="/admin/style.css"`, `list="model-catalog"`, `<option value="known/model">`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if got := strings.Count(body, `name="group"`); got != 5 {
		t.Errorf("group count %d, want 5", got)
	}
	if got := strings.Count(body, `name="models"`); got != 5 {
		t.Errorf("models count %d, want 5", got)
	}
	if got := strings.Count(body, `name="csrf"`); got != 2 {
		t.Errorf("csrf count %d, want 2", got)
	}
	if strings.Index(body, `value="a-group"`) > strings.Index(body, `value="z-group"`) {
		t.Error("rules not sorted")
	}
	if strings.Contains(body, "<script") {
		t.Error("unexpected script")
	}
}

func TestAllUntrustedValuesEscaped(t *testing.T) {
	attack := `"><script>alert(1)</script><img src=x onerror=alert(2)>`
	var out bytes.Buffer
	err := Render(&out, Page{Subject: attack, CSRF: attack, Error: attack, Notice: attack, Rules: map[string][]string{attack: {attack}}, Models: []string{attack}, Audit: []AuditEntry{{At: time.Date(2026, 10, 5, 12, 0, 0, 0, time.FixedZone("UTC+3", 10800)), Subject: attack, Before: map[string][]string{attack: {attack}}, After: map[string][]string{"after": {attack}}}}})
	if err != nil {
		t.Fatal(err)
	}
	body := out.String()
	for _, bad := range []string{"<script>", "<img ", `value=""><script>`} {
		if strings.Contains(body, bad) {
			t.Errorf("unescaped content %q", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "&#34;", `role="alert"`, `role="status"`, "05.10.2026 09:00:00 UTC", "До изменения", "После изменения"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestEmptyPageStillHasThreeRowsAndAccessibleLabels(t *testing.T) {
	var out bytes.Buffer
	if err := Render(&out, Page{}); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if strings.Count(body, `name="group"`) != 3 {
		t.Error("expected three empty rows")
	}
	for _, want := range []string{`lang="ru"`, `for="group-1"`, `id="group-1"`, `for="models-1"`, `id="models-1"`, "Изменения пока не зарегистрированы.", "Список моделей пуст или временно недоступен."} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, `role="alert"`) {
		t.Error("empty error shown")
	}
}

func TestSnapshotSortedAndEmpty(t *testing.T) {
	if got := snapshot(nil); got != "Правила отсутствуют" {
		t.Fatal(got)
	}
	if got := snapshot(map[string][]string{"z": {"b", "a"}, "a": {"x"}}); got != "a → x\nz → b, a" {
		t.Fatal(got)
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }
func TestRenderPropagatesWriteError(t *testing.T) {
	if err := Render(failedWriter{}, Page{}); err == nil {
		t.Fatal("expected writer error")
	}
}
