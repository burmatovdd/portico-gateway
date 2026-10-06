package oauthbridge

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicPages(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		path   string
		status int
		title  string
	}{
		{"/", 200, "Шлюз доступа к инструментам"},
		{"/missing", 404, "Страница не найдена"},
		{"/oauth/authorize?client_id=unknown", 400, "Ошибка запроса"},
		{"/oauth/callback?error=access_denied", 400, "Ошибка запроса"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", tc.path, nil)
			r.Header.Set("Accept", "text/html")
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.title) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
				t.Fatal("expected HTML")
			}
			if strings.Contains(w.Body.String(), "unknown") {
				t.Fatal("untrusted query reflected")
			}
		})
	}
}

func TestMachineErrorsStayJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/oauth/authorize?client_id=unknown", nil)
	(&Server{}).Handler().ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid_request"`) {
		t.Fatal(w.Body.String())
	}
}
