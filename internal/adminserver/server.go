// Package adminserver exposes authenticated, versioned access policy management.
package adminserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"portico-gateway/internal/adminauth"
	"portico-gateway/internal/adminui"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/modelpolicy"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Auth interface {
	Authenticate(*http.Request) (identity.Identity, string, error)
	CheckCSRF(*http.Request) bool
	Login(http.ResponseWriter, *http.Request)
	Callback(http.ResponseWriter, *http.Request)
	Logout(http.ResponseWriter, *http.Request)
}
type Policies interface {
	Read(context.Context) (modelpolicy.Snapshot, error)
	Update(context.Context, int64, string, map[string][]string) error
	History(context.Context) ([]modelpolicy.Audit, error)
}
type Server struct {
	Auth                   Auth
	Policies               Policies
	CatalogURL, CatalogKey string
	Client                 *http.Client
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/login", s.Auth.Login)
	mux.HandleFunc("GET /admin/callback", s.Auth.Callback)
	mux.HandleFunc("POST /admin/logout", s.Auth.Logout)
	mux.HandleFunc("GET /admin/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		io.WriteString(w, adminui.CSS)
	})
	mux.HandleFunc("GET /admin/{$}", s.page)
	mux.HandleFunc("POST /admin/models", s.save)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (identity.Identity, string, bool) {
	id, csrf, err := s.Auth.Authenticate(r)
	if errors.Is(err, adminauth.ErrUnauthorized) {
		if r.Method == "GET" {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		} else {
			http.Error(w, "Сеанс завершён. Войдите повторно через /admin/.", 401)
		}
		return id, "", false
	}
	if errors.Is(err, adminauth.ErrForbidden) {
		http.Error(w, "Доступ разрешён только администраторам Portico.", 403)
		return id, "", false
	}
	if err != nil {
		http.Error(w, "Не удалось проверить сеанс. Повторите попытку позднее.", 503)
		return id, "", false
	}
	return id, csrf, true
}
func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	id, csrf, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	s.render(w, r, id, csrf, 200, "")
}
func (s *Server) render(w http.ResponseWriter, r *http.Request, id identity.Identity, csrf string, status int, message string) {
	p, err := s.Policies.Read(r.Context())
	if err != nil {
		http.Error(w, "Хранилище правил доступа недоступно или ещё не инициализировано.", 503)
		return
	}
	audit, err := s.Policies.History(r.Context())
	if err != nil {
		http.Error(w, "Журнал изменений недоступен. Повторите попытку позднее.", 503)
		return
	}
	models, catErr := s.catalog(r.Context())
	data := adminui.Page{Subject: id.Subject, CSRF: csrf, Revision: p.Revision, Rules: p.Rules, Models: models, Error: message}
	if catErr != nil {
		data.Notice = "Каталог моделей временно недоступен. Существующие правила сохранены. Добавление новых моделей недоступно до восстановления каталога."
	}
	if r.URL.Query().Get("saved") == "1" {
		data.Notice = "Правила сохранены. Изменения применяются к новым запросам."
	}
	for _, a := range audit {
		data.Audit = append(data.Audit, adminui.AuditEntry{At: a.At, Subject: a.Subject, Before: a.Before, After: a.After})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = adminui.Render(w, data)
}
func parseRules(form url.Values) (map[string][]string, error) {
	groups, models := form["group"], form["models"]
	if len(groups) != len(models) || len(groups) > 503 {
		return nil, modelpolicy.ErrInvalid
	}
	rules := map[string][]string{}
	for i, g := range groups {
		g = strings.TrimSpace(g)
		m := strings.TrimSpace(models[i])
		if g == "" && m == "" {
			continue
		}
		if _, exists := rules[g]; exists {
			return nil, modelpolicy.ErrInvalid
		}
		var names []string
		for _, n := range strings.Split(m, ",") {
			names = append(names, strings.TrimSpace(n))
		}
		sort.Strings(names)
		rules[g] = names
	}
	return rules, modelpolicy.Validate(rules)
}
func (s *Server) save(w http.ResponseWriter, r *http.Request) {
	id, csrf, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if r.ParseForm() != nil || !s.Auth.CheckCSRF(r) {
		http.Error(w, "Не удалось подтвердить запрос. Обновите страницу и повторите попытку.", 403)
		return
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if err != nil {
		s.render(w, r, id, csrf, 400, "Некорректная версия правил. Обновите страницу.")
		return
	}
	rules, err := parseRules(r.PostForm)
	if err != nil {
		s.render(w, r, id, csrf, 400, "Проверьте группы и модели: значения должны быть заполнены, без повторов и подстановочных знаков.")
		return
	}
	previous, err := s.Policies.Read(r.Context())
	if err != nil {
		http.Error(w, "Хранилище правил недоступно.", 503)
		return
	}
	// Existing exact grants may be retained during a catalog outage; new grants
	// require the model to be visible through Portico's scoped upstream key.
	models, catErr := s.catalog(r.Context())
	catalog := map[string]bool{}
	for _, m := range models {
		catalog[m] = true
	}
	for g, names := range rules {
		for _, m := range names {
			existing := false
			for _, old := range previous.Rules[g] {
				if old == m {
					existing = true
				}
			}
			if !existing && !catalog[m] {
				message := "Модель отсутствует в каталоге, доступном ключу Portico. Сначала предоставьте доступ в LiteLLM."
				if catErr != nil {
					message = "Каталог моделей недоступен. Добавить новые разрешения сейчас невозможно."
				}
				s.render(w, r, id, csrf, 400, message)
				return
			}
		}
	}
	err = s.Policies.Update(r.Context(), revision, id.Issuer+" | "+id.Subject, rules)
	if errors.Is(err, modelpolicy.ErrConflict) {
		s.render(w, r, id, csrf, 409, "Правила изменены другим администратором. Проверьте актуальные значения и повторите изменение.")
		return
	}
	if err != nil {
		http.Error(w, "Не удалось сохранить правила. Изменения не подтверждены.", 503)
		return
	}
	http.Redirect(w, r, "/admin/?saved=1", http.StatusSeeOther)
}
func (s *Server) catalog(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(s.CatalogURL, "/")+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.CatalogKey)
	c := *s.Client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("catalog unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("invalid catalog")
	}
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err = json.Unmarshal(data, &body); err != nil {
		return nil, err
	}
	out := []string{}
	seen := map[string]bool{}
	for _, m := range body.Data {
		if m.ID != "" && !seen[m.ID] {
			out = append(out, m.ID)
			seen[m.ID] = true
		}
	}
	sort.Strings(out)
	return out, nil
}
