// Package webui renders the public browser interface. Protocol responses remain JSON.
package webui

import (
	"embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed page.html assets/*
var files embed.FS
var page = template.Must(template.ParseFS(files, "page.html"))

type Page struct {
	Title, Body, Note, Client, Transaction, CSRF string
	ReturnURL                                    string
	HomeLink                                     bool
}

func Render(w http.ResponseWriter, status int, data Page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = page.Execute(w, data)
}
func Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		Error(w, 404, "not_found")
		return
	}
	Render(w, 200, Page{Title: "Шлюз доступа к инструментам", Body: "Для начала работы откройте подключение Portico Gateway в используемом приложении.", Note: "Информацию о подключении предоставляет администратор сервиса."})
}
func Assets() http.Handler {
	// FileServer serves only the embedded asset directory; templates are not exposed.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/assets/portico.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case "/assets/arch.png":
			w.Header().Set("Content-Type", "image/png")
		default:
			http.NotFound(w, r)
			return
		}
		data, err := files.ReadFile(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	})
}
func Consent(w http.ResponseWriter, client, transaction, csrf, returnURL string) {
	Render(w, 200, Page{Title: "Подключение к инструментам", Body: "Приложение запрашивает доступ к инструментам, разрешённым вашей учётной записи.", Client: client, Transaction: transaction, CSRF: csrf, ReturnURL: returnURL})
}
func Error(w http.ResponseWriter, status int, code string) {
	ErrorWithReturn(w, status, code, "")
}

// ErrorWithReturn accepts only a return URL validated by the OAuth bridge.
func ErrorWithReturn(w http.ResponseWriter, status int, code, returnURL string) {
	p := Page{Title: "Ошибка запроса", Body: "Запрос на подключение недействителен. Выполните подключение повторно из исходного приложения.", Note: "При повторении ошибки обратитесь к администратору сервиса.", HomeLink: true}
	switch {
	case status == 404:
		p.Title = "Страница не найдена"
		p.Body = "Запрашиваемая страница отсутствует. Проверьте адрес или перейдите на главную страницу."
		p.Note = ""
	case status == 429:
		p.Title = "Обработка запроса приостановлена"
		p.Body = "Сервис временно не принимает новые запросы на подключение. Повторите попытку позднее."
	case status >= 500:
		p.Title = "Сервис временно недоступен"
		p.Body = "Запрос не может быть обработан. Повторите подключение позднее."
	case status == 403:
		p.Title = "Ошибка проверки запроса"
		p.Body = "Не удалось подтвердить запрос на подключение. Выполните подключение повторно из исходного приложения."
	case code == "access_denied":
		p.Title = "Ошибка авторизации"
		p.Body = "Авторизация не завершена. Выполните вход повторно из исходного приложения."
	}
	p.ReturnURL = returnURL
	Render(w, status, p)
}
