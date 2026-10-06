// Package adminui renders the administrative model access form without scripts.
package adminui

import (
	"html/template"
	"io"
	"sort"
	"strings"
	"time"
)

// Page contains display data only. The caller authenticates, authorizes and sets
// response security headers before rendering; all strings remain untrusted text.
type Page struct {
	Subject, CSRF, Error, Notice string
	Revision                     int64
	Rules                        map[string][]string
	Models                       []string
	Audit                        []AuditEntry
}

type AuditEntry struct {
	At            time.Time
	Subject       string
	Before, After map[string][]string
}

type ruleRow struct {
	Number        int
	Group, Models string
}
type view struct {
	Page
	Rows []ruleRow
}

// Render writes escaped HTML. Saved model IDs are never filtered by the catalog.
func Render(w io.Writer, data Page) error {
	groups := make([]string, 0, len(data.Rules))
	for group := range data.Rules {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	rows := make([]ruleRow, 0, len(groups)+3)
	for _, group := range groups {
		rows = append(rows, ruleRow{len(rows) + 1, group, strings.Join(data.Rules[group], ", ")})
	}
	for i := 0; i < 3; i++ {
		rows = append(rows, ruleRow{Number: len(rows) + 1})
	}
	return page.Execute(w, view{Page: data, Rows: rows})
}

func snapshot(rules map[string][]string) string {
	if len(rules) == 0 {
		return "Правила отсутствуют"
	}
	groups := make([]string, 0, len(rules))
	for group := range rules {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	lines := make([]string, 0, len(groups))
	for _, group := range groups {
		lines = append(lines, group+" → "+strings.Join(rules[group], ", "))
	}
	return strings.Join(lines, "\n")
}

var page = template.Must(template.New("admin-models").Funcs(template.FuncMap{
	"snapshot":  snapshot,
	"timestamp": func(at time.Time) string { return at.UTC().Format("02.01.2006 15:04:05 UTC") },
}).Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Доступ к моделям — Portico Gateway</title><link rel="stylesheet" href="/admin/style.css"></head>
<body><a class="skip" href="#main">Перейти к содержимому</a><div class="shell">
<header><a class="brand" href="/" aria-label="Portico Gateway — главная"><span class="mark" aria-hidden="true"></span><span>Portico Gateway</span></a><div class="account"><span>{{.Subject}}</span><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="quiet" type="submit">Выйти</button></form></div></header>
<main id="main"><div class="intro"><p class="eyebrow">Администрирование</p><h1>Доступ к моделям</h1><p class="description">Укажите модели, разрешённые каждой группе пользователей. Изменения вступят в силу после сохранения.</p><p class="revision">Редакция правил: {{.Revision}}</p></div>
{{if .Error}}<div class="message error" role="alert"><strong>Изменения не сохранены</strong><p>{{.Error}}</p></div>{{end}}
{{if .Notice}}<div class="message notice" role="status">{{.Notice}}</div>{{end}}
<div class="workspace"><section class="editor" aria-labelledby="rules-title"><h2 id="rules-title">Правила доступа</h2><p class="hint" id="rules-help">Введите точное имя группы и идентификаторы моделей через запятую. Для удаления правила очистите оба поля в его строке. Пустые строки не сохраняются.</p>
<form method="post" action="/admin/models" aria-describedby="rules-help"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="revision" value="{{.Revision}}">
<div class="rows">{{range .Rows}}<fieldset class="rule"><legend>Правило {{.Number}}</legend><div class="field"><label for="group-{{.Number}}">Группа</label><input id="group-{{.Number}}" name="group" value="{{.Group}}" type="text" autocomplete="off" spellcheck="false" placeholder="Имя группы"></div><div class="field models-field"><label for="models-{{.Number}}">Модели</label><input id="models-{{.Number}}" name="models" value="{{.Models}}" type="text" list="model-catalog" autocomplete="off" spellcheck="false" placeholder="model-id, another-model-id"></div></fieldset>{{end}}</div>
<datalist id="model-catalog">{{range .Models}}<option value="{{.}}"></option>{{end}}</datalist>
<div class="save"><p class="hint">Для новых правил предусмотрены три пустые строки. После сохранения можно добавить следующие.</p><button class="primary" type="submit">Сохранить изменения</button></div></form></section>
<aside class="catalog" aria-labelledby="catalog-title"><h2 id="catalog-title">Каталог моделей</h2><p class="hint">Используйте эти идентификаторы в правилах. Для нескольких моделей скопируйте их в поле через запятую.</p>{{if .Models}}<p class="count">Моделей в каталоге: {{len .Models}}</p><ul>{{range .Models}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}<p class="empty">Список моделей пуст или временно недоступен.</p>{{end}}<p class="catalog-note">Сохранённые идентификаторы остаются в правилах, даже если их нет в текущем каталоге.</p></aside></div>
<section class="audit" aria-labelledby="audit-title"><div class="section-heading"><h2 id="audit-title">История изменений</h2><p class="hint">Время указано в UTC.</p></div>{{if .Audit}}<ol class="audit-list">{{range .Audit}}<li><div class="audit-meta"><strong>{{.Subject}}</strong><span>{{timestamp .At}}</span></div><div class="snapshots"><div><h3>До изменения</h3><pre>{{snapshot .Before}}</pre></div><div><h3>После изменения</h3><pre>{{snapshot .After}}</pre></div></div></li>{{end}}</ol>{{else}}<p class="empty">Изменения пока не зарегистрированы.</p>{{end}}</section>
</main><footer>Portico Gateway · Управление доступом</footer></div></body></html>`))

// CSS is served by the parent router at GET /admin/style.css.
const CSS = `*{box-sizing:border-box}html{color-scheme:light}body{margin:0;background:#faf7f3;color:#201c20;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.55}.shell{max-width:1400px;margin:auto;padding:0 clamp(20px,5vw,76px)}a{color:#503449;text-underline-offset:4px}header{display:flex;align-items:center;justify-content:space-between;gap:24px;padding:30px 0;border-bottom:1px solid #ded6d1}.brand{display:flex;align-items:center;gap:14px;color:inherit;text-decoration:none;font:28px "Times New Roman",Times,serif}.mark{display:block;flex:0 0 30px;width:30px;height:34px;background:#aa634b;clip-path:polygon(0 25%,50% 0,100% 25%,100% 100%,67% 100%,67% 48%,61% 39%,50% 36%,39% 39%,33% 48%,33% 100%,0 100%)}.account{display:flex;align-items:center;gap:18px;color:#655b64;min-width:0}.account>span{max-width:300px;overflow-wrap:anywhere}.intro{max-width:740px;padding:52px 0 32px}.eyebrow{color:#8b5545;font-size:12px;letter-spacing:.13em;text-transform:uppercase;margin:0 0 16px}h1,h2,h3{font-family:"Times New Roman",Times,serif;font-weight:400;line-height:1.15}h1{font-size:clamp(38px,4.5vw,62px);letter-spacing:-.02em;margin:0 0 22px}h2{font-size:30px;margin:0 0 16px}h3{font-size:21px;margin:0 0 12px}.description{color:#56505a;font-size:18px;max-width:620px;margin:0 0 20px}.revision,.hint,.count{font-size:14px;color:#6a626a}.revision{margin:0}.workspace{display:grid;grid-template-columns:minmax(0,1fr) 290px;gap:40px}.editor,.catalog{min-width:0}.hint{margin:0 0 22px}.rows{border-top:1px solid #ded6d1}.rule{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.7fr);gap:18px;margin:0;padding:20px 0 24px;border:0;border-bottom:1px solid #ded6d1;min-width:0}.rule legend{grid-column:1/-1;padding:0;font-size:12px;letter-spacing:.06em;color:#766874}.field{min-width:0}.field label{display:block;font-size:14px;margin:0 0 8px}input{width:100%;min-width:0;border:1px solid #cfc3ca;background:#fffdfa;border-radius:6px;padding:12px;color:#201c20;font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}input::placeholder{color:#857a82;font-size:12px}button{font:inherit;cursor:pointer;border-radius:6px;padding:12px 20px}.primary{background:#503449;color:#fff9f8;border:1px solid #503449;white-space:nowrap}.primary:hover{background:#3c2537}.quiet{background:transparent;color:#503449;border:1px solid #cfc3ca;padding:8px 14px}.quiet:hover{background:#efe7eb}.save{display:flex;gap:24px;align-items:center;justify-content:space-between;padding:24px 0}.save .hint{max-width:380px;margin:0}.catalog{background:#f0e9e6;border:1px solid #e1d7d2;border-radius:8px;padding:24px;align-self:start}.catalog h2{font-size:27px}.catalog ul{list-style:none;padding:0;margin:0;max-height:540px;overflow:auto}.catalog li{padding:10px 0;border-bottom:1px solid #ddd1d7}.catalog code{font-size:13px;overflow-wrap:anywhere}.catalog-note{font-size:13px;color:#665862;margin:22px 0 0}.empty{color:#6a626a;font-size:14px}.message{padding:20px 24px;border:1px solid;border-radius:6px;margin:0 0 28px;overflow-wrap:anywhere}.message p{margin:6px 0 0}.error{border-color:#bc8777;background:#f8ebe5;color:#76392c}.notice{border-color:#9aab96;background:#edf1e9;color:#345537}.audit{margin:52px 0 0;padding-top:34px;border-top:1px solid #cfc3ca}.section-heading{display:flex;align-items:baseline;justify-content:space-between;gap:24px}.audit-list{list-style:none;padding:0;margin:0}.audit-list>li{padding:24px 0;border-top:1px solid #ded6d1}.audit-meta{display:flex;justify-content:space-between;gap:20px;margin-bottom:20px;font-size:13px;overflow-wrap:anywhere}.audit-meta span{color:#6a626a}.snapshots{display:grid;grid-template-columns:1fr 1fr;gap:24px}.snapshots>div{min-width:0}.snapshots pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;margin:0;padding:16px;background:#f0e9e6;border-radius:6px}footer{padding:28px 0;margin-top:32px;border-top:1px solid #ded6d1;color:#756c73;font-size:13px}.skip{position:absolute;left:20px;top:-100px;padding:12px;background:#fffdfa;z-index:1}.skip:focus{top:12px}a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid #9d553d;outline-offset:3px}@media(max-width:1000px){.workspace{grid-template-columns:minmax(0,1fr) 240px;gap:24px}.catalog{padding:18px}.save{align-items:flex-start;flex-direction:column}}@media(max-width:760px){header{align-items:flex-start;flex-direction:column;padding:24px 0}.account{width:100%;justify-content:space-between}.account>span{max-width:75%}.intro{padding-top:36px}.workspace{grid-template-columns:1fr}.catalog{margin-top:12px}.catalog ul{max-height:260px}.rule{grid-template-columns:1fr;gap:12px}.save .primary{width:100%}.save{gap:18px}.snapshots{grid-template-columns:1fr;gap:18px}.audit-meta,.section-heading{flex-direction:column;gap:6px}.audit{margin-top:36px}.brand{font-size:26px}}`
