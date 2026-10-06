"use strict";
(() => {
 const card = document.getElementById("scan-card");
 if (!card) return;
 const id = card.dataset.scanId;
 if (!/^[a-z][a-z0-9-]{2,62}$/.test(id)) return;
 const terminal = new Set(["complete", "completed", "failed", "cancelled", "canceled", "error"]);
 let stopped = false, busy = false, timer, retry = 5000, current = null, artifactsChecked = false;
 const put = (key, value) => { document.getElementById(key).textContent = value; };
 const words = {queued:"В очереди",running:"Выполняется",pending:"Ожидание",complete:"Завершена",completed:"Завершён",failed:"Ошибка",cancelled:"Отменена",canceled:"Отменена",unknown:"Неизвестно",waiting_for_model:"Ожидание ответа модели",executing_tool:"Выполнение инструмента",tool_completed:"Инструмент завершил работу",model_response:"Получен ответ модели",model_error:"Ошибка запроса к модели",initializing:"Подготовка",analysis:"Анализ",report_publication:"Публикация отчёта",finished:"Завершение",queue:"Очередь",environment:"Подготовка среды"};
 const label = value => typeof value === "string" ? (words[value] || value) : "Нет данных";
 const seconds = value => Number.isFinite(value) && value >= 0 ? value : null;
 const duration = value => { const n=seconds(value); if(n===null)return "Нет данных"; const t=Math.floor(n);return (Math.floor(t/3600)>0?Math.floor(t/3600)+" ч ":"")+Math.floor((t%3600)/60)+" мин "+t%60+" с"; };
 const parsed = value => typeof value === "string" ? Date.parse(value) : NaN;
 const age = value => {const at=parsed(value);return Number.isFinite(at)?duration(Math.max(0,(Date.now()-at)/1000))+" назад":"Нет данных";};
 function clocks() {
  if (!current) return;
  const p=current.progress || {}, start=parsed(current.started_at), finish=parsed(current.finished_at);
  let elapsed=current.duration_seconds;
  if(Number.isFinite(start)){if(Number.isFinite(finish))elapsed=Math.max(0,(finish-start)/1000);else if(!terminal.has(current.status))elapsed=Math.max(0,(Date.now()-start)/1000);}
  put("elapsed", duration(elapsed));
  put("last-event", age(p.last_useful_event_at || p.last_event_at));
  put("heartbeat", p.heartbeat_at ? age(p.heartbeat_at) + (p.stale ? " · устаревший сигнал" : "") : "Нет данных");
 }
 function message(text) { const el=document.getElementById("message");el.textContent=text;el.hidden=!text; }
 function render(data) {
  current=data;
  const p=data.progress || {};
  put("status",label(data.status));
  put("eta",seconds(p.eta_seconds)===null?"Неизвестна":duration(p.eta_seconds));
  put("activity",label(p.stage)+(typeof p.tool==="string"&&p.tool?" · "+p.tool:""));
  const list=document.getElementById("stages");list.replaceChildren();
  const stages=Array.isArray(p.lifecycle_stages)&&p.lifecycle_stages.length?p.lifecycle_stages:(Array.isArray(p.stages)?p.stages:[]);
  for(const stage of stages.slice(0,30)){if(!stage||typeof stage!=="object")continue;const li=document.createElement("li");li.textContent=(typeof stage.name==="string"?stage.name:label(stage.id))+" — "+label(stage.status)+(typeof stage.description==="string"?". "+stage.description:"");list.appendChild(li);}
  if(!list.childNodes.length){const li=document.createElement("li");li.textContent="Данные об этапах не предоставлены.";list.appendChild(li);}
  const index=Number(p.lifecycle_stage_index), count=Number(p.lifecycle_stage_count);
  put("stage-heading",Number.isInteger(index)&&index>0&&Number.isInteger(count)&&index<=count?"Этап "+index+" из "+count:"Этапы проверки");
  const obs=p.observations||{}, facts=[];
  for(const [key,field,title] of [["run","target_count","Целей"],["agents","agent_count","Агентов"],["coverage","surfaces_reviewed","Поверхностей учтено"],["findings","findings_count","Находок оформлено"]]){
   const o=obs[key];if(o&&o.available&&Number.isFinite(o[field]))facts.push(title+": "+o[field]+(o.stale?" (устаревшие данные)":""));
  }
  if(obs.llm&&obs.llm.available){const m=obs.llm.latest_request||{};if(Number.isFinite(m.duration_ms))facts.push("Последний запрос к модели: "+duration(m.duration_ms/1000));if(Number.isFinite(m.input_tokens))facts.push("Входной контекст: "+m.input_tokens+" токенов");}
  put("observations",facts.length?facts.join(" · "):"Данных о выполненных действиях пока нет");
  clocks();
 }
 async function loadArtifacts() {
  const list=document.getElementById("artifacts");
  try {
   const response=await fetch("/portal/api/scans/"+encodeURIComponent(id)+"/artifacts",{credentials:"same-origin",cache:"no-store",headers:{Accept:"application/json"},signal:AbortSignal.timeout(15000)});
   if(response.status===401){stopped=true;put("connection","Требуется вход");message("Сеанс завершён. Выполните вход повторно.");document.getElementById("login-link").hidden=false;return;}
   if(!response.ok)throw new Error("unavailable");
   const data=await response.json();
   if(data.scan_id!==id||!Array.isArray(data.artifacts))throw new Error("invalid");
   list.replaceChildren();
   const fixed=new Set(["report.md","findings.json","findings.sarif","coverage.json","vulnerabilities.csv"]);
   for(const name of data.artifacts){if(typeof name!=="string"||(!fixed.has(name)&&!/^evidence\/[A-Za-z0-9][A-Za-z0-9_.-]{0,191}\.md$/.test(name)))continue;const li=document.createElement("li"),link=document.createElement("a");link.textContent=name;link.href="/portal/scans/"+encodeURIComponent(id)+"/evidence?name="+encodeURIComponent(name);li.appendChild(link);list.appendChild(li);}
   if(!list.childNodes.length){const li=document.createElement("li");li.textContent="Опубликованных файлов пока нет.";list.appendChild(li);}
  } catch (_){list.replaceChildren();const li=document.createElement("li");li.textContent="Список файлов пока недоступен. Он будет запрошен снова при завершении проверки; также можно обновить страницу.";list.appendChild(li);}
  artifactsChecked=true;
 }
 function schedule(delay) { if(!stopped)timer=setTimeout(poll,delay); }
 async function poll() {
  if(stopped||busy)return;
  busy=true;
  const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),25000);
  try {
   const response=await fetch("/portal/api/scans/"+encodeURIComponent(id),{credentials:"same-origin",cache:"no-store",headers:{Accept:"application/json"},signal:controller.signal});
   if(response.status===401){stopped=true;put("connection","Требуется вход");message("Сеанс завершён. Выполните вход повторно.");document.getElementById("login-link").hidden=false;return;}
   if(response.status===403||response.status===404){stopped=true;put("connection","Обновление остановлено");message("Проверка недоступна для этой учётной записи или не найдена.");return;}
   if(response.status===503||response.status===429||response.status>=500)throw new Error("temporary");
   if(!response.ok){stopped=true;put("connection","Обновление остановлено");message("Не удалось получить состояние проверки. Обновите страницу позднее.");return;}
   const data=await response.json();
   if(!data||data.scan_id!==id)throw new Error("invalid response");
   render(data);retry=5000;message("");
   if(!artifactsChecked||terminal.has(data.status))await loadArtifacts();
   if(stopped)return;
   if(terminal.has(data.status)){stopped=true;put("connection","Проверка завершена · обновление остановлено");return;}
   put("connection","Связь с API установлена");schedule(5000);
  } catch (_) {
   put("connection","Нет свежих данных");message("Не удалось обновить состояние. Повторная попытка через "+Math.floor(retry/1000)+" с. Причина задержки проверки неизвестна.");schedule(retry);retry=Math.min(retry*2,30000);
  } finally {clearTimeout(timeout);busy=false;}
 }
 const clock=setInterval(clocks,1000);
 window.addEventListener("pagehide",()=>{stopped=true;clearTimeout(timer);clearInterval(clock);});
 poll();
})();
