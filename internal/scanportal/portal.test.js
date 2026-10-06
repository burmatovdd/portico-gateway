const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/portal.js', 'utf8');
function harness(fetchImpl, artifacts = []) {
 const elements = new Map();
 const element = () => ({textContent:'',hidden:true,dataset:{scanId:'scan-one'},childNodes:[],replaceChildren(){this.childNodes=[];},appendChild(child){this.childNodes.push(child);}});
 const get = key => {if(!elements.has(key))elements.set(key,element());return elements.get(key);};
 let sequence=0;
 const timers=new Map();
 const context={document:{getElementById:get,createElement:element},window:{addEventListener(){}},AbortController,AbortSignal,fetch:async (url, options) => url.endsWith("/artifacts") ? response(200,{scan_id:"scan-one",artifacts}) : fetchImpl(url,options),Date,Set,Number,Math,Error,encodeURIComponent,setTimeout(fn,delay){const id=++sequence;timers.set(id,{fn,delay});return id;},clearTimeout(id){timers.delete(id);},setInterval(){return 99;},clearInterval(){}};
 vm.runInNewContext(source,context);
 return {get,timers,async flush(){await new Promise(resolve=>setImmediate(resolve));},async runNext(){const entry=[...timers.entries()].find(([,timer])=>timer.delay!==25000);assert.ok(entry);timers.delete(entry[0]);await entry[1].fn();}};
}
function response(status,data){return {status,ok:status===200,json:async()=>data};}
test('terminal scan stops polling; HTML-like fields remain text',async()=>{
 let calls=0;const h=harness(async()=>{calls++;return response(200,{scan_id:'scan-one',status:'complete',progress:{eta_seconds:null,stage:'<img src=x>',lifecycle_stages:[{name:'<script>',status:'completed'}]}});});await h.flush();
 assert.equal(calls,1);assert.equal(h.timers.size,0);assert.equal(h.get('eta').textContent,'Неизвестна');assert.equal(h.get('activity').textContent,'<img src=x>');assert.match(h.get('stages').childNodes[0].textContent,/<script>/);
});
test('auth and owner denial stop; login link only on 401',async()=>{
 for(const code of [401,403,404]){const h=harness(async()=>response(code));await h.flush();assert.equal(h.timers.size,0);assert.equal(h.get('login-link').hidden,code!==401);}
});
test('temporary failures back off from 5 to 30 seconds',async()=>{
 const h=harness(async()=>response(503));await h.flush();
 for(const delay of [5000,10000,20000,30000,30000]){assert.equal([...h.timers.values()][0].delay,delay);await h.runNext();}
});
test('network failures back off and success resets to normal five seconds',async()=>{
 let calls=0;const h=harness(async()=>{if(++calls<=2)throw new Error('network');return response(200,{scan_id:'scan-one',status:'running',progress:{eta_seconds:null}});});await h.flush();await h.runNext();assert.equal([...h.timers.values()][0].delay,10000);await h.runNext();assert.equal([...h.timers.values()][0].delay,5000);
});
test('only one request is in flight',async()=>{
 let complete,calls=0;const h=harness(()=>{calls++;return new Promise(resolve=>{complete=resolve;});});assert.equal(calls,1);assert.equal([...h.timers.values()].filter(t=>t.delay===5000).length,0);complete(response(200,{scan_id:'scan-one',status:'running',progress:{}}));await h.flush();assert.equal(calls,1);assert.equal([...h.timers.values()][0].delay,5000);
});
test('artifact names generate only controlled same-origin download links',async()=>{
 const h=harness(async()=>response(200,{scan_id:'scan-one',status:'complete',progress:{}}),['evidence/vuln-0001.md','report.md','javascript:alert(1)','evidence/../x.md','<img>']);await h.flush();
 const rows=h.get('artifacts').childNodes;assert.equal(rows.length,2);assert.equal(rows[0].childNodes[0].textContent,'evidence/vuln-0001.md');assert.equal(rows[0].childNodes[0].href,'/portal/scans/scan-one/evidence?name=evidence%2Fvuln-0001.md');
});
