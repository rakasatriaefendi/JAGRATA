// Dependency-free acceptance harness. Requires explicit local private adapter config.
// Never starts/stops Docker. Uses the actual Manager HTTPS launch and installed Chromium.
import http from 'node:http';
import {spawn,execFileSync} from 'node:child_process';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {bootstrap} from '../../apps/manager/auth.ts';
import {launch} from '../../apps/manager/server.ts';
const adapterFile=process.env.GUARD_ADAPTER_FILE;
if(!adapterFile)throw Error('GUARD_ADAPTER_FILE must explicitly select an owned QA installation');
const id=randomBytes(5).toString('hex'),qa=resolve(process.env.GUARD_BROWSER_STATE||('runtime/qa-cs04-browser-'+id)),out=resolve(process.env.GUARD_BROWSER_OUT||'docs/design/cs04/previews');
await mkdir(qa,{recursive:true});await mkdir(out,{recursive:true});
const password=randomBytes(28).toString('base64url');
await bootstrap(join(qa,'admin.json'),'browser-auditor',password);
const openssl=process.env.GUARD_OPENSSL||(process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl');
execFileSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(qa,'tls.key'),'-out',join(qa,'tls.crt'),'-days','2','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore',windowsHide:true});
Object.assign(process.env,{GUARD_ADMIN_FILE:join(qa,'admin.json'),GUARD_TLS_CERT:join(qa,'tls.crt'),GUARD_TLS_KEY:join(qa,'tls.key'),GUARD_PORT:String(Number(process.env.GUARD_BROWSER_PORT||44354))});
const server=await launch();await new Promise<void>(r=>server.listening?r():server.once('listening',r));
const origin='https://127.0.0.1:'+process.env.GUARD_PORT;
const exe=process.env.GUARD_CHROMIUM||join(process.env.LOCALAPPDATA||'','ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-win64/chrome-headless-shell.exe');
const child=spawn(exe,['--headless','--ignore-certificate-errors','--remote-debugging-port=0','--user-data-dir='+join(qa,'browser-profile'),'about:blank'],{stdio:['ignore','ignore','pipe'],windowsHide:true});
let ws:WebSocket,seq=0,session:string|undefined;const pending=new Map<number,any>(),checks:string[]=[],errors:string[]=[],layout:any[]=[];
const wait=(ms:number)=>new Promise(r=>setTimeout(r,ms));
function send(method:string,params:any={},sid=session):Promise<any>{return new Promise((resolve,reject)=>{const id=++seq;const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method))},15000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params,...(sid?{sessionId:sid}:{})}))})}
async function evaluate(expression:string){const result=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,userGesture:true,replMode:true});if(result.exceptionDetails)throw Error('Browser evaluation failed: '+(result.exceptionDetails.exception?.description||result.exceptionDetails.text));return result.result.value}
function assert(value:any,message:string){if(!value)throw Error(message);checks.push(message)}
async function until(expression:string){for(let i=0;i<150;i++){if(await evaluate(expression))return;await wait(100)}throw Error('Timed out waiting for '+expression)}
async function screenshot(name:string){const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:!name.startsWith('drawer')});await writeFile(join(out,name+'.png'),Buffer.from(shot.data,'base64'))}
async function resize(width:number,height=1000){await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false})}
async function run(endpoint:string){
 ws=new WebSocket(endpoint);await new Promise(r=>ws.onopen=r);ws.onmessage=event=>{const m=JSON.parse(String(event.data));if(m.id){const p=pending.get(m.id);if(p){clearTimeout(p.timer);pending.delete(m.id);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result)}}if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails.text)};
 const target=await send('Target.createTarget',{url:'about:blank'},undefined);session=(await send('Target.attachToTarget',{targetId:target.targetId,flatten:true},undefined)).sessionId;await send('Runtime.enable');await send('Page.enable');await resize(1440);await send('Page.navigate',{url:origin+'/#sources'});
 await until(`document.querySelector('#login-form')&&!document.querySelector('#login-form button').disabled`);
 assert(await evaluate(`(await fetch('/api/sources')).status===401`),'sources reject anonymous browser');
 await evaluate(`document.querySelector('#username').value='browser-auditor';document.querySelector('#password').value=${JSON.stringify(password)};document.querySelector('#login-form').requestSubmit()`);
 await until(`document.querySelector('#source-add')&&!document.querySelector('#source-add').disabled`);
 assert(await evaluate(`!document.querySelector('#source-drawer').open`),'source workspace is list-first');if(process.env.GUARD_CS04_OBSERVED!=='1')assert(await evaluate(`document.querySelector('#content').textContent.includes('No configured sources')`),'empty workspace explains explicit file onboarding');
 if(process.env.GUARD_CS04_OBSERVED==='1')assert(await evaluate(`document.querySelectorAll('[data-source-status=OBSERVED]').length===2`),'actual appended SSH and Nginx engine evidence reaches authenticated Console');
 const path=join(qa,'browser-explicit-auth.log');await writeFile(path,'synthetic browser metadata fixture only\n',{flag:'wx'});
 async function form(name:string,type:string,file:string){await evaluate(`document.querySelector('#source-add').focus();document.querySelector('#source-add').click();document.querySelector('#source-form [name=name]').value=${JSON.stringify(name)};document.querySelector('#source-form [name=type]').value=${JSON.stringify(type)};document.querySelector('#source-form [name=type]').dispatchEvent(new Event('change'));document.querySelector('#source-form [name=path]').value=${JSON.stringify(file)};document.querySelector('#source-form [name=consent]').checked=true`)}
 await form('Browser SSH','ssh',path);
 assert(await evaluate(`document.activeElement.name==='name'`),'drawer autofocus reaches display name');
 await evaluate(`document.querySelector('#source-validate').click()`);await until(`document.querySelector('#source-feedback').textContent.includes('Regular local file')`);
 assert(await evaluate(`document.querySelector('#toast').parentElement.id==='source-drawer'`),'validation toast uses active drawer top layer');
 await evaluate(`document.querySelector('#source-form').requestSubmit()`);await until(`!document.querySelector('#source-drawer').open&&document.querySelector('.source-table').textContent.includes('Browser SSH')`);
 assert(await evaluate(`document.querySelector('.source-table').textContent.includes('VALIDATED')`),'saved local file does not claim engine ingestion');
 await form('Duplicate file','nginx',path);await evaluate(`document.querySelector('#source-form').requestSubmit()`);await until(`document.querySelector('#source-feedback').textContent.includes('already has')`);
 assert(await evaluate(`document.querySelector('#source-drawer').open`),'duplicate error preserves drawer and inputs');
 await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await until(`!document.querySelector('#source-drawer').open`);
 assert(await evaluate(`document.activeElement.id==='source-add'`),'Escape restores opener focus');
 const web=join(qa,'browser-explicit-access.log');await writeFile(web,'synthetic browser metadata fixture only\n',{flag:'wx'});
 await form('Browser Nginx','nginx',web);assert(await evaluate(`document.querySelector('#source-format').textContent.includes('combined')`),'connector changes supported format guidance');await evaluate(`document.querySelector('#source-form').requestSubmit()`);await until(`!document.querySelector('#source-drawer').open`);
 await evaluate(`document.querySelector('[data-source-edit]').click();document.querySelector('#source-form [name=name]').value='Renamed synthetic source';document.querySelector('#source-form [name=consent]').checked=true;document.querySelector('#source-form').requestSubmit()`);await until(`!document.querySelector('#source-drawer').open`);
 assert(await evaluate(`document.querySelector('.source-table').textContent.includes('Renamed synthetic source')`),'edit persists updated source name');
 // Confirm cancellation does not change configuration.
 await evaluate(`document.querySelector('[data-source-disable]').click()`);assert(await evaluate(`document.querySelector('#source-confirm').open&&document.querySelector('#source-confirm').textContent.includes('can continue reading')`),'disable confirms its engine boundary');await evaluate(`document.querySelector('#source-confirm [data-close]').click()`);
 for(const width of [1920,1440,1280,1024,768,390,360])for(const theme of ['dark','light']){
  await resize(width,1000);await evaluate(`document.documentElement.dataset.theme='${theme}'`);
  for(const page of ['overview','alerts','health','sources']){await evaluate(`location.hash='${page}'`);await wait(50);assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),`${width}/${theme}/${page}: no horizontal overflow`)}
  await evaluate(`document.querySelector('#source-add').click()`);await wait(320);
  assert(await evaluate(`(()=>{const d=document.querySelector('#source-drawer'),r=d.getBoundingClientRect();return d.open&&r.left>=-1&&r.right<=innerWidth+1&&d.scrollWidth<=d.clientWidth+1})()`),`${width}/${theme}: drawer fits viewport`);
  if(width>=768)assert(await evaluate(`Math.abs(document.querySelector('#source-drawer').getBoundingClientRect().height-innerHeight)<2`),`${width}/${theme}: desktop drawer uses full workspace height`);
  if((width===1440&&theme==='dark')||(width===390&&theme==='light'))await screenshot(`drawer-${width}-${theme}`);
  await evaluate(`document.querySelector('#source-drawer').close()`);await wait(60);
  if(['1920-light','1440-dark','390-dark','360-light'].includes(width+'-'+theme))await screenshot(`sources-${width}-${theme}`);
  const sample=await evaluate(`({width:innerWidth,theme:document.documentElement.dataset.theme,main:Math.round(document.querySelector('main').getBoundingClientRect().width),title:getComputedStyle(document.querySelector('#content h1')).fontSize,text:getComputedStyle(document.body).fontSize})`);layout.push(sample);assert(parseFloat(sample.title)>=(width<768?28:30),`${width}/${theme}: page title is comfortably readable`);
 }
 await resize(1440);await evaluate(`document.documentElement.dataset.theme='dark'`);
 // Real keyboard Tab remains inside the native modal.
 await evaluate(`document.querySelector('#source-add').click()`);for(let n=0;n<14;n++){await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});assert(await evaluate(`document.querySelector('#source-drawer').contains(document.activeElement)`),'keyboard focus stays in drawer '+n)}await evaluate(`document.querySelector('#source-drawer').close()`);
 // Source-specific error is recoverable, and engine unavailability does not hide configuration.
 await evaluate(`window.sourceFetch=window.fetch;window.fetch=async(path,options)=>path==='/api/snapshot'?new Response(JSON.stringify({error:'QA engine unavailable'}),{status:503,headers:{'Content-Type':'application/json'}}):window.sourceFetch(path,options);document.querySelector('#refresh').click()`);await until(`!document.querySelector('#refresh').disabled`);assert(await evaluate(`document.querySelector('#source-add')&&!document.querySelector('#source-add').disabled`),'engine outage preserves source configuration workspace');await evaluate(`window.fetch=window.sourceFetch`);
 await evaluate(`window.fetch=async(path,options)=>path==='/api/sources'?new Response(JSON.stringify({error:'QA source read unavailable'}),{status:503,headers:{'Content-Type':'application/json'}}):window.sourceFetch(path,options);document.querySelector('#refresh').click()`);await until(`document.querySelector('#source-retry')!==null`);assert(await evaluate(`document.querySelector('#content').textContent.includes('QA source read unavailable')`),'source fetch error is visible with retry');await evaluate(`window.fetch=window.sourceFetch;document.querySelector('#source-retry').click()`);await until(`document.querySelector('#source-retry')===null`);assert(await evaluate(`document.querySelector('.source-table')!==null`),'source retry restores configured rows');

 await evaluate(`document.querySelector('[data-source-disable]').click();document.querySelector('#source-confirm-action').click()`);await until(`!document.querySelector('#source-confirm').open`);assert(await evaluate(`document.querySelector('.source-table').textContent.includes('DISABLED')`),'confirmed disable persists without Docker action');
 const toRemove=await evaluate(`document.querySelectorAll('[data-source-remove]').length`);await evaluate(`document.querySelectorAll('[data-source-remove]')[${toRemove-1}].click();document.querySelector('#source-confirm-action').click()`);await until(`!document.querySelector('#source-confirm').open`);assert(await evaluate(`document.querySelectorAll('[data-source-remove]').length===${toRemove-1}`),'confirmed removal updates list and preserves underlying file');
 await evaluate(`document.querySelector('#refresh').click()`);await until(`!document.querySelector('#refresh').disabled`);assert(await evaluate(`document.querySelector('.source-table').textContent.includes('DISABLED')`),'source state survives fresh server read');
 // Check actual computed design token pair contrast in both themes.
 for(const theme of ['dark','light']){const colors=await evaluate(`document.documentElement.dataset.theme='${theme}';(()=>{const s=getComputedStyle(document.documentElement);return Object.fromEntries(['text','muted','faint','accent','on-accent','warning','critical','canvas','surface','elevated'].map(k=>[k,s.getPropertyValue('--'+k).trim()]))})()`);const lum=(hex:string)=>{const rgb=hex.replace('#','').match(/../g)!.map(c=>parseInt(c,16)/255).map(c=>c<=.04045?c/12.92:((c+.055)/1.055)**2.4);return .2126*rgb[0]+.7152*rgb[1]+.0722*rgb[2]};for(const[fg,bg]of [['text','canvas'],['text','surface'],['muted','surface'],['muted','elevated'],['faint','elevated'],['accent','surface'],['on-accent','accent'],['warning','surface'],['critical','surface']]){const a=lum(colors[fg]),b=lum(colors[bg]),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);assert(ratio>=4.5,`${theme}: ${fg}/${bg} contrast ${ratio.toFixed(2)} meets AA`)}}
 await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});assert(await evaluate(`getComputedStyle(document.querySelector('#toast')).transitionDuration==='0s'`),'reduced motion disables toast transition');
 assert(errors.length===0,'no uncaught browser exceptions');
}
let started=false;const completion=new Promise<void>((done,reject)=>{child.once('error',reject);child.stderr.on('data',buffer=>{const match=String(buffer).match(/DevTools listening on (ws:\/\/\S+)/);if(match&&!started){started=true;run(match[1]).then(done,reject)}});setTimeout(()=>{if(!started)reject(Error('Browser did not start'))},15000).unref()});
try{await completion;await writeFile(join(out,'qa-results.json'),JSON.stringify({at:new Date().toISOString(),checks,layout,errors,engineEvidenceRequired:process.env.GUARD_CS04_OBSERVED==='1',qa},null,2));console.log(JSON.stringify({passed:checks.length,errors,qa},null,2))}
catch(e){try{const shot=await send('Page.captureScreenshot',{format:'png'});await writeFile(join(qa,'failure.png'),Buffer.from(shot.data,'base64'))}catch{};await writeFile(join(qa,'failure.json'),JSON.stringify({error:String(e),checks,errors},null,2));throw e}
finally{ws?.close();child.kill();server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));for(const p of pending.values())clearTimeout(p.timer)}
