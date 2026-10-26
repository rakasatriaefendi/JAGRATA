import https from 'node:https';
import {readFile} from 'node:fs/promises';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {resolve,dirname} from 'node:path';
import {Auth} from './auth.ts';
import {CrowdSec} from './adapter.ts';
import {Sources} from './sources.ts';
import {Remediation,observeDecisions} from './remediation.ts';
import {SecurityPlatform} from './security.ts';
import {SecurityPlans} from './security-plans.ts';
const consoleRoot=resolve(dirname(fileURLToPath(import.meta.url)),'../console');
const cookieName='__Host-guard';
async function body(req:any){let size=0,chunks=[];for await(const chunk of req){size+=chunk.length;if(size>4096)throw Object.assign(Error('Request too large'),{status:413});chunks.push(chunk)}try{return JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{throw Object.assign(Error('Invalid JSON'),{status:400})}}
export function handler({auth,adapter,origin,sources,remediation,security,securityPlans}:{auth:Auth;adapter:any;origin:string;sources?:Sources;remediation?:Remediation;security?:SecurityPlatform;securityPlans?:SecurityPlans}){
 const budgets=new WeakMap<object,{at:number;reads:number;plans:number}>();
 function budget(session:object,plan=false){const now=Date.now();let b=budgets.get(session);if(!b||now-b.at>=60000){b={at:now,reads:0,plans:0};budgets.set(session,b)}if(plan?++b.plans>6:++b.reads>12)throw Object.assign(Error('Security request budget exceeded. Wait before refreshing.'),{status:429})}
 return async(req:any,res:any)=>{res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");res.setHeader('Permissions-Policy','clipboard-write=(self)');
 const send=(status:number,data:any)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(data))};
 try{
  if(req.headers.host!==new URL(origin).host)return send(403,{error:'Invalid host'});
  const url=new URL(req.url,origin);if(url.href.length>2048)return send(414,{error:'URL too long'});
  const secret=String(req.headers.cookie||'').split(';').map((x:string)=>x.trim()).find((x:string)=>x.startsWith(cookieName+'='))?.slice(cookieName.length+1)||'';
  const session=secret.length<128?auth.get(secret):null;
  if(req.method==='POST'){
   if(req.headers.origin!==origin||req.headers['content-type']!=='application/json')return send(403,{error:'Same-origin JSON request required'});
   if(url.pathname==='/api/login'){
    if(req.headers['x-guard-login']!=='1')return send(403,{error:'Login request rejected'});const b=await body(req);
    if(!b||typeof b.username!=='string'||typeof b.password!=='string'||b.username.length>64||b.password.length>256)return send(400,{error:'Invalid credentials format'});
    const signed=await auth.login(b.username,b.password,req.socket.remoteAddress||'local');if(!signed)return send(401,{error:'Invalid username or password'});
    if(secret)auth.logout(secret);res.setHeader('Set-Cookie',`${cookieName}=${signed.secret}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800`);return send(200,{csrf:signed.session.csrf,username:auth.admin.username});
   }
   if(!session)return send(401,{error:'Authentication required'});
   if(req.headers['x-csrf-token']!==session.csrf)return send(403,{error:'CSRF validation failed'});
   if(url.pathname==='/api/logout'){auth.logout(secret);res.setHeader('Set-Cookie',`${cookieName}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);return send(200,{ok:true})}
   if(remediation&&url.pathname==='/api/remediation/preview')return send(200,await remediation.preview(await body(req),auth.admin.username));
   if(remediation&&url.pathname==='/api/remediation/confirm')return send(200,await remediation.confirm(await body(req),auth.admin.username));
   if(sources&&url.pathname==='/api/sources/validate')return send(200,await sources.validate(await body(req)));
   if(sources&&url.pathname==='/api/sources/save'){const b=await body(req);await sources.change('save',b);return send(200,await sources.list())}
   if(sources&&url.pathname==='/api/sources/remove'){await sources.change('remove',await body(req));return send(200,await sources.list())}
   if(securityPlans&&url.pathname==='/api/security/plan'){budget(session,true);return send(200,await securityPlans.prepare(await body(req),auth.admin.username))}
   return send(404,{error:'Operation not available'});
  }
  if(req.method!=='GET')return send(405,{error:'Method not allowed'});
  if(url.pathname.startsWith('/api/')){
   if(!session)return send(401,{error:'Authentication required'});
   if(url.pathname==='/api/session')return send(200,{csrf:session.csrf,username:auth.admin.username});
   if(security&&url.pathname==='/api/security'){budget(session);return send(200,await security.snapshot())}
   if(remediation&&url.pathname==='/api/remediation')return send(200,await remediation.list());
   if(remediation&&url.pathname==='/api/remediation/decisions'){if(security){const v=await security.snapshot();if(!v.decisions||!v.identity)return send(503,{error:'Decision observation unavailable; no zero substituted.'});return send(200,{...v.decisions,observedAt:v.observedAt,installationId:v.identity.installationId,mode:'READ_ONLY_DRY_RUN',enforcement:'NOT_VERIFIED'})}return send(200,await observeDecisions(adapter))}
   if(sources&&url.pathname==='/api/sources')return send(200,await sources.list());
   if(url.pathname==='/api/snapshot'){try{return send(200,await adapter.snapshot())}catch{return send(503,{error:'CrowdSec observation unavailable. No sample data substituted.',state:'UNAVAILABLE'})}}
   const detail=url.pathname.match(/^\/api\/alerts\/([1-9][0-9]{0,8})$/);if(detail){try{return send(200,{alert:await adapter.detail(Number(detail[1])),observedAt:new Date().toISOString(),freshness:'HISTORICAL'})}catch{return send(503,{error:'Alert unavailable from the configured engine'})}}
   return send(404,{error:'API route not found'});
  }
  const files:any={'/':['index.html','text/html'],'/client.js':['client.js','text/javascript'],'/styles.css':['styles.css','text/css'],'/design.css':['../../docs/design/cs01-5/prototype/styles.css','text/css']};const item=files[url.pathname];if(!item)return send(404,{error:'Page not found'});const content=await readFile(resolve(consoleRoot,item[0]));res.writeHead(200,{'Content-Type':item[1]+'; charset=utf-8'});res.end(content);
 }catch(error:any){send(error.status||500,{error:error.public||error.status===429?error.message:'Request failed safely',...(/^[a-f0-9]{32}$/.test(error.correlationId)?{correlationId:error.correlationId}:{})})}
 };
}
export async function launch(){const {GUARD_ADMIN_FILE,GUARD_ADAPTER_FILE,GUARD_TLS_CERT,GUARD_TLS_KEY}=process.env;if(!GUARD_ADMIN_FILE||!GUARD_ADAPTER_FILE||!GUARD_TLS_CERT||!GUARD_TLS_KEY)throw Error('Explicit admin/adapter files and TLS certificate/key required; run bootstrap first.');const port=Number(process.env.GUARD_PORT||44331);if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Invalid port');const origin=`https://127.0.0.1:${port}`;const auth=await Auth.load(GUARD_ADMIN_FILE),adapter=await CrowdSec.load(GUARD_ADAPTER_FILE);const sources=new Sources(resolve(dirname(GUARD_ADMIN_FILE),'sources'),adapter);const remediation=new Remediation(resolve(dirname(GUARD_ADMIN_FILE),'remediation'),adapter),security=new SecurityPlatform(adapter,sources),securityPlans=new SecurityPlans(security,remediation);const server=https.createServer({cert:await readFile(GUARD_TLS_CERT),key:await readFile(GUARD_TLS_KEY)},handler({auth,adapter,origin,sources,remediation,security,securityPlans}));server.requestTimeout=10_000;server.headersTimeout=10_000;server.maxConnections=64;await new Promise<void>((ready,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>{server.removeListener('error',reject);console.log('Guard Console: '+origin);ready()})});return server}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)launch().catch(()=>{console.error('Startup refused. Check explicit private configuration, bootstrap and TLS. No secrets logged.');process.exitCode=1});
