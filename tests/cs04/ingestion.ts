// Execution requires separate operator ingestion approval. Importing is side-effect free.
// One existing CS04 engine; no Docker lifecycle commands. Never run for hardening tests.
import * as fs from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {execFile,fork} from 'node:child_process';
import {CrowdSec} from '../../apps/manager/adapter.ts';
import {Sources,acquisition} from '../../apps/manager/sources.ts';
import {TARGET,ROOT,RUN_LIMIT_MS,TERMINATION_GRACE_MS,REPORT_GRACE_MS,Budget,VerifiedLog,IngestionFault,requireSafe,parseTarget,unlinkedPath,jsonFile,readBounded,validateBundle,verifyEngine,hash,failureCode} from './ingestion-safety.ts';

const OLD_IDS=['63a6462c8beba871d6f2adb0b52bc8ab09dc6950c38c9559780f7c88d52fd307','ebe24d67e2fe2b81a53d5de96e777b7ba00f955e5b4df547bb55fe5487fcf07b'];
const CS01_FILES=['runtime/qa-cs01-98d2e1ede4/after-alerts.json','runtime/qa-cs01-98d2e1ede4/after-metrics.json','runtime/qa-cs01-98d2e1ede4/evidence.json','fixtures/logs/ssh/auth.log','fixtures/logs/web/access.log'];
const ARTIFACTS=new Set(['prewarmup-observation.json','before-observation.json','after-observation.json','source-observation.json','adapter-verified.json','ingestion-results.json']);
const previousNames=['append-started.json',...ARTIFACTS,'ingestion-evidence','ingestion-supervisor-failure.json'];
const specs={ssh:{ip:'203.0.113.164',count:8,scenario:'crowdsecurity/ssh-bf',parser:'crowdsecurity/sshd-logs'},nginx:{ip:'198.51.100.164',count:12,scenario:'crowdsecurity/http-probing',parser:'crowdsecurity/nginx-logs'}};
const canonical=(x:any):any=>Array.isArray(x)?x.map(canonical):x&&typeof x==='object'?Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,canonical(v)])):x;
const digest=(x:any)=>hash(JSON.stringify(canonical(x)));
const encoded=(x:any,max=2*1024*1024)=>{const b=Buffer.from(JSON.stringify(x)+'\n');requireSafe(b.length<=max,'EVIDENCE_BOUND');return b};
export function dockerReadAllowed(args:string[]){
 const prefix=['--context','desktop-linux'];if(args[0]!==prefix[0]||args[1]!==prefix[1])return false;const rest=args.slice(2);
 return [ ['context','inspect','desktop-linux'],['container','inspect',TARGET.id],['container','inspect',...OLD_IDS],
  ['exec',TARGET.id,'cscli','alerts','list','--limit','201','-o','json'],['exec',TARGET.id,'cscli','metrics','show','acquisition','parsers','scenarios','-o','json'],['exec',TARGET.id,'cscli','scenarios','list','-o','json'],
  ['exec',TARGET.id,'cscli','config','show','--key','Config.API.Server.OnlineClient','-o','json']
 ].some(expected=>JSON.stringify(expected)===JSON.stringify(rest));
}
export function payload(type:'ssh'|'nginx',warmup:boolean,date:Date){
 const months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],p=(n:number)=>String(n).padStart(2,'0');
 const time=`${p(date.getUTCHours())}:${p(date.getUTCMinutes())}:${p(date.getUTCSeconds())}`,ssh=`${months[date.getUTCMonth()]} ${p(date.getUTCDate())} ${time}`,web=`${p(date.getUTCDate())}/${months[date.getUTCMonth()]}/${date.getUTCFullYear()}:${time} +0000`;
 if(warmup)return type==='ssh'?`${ssh} guard-cs04 sshd[6400]: Accepted password for synthetic from 192.0.2.164 port 50001 ssh2\n`:`192.0.2.165 - - [${web}] "GET / HTTP/1.1" 200 612 "-" "guard-cs04-benign/1.0"\n`;
 return Array.from({length:specs[type].count},(_,n)=>type==='ssh'?`${ssh} guard-cs04 sshd[${6400+n}]: Failed password for invalid user synthetic${n} from 203.0.113.164 port ${51000+n} ssh2\n`:`198.51.100.164 - - [${web}] "GET /cs04-probe-${n} HTTP/1.1" 404 162 "-" "guard-cs04-synthetic/1.0"\n`).join('');
}
function counter(o:any,kind:string,key:string,name:string){const value=o?.metrics?.[kind]?.[key]?.[name];return typeof value==='number'&&Number.isFinite(value)?value:0}
export function observationSummary(o:any,sources:any[]){
 if(!o)return null;return {observedAt:o.observedAt,lapi:o.engine?.lapi,alertCount:Array.isArray(o.alerts)?o.alerts.length:null,
  sources:sources.map(s=>({type:s.type,reads:counter(o,'acquisition','file:'+s.containerPath,'reads'),parsed:counter(o,'acquisition','file:'+s.containerPath,'parsed'),parser:counter(o,'parsers',specs[s.type as 'ssh'|'nginx'].parser,'parsed'),pour:counter(o,'scenarios',specs[s.type as 'ssh'|'nginx'].scenario,'pour'),overflow:counter(o,'scenarios',specs[s.type as 'ssh'|'nginx'].scenario,'overflow')})),
  testAlerts:(o.alerts||[]).filter((a:any)=>Object.values(specs).some(s=>s.ip===a.source)).slice(0,4).map((a:any)=>({id:a.id,scenario:a.scenario,source:a.source,createdAt:a.createdAt,eventCount:a.eventCount}))};
}
export function assertions(before:any,after:any,sources:any[],attackStartedAt:string){
 requireSafe(after?.engine?.lapi&&after.metrics&&Array.isArray(after.alerts)&&!after.window?.truncated,'OBSERVATION');
 const details=[];for(const s of sources){const spec=specs[s.type as 'ssh'|'nginx'],key='file:'+s.containerPath;
  const reads=counter(after,'acquisition',key,'reads')-counter(before,'acquisition',key,'reads'),parsed=counter(after,'acquisition',key,'parsed')-counter(before,'acquisition',key,'parsed');
  requireSafe(reads>=spec.count&&parsed>=spec.count,'ACQUISITION_DELTA');requireSafe(counter(after,'parsers',spec.parser,'parsed')-counter(before,'parsers',spec.parser,'parsed')>0,'PARSER_DELTA');
  requireSafe(counter(after,'scenarios',spec.scenario,'pour')-counter(before,'scenarios',spec.scenario,'pour')>=spec.count,'SCENARIO_DELTA');requireSafe(counter(after,'scenarios',spec.scenario,'overflow')-counter(before,'scenarios',spec.scenario,'overflow')>=1,'OVERFLOW_DELTA');
  const a=after.alerts.find((a:any)=>a.source===spec.ip&&a.scenario===spec.scenario&&!before.alerts.some((b:any)=>b.id===a.id));requireSafe(a,'FRESH_ALERT');
  requireSafe(Number.isFinite(Date.parse(a.createdAt))&&Date.parse(a.createdAt)>=Date.parse(attackStartedAt)-1000&&Date.parse(a.createdAt)<=Date.parse(after.observedAt)+5000,'ALERT_TIME');
  requireSafe(a.events?.some((e:any)=>e.meta?.datasource_path===s.containerPath)&&a.eventCount>0,'ALERT_SOURCE');details.push({type:s.type,sourceId:s.id,submitted:spec.count,readsDelta:reads,parsedDelta:parsed,parser:spec.parser,scenario:spec.scenario,alertId:a.id,eventCount:a.eventCount,sourceIp:spec.ip,createdAt:a.createdAt,decisions:a.decisions});
 }return details;
}
export interface HarnessPorts{
 verify:()=>Promise<any>;preserve:()=>Promise<any>;checkPreserved:(value:any)=>Promise<void>;acquire:(sources:any[])=>Promise<any>;
 observe:()=>Promise<any>;engine:()=>Promise<void>;view:()=>Promise<any>;marker:(s:any)=>Promise<void>;checkpoint:(s:any)=>Promise<void>;
 artifact:(name:string,value:any)=>Promise<void>;failure:(s:any)=>Promise<void>;emit:(s:any)=>void;pause:()=>Promise<void>;now:()=>Date;
}
export async function runHarness(p:HarnessPorts,budget=new Budget()){
 const state:any={phase:'VERIFY',target:TARGET.id,markerCreated:false,writeIntents:[],bytes:{ssh:0,nginx:0},warmupCounts:{ssh:0,nginx:0},lastObservation:null,preservation:'NOT_CHECKED',failureEvidenceSaved:false};
 let leases:any={},footprint:any,sources:any[]=[],result:any;
 const progress=()=>{try{p.emit(JSON.parse(encoded(state,16384).toString()))}catch{}};
 const checkpoint=async()=>{budget.check();await p.checkpoint(state);budget.check();progress()};
 const observe=async()=>{const value=await budget.read(p.observe);requireSafe(value.metrics&&Array.isArray(value.alerts),'METRICS_REQUIRED');state.lastObservation=observationSummary(value,sources);progress();return value};
 const append=async(s:any,warmup:boolean)=>{
  budget.check();await budget.read(p.engine);const type=s.type as 'ssh'|'nginx',text=payload(type,warmup,p.now());
  state.phase=warmup?'WARMUP_WRITE':'ATTACK_WRITE';const intent:any={type,kind:warmup?'warmup':'attack',bytes:Buffer.byteLength(text),sha256:hash(text),status:'PENDING'};state.writeIntents.push(intent);
  try{await checkpoint()}catch(e){intent.status='NOT_STARTED';throw e}
  const attempted=leases[type].attemptedBytes,written=leases[type].writtenBytes;
  try{await leases[type].append(text,budget);intent.status='COMMITTED'}catch(e){intent.status=leases[type].attemptedBytes>attempted?'UNCERTAIN':'FAILED_BEFORE_WRITE';throw e}finally{state.bytes[type]=leases[type].writtenBytes;intent.bytesWritten=leases[type].writtenBytes-written}
  if(warmup)state.warmupCounts[type]++;await checkpoint();
 };
 try{
  const verified=await budget.read(p.verify);sources=verified.sources;requireSafe(sources.length===2&&sources.some(s=>s.type==='ssh')&&sources.some(s=>s.type==='nginx'),'SOURCE_TYPES');
  footprint=await budget.read(p.preserve);leases=await p.acquire(sources);budget.check();
  state.phase='READINESS';let initial:any=null;
  for(let n=0;n<90;n++){budget.check();try{initial=await observe();if(initial.engine?.lapi&&Object.values(specs).every(s=>initial.scenarios?.includes(s.scenario)))break}catch(e){if(e instanceof IngestionFault&&e.code==='DEADLINE')throw e;state.readErrors=(state.readErrors||0)+1}await budget.read(p.pause)}
  requireSafe(initial?.engine?.lapi&&Object.values(specs).every(s=>initial.scenarios?.includes(s.scenario)),'READINESS');requireSafe(initial.alerts.length===0&&!initial.window?.truncated,'NONEMPTY_ALERT_BASELINE');
  const ready=await budget.read(p.view);requireSafe(ready.sources?.length===2&&ready.sources.every((s:any)=>s.status==='APPLIED'),'SOURCE_NOT_APPLIED');
  for(const s of sources)await leases[s.type].verify();budget.check();await p.marker({containerId:TARGET.id,installationId:TARGET.installation,at:p.now().toISOString()});state.markerCreated=true;
  await checkpoint();await p.artifact('prewarmup-observation.json',initial);budget.check();
  let before=initial;
  for(let n=0;n<15;n++){
   for(const s of sources)if(counter(before,'acquisition','file:'+s.containerPath,'reads')<=0||counter(before,'acquisition','file:'+s.containerPath,'parsed')<=0)await append(s,true);
   await budget.read(p.pause);before=await observe();if(sources.every(s=>counter(before,'acquisition','file:'+s.containerPath,'reads')>0&&counter(before,'acquisition','file:'+s.containerPath,'parsed')>0))break;
  }
  requireSafe(sources.every(s=>counter(before,'acquisition','file:'+s.containerPath,'reads')>0&&counter(before,'acquisition','file:'+s.containerPath,'parsed')>0),'TAIL_NOT_OBSERVED');
  requireSafe(!before.alerts.some((a:any)=>Object.values(specs).some(s=>s.ip===a.source)),'TEST_IP_BASELINE');await p.artifact('before-observation.json',before);budget.check();
  state.attackStartedAt=p.now().toISOString();for(const s of sources)await append(s,false);
  state.phase='ASSERTIONS';let after:any=null,details:any=null,lastAssertion='ASSERTION';
  for(let n=0;n<45;n++){await budget.read(p.pause);after=await observe();try{details=assertions(before,after,sources,state.attackStartedAt);break}catch(e){lastAssertion=failureCode(e)}}
  requireSafe(details,lastAssertion);await p.artifact('after-observation.json',after);budget.check();
  const view=await budget.read(p.view);requireSafe(view.sources?.length===2&&view.sources.every((s:any)=>s.status==='OBSERVED'),'MANAGER_SOURCE_STATE');await p.artifact('source-observation.json',view);budget.check();
  await budget.read(p.engine);for(const lease of Object.values(leases) as any[])await lease.verify();budget.check();await budget.read(()=>p.checkPreserved(footprint));state.preservation='VERIFIED';state.phase='COMPLETE';await checkpoint();
  await p.artifact('adapter-verified.json',{binding:'verified by live adapter'});budget.check();
  await p.artifact('ingestion-results.json',{at:p.now().toISOString(),target:TARGET.id,details,warmupCounts:state.warmupCounts,bytes:state.bytes,preservation:state.preservation,enforcement:'NOT ENABLED OR TESTED'});budget.check();
  result={ok:true,details,state};
 }catch(e){
  state.errorCode=failureCode(e);state.failedPhase=state.phase;state.phase='FAILED';
  for(const[type,lease]of Object.entries(leases) as any)state.bytes[type]=lease.writtenBytes;
  if(footprint)try{budget.check();await budget.read(()=>p.checkPreserved(footprint));state.preservation='VERIFIED'}catch{state.preservation='UNVERIFIED_AFTER_FAILURE'}
  try{await p.failure(state);state.failureEvidenceSaved=true}catch{state.failureEvidenceSaved=false;state.evidenceErrorCode='EVIDENCE_IO'}
  progress();result={ok:false,errorCode:state.errorCode,state};
 }finally{
  for(const lease of Object.values(leases) as any[])try{await lease.close()}catch{state.closeFailure=true}
  if(state.closeFailure){state.phase='FAILED';state.errorCode='HANDLE_CLOSE';try{await p.failure(state);state.failureEvidenceSaved=true}catch{state.failureEvidenceSaved=false}result={ok:false,errorCode:'HANDLE_CLOSE',state}}
 }
 try{p.emit(result)}catch{}return result;
}
// Creates and holds only its own private diagnostic files; never removes anything.
export class EvidenceJournal{
 journal:any;failureSlot:any;records=0;
 constructor(journal:any,failureSlot:any){this.journal=journal;this.failureSlot=failureSlot}
 async checkpoint(state:any){try{requireSafe(++this.records<=128,'EVIDENCE_BOUND');const bytes=encoded(state,16384);await this.journal.writeFile(bytes);await this.journal.sync()}catch(e){if(e instanceof IngestionFault)throw e;throw new IngestionFault('EVIDENCE_IO')}}
 async failure(state:any){const {failureEvidenceSaved,...rest}=state;const bytes=encoded({status:'FAILED',...rest},60000),slot=Buffer.alloc(65536,32);bytes.copy(slot);let offset=0;while(offset<slot.length){const r=await this.failureSlot.write(slot,offset,slot.length-offset,offset);requireSafe(r.bytesWritten>0,'EVIDENCE_IO');offset+=r.bytesWritten}await this.failureSlot.sync()}
 async close(){await Promise.allSettled([this.journal.close(),this.failureSlot.close()])}
}
async function exclusive(path:string,value:any){await unlinkedPath(TARGET.qa,undefined,true);const h=await fs.open(path,'wx',0o600);try{const opened=await h.stat({bigint:true}),visible=await unlinkedPath(path);requireSafe(opened.isFile()&&opened.nlink===1n&&opened.ino===visible.ino&&opened.dev===visible.dev,'EVIDENCE_IO');await h.writeFile(encoded(value));await h.sync()}finally{await h.close()}}
async function createEvidence(){
 await unlinkedPath(TARGET.qa,undefined,true);for(const name of previousNames){try{await fs.lstat(join(TARGET.qa,name));throw new IngestionFault('REPLAY')}catch(e:any){if(e.code!=='ENOENT')throw e}}
 const dir=join(TARGET.qa,'ingestion-evidence');await fs.mkdir(dir,{mode:0o700});await unlinkedPath(dir,undefined,true);
 const journal=await fs.open(join(dir,'journal.ndjson'),'wx',0o600);let slot:any;
 try{slot=await fs.open(join(dir,'failure.json'),'wx+',0o600);const initial=Buffer.alloc(65536,32);encoded({status:'ARMED',target:TARGET.id}).copy(initial);await slot.writeFile(initial);await slot.sync();return new EvidenceJournal(journal,slot)}catch(e){await journal.close();if(slot)await slot.close();throw e}
}
async function livePorts(budget:Budget,evidence:EvidenceJournal):Promise<HarnessPorts>{
 const read=async(args:string[])=>{requireSafe(dockerReadAllowed(args),'DOCKER_OPERATION_DENIED');const timeout=Math.min(5000,budget.remaining());return new Promise<string>((done,reject)=>execFile('docker',args,{timeout,signal:budget.signal,maxBuffer:2*1024*1024,encoding:'utf8',shell:false,windowsHide:true,env:{...process.env,DOCKER_HOST:undefined,DOCKER_CONTEXT:undefined}},(e,out)=>e?reject(new IngestionFault('DOCKER_READ')):done(out)))};
 const docker=(args:string[])=>read(['--context','desktop-linux',...args]).then(JSON.parse);
 let bundle:any,adapter:CrowdSec,store:Sources,startedAt:string;
 const preserve=async()=>{const files:any={};for(const path of CS01_FILES)files[path]=hash(await readBounded(join(ROOT,path),2*1024*1024));const old=await docker(['container','inspect',...OLD_IDS]);
  const oldState=old.map((c:any)=>({id:c.Id,name:c.Name,image:c.Image,status:c.State.Status,startedAt:c.State.StartedAt,pid:c.State.Pid,restartCount:c.RestartCount,configHash:digest(c.Config),hostConfigHash:digest(c.HostConfig),mounts:[...c.Mounts].sort((a,b)=>a.Destination.localeCompare(b.Destination)),networks:c.NetworkSettings.Networks}));requireSafe(oldState.length===2&&oldState.every((c:any,i:number)=>c.id===OLD_IDS[i]),'PROTECTED_IDENTITY');return {files,oldHash:digest(oldState)};
 };
 return {
  async verify(){
   await unlinkedPath(TARGET.qa,undefined,true);const plan=join(TARGET.qa,'sources/plans',TARGET.plan),raw=await readBounded(join(plan,'compose.json')),rawManifest=await readBounded(join(plan,'manifest.json'));
   bundle={adapter:await jsonFile(join(TARGET.qa,'adapter.json')),registration:await jsonFile(join(TARGET.qa,'registration.json')),preflight:await jsonFile(join(TARGET.qa,'create-preflight.json')),created:await jsonFile(join(TARGET.qa,'create-verification.json')),manifest:JSON.parse(rawManifest.toString('utf8')),manifestHash:hash(rawManifest),registry:await jsonFile(join(TARGET.qa,'sources/sources.json')),compose:JSON.parse(raw.toString('utf8')),composeHash:hash(raw),actualRootHash:hash(process.platform==='win32'?TARGET.qa.toLowerCase():TARGET.qa)};
   Object.assign(bundle,validateBundle(bundle));
   for(const s of bundle.sources){const file=join(plan,'guard-'+s.id+'.yaml');requireSafe((await readBounded(file,2048)).toString('utf8')===acquisition(s),'ACQUISITION_TEMPLATE');requireSafe(Date.parse(bundle.created.at)>=Number((await fs.lstat(file)).mtimeMs),'ACQUISITION_CHANGED')}
   adapter=new CrowdSec(bundle.config,read);store=new Sources(join(TARGET.qa,'sources'),adapter);const c=await adapter.owned();startedAt=verifyEngine(c,bundle);requireSafe(await docker(['exec',TARGET.id,'cscli','config','show','--key','Config.API.Server.OnlineClient','-o','json'])===null,'CAPI_ENABLED');return {sources:bundle.sources};
  },preserve,async checkPreserved(before){requireSafe(digest(await preserve())===digest(before),'PRESERVATION')},
  async acquire(sources){const leases:any={};try{for(const s of sources){budget.check();leases[s.type]=await VerifiedLog.acquire(s)}return leases}catch(e){await Promise.allSettled(Object.values(leases).map((l:any)=>l.close()));throw e}},
  async engine(){verifyEngine(await adapter.owned(),bundle,startedAt)},async observe(){adapter.cached=null;return adapter.snapshot()},async view(){return store.list()},
  marker:state=>exclusive(join(TARGET.qa,'append-started.json'),state),checkpoint:state=>evidence.checkpoint(state),failure:state=>evidence.failure(state),
  async artifact(name,value){requireSafe(ARTIFACTS.has(name),'EVIDENCE_PATH');await exclusive(join(TARGET.qa,name),name==='adapter-verified.json'?bundle.config:value)},
  emit(state){if(process.send)process.send({type:'status',value:JSON.parse(encoded(state,65536).toString())},()=>{})},
  pause:()=>new Promise(done=>setTimeout(done,Math.min(1000,budget.remaining()))),now:()=>new Date()
 };
}
export async function supervise(makeChild:()=>any,ms=RUN_LIMIT_MS,grace=TERMINATION_GRACE_MS){
 requireSafe(ms>0&&ms<=RUN_LIMIT_MS&&grace>0&&grace<=TERMINATION_GRACE_MS,'DEADLINE_CONFIG');const child=makeChild();let terminationCode:string|null=null,last:any=null,outputBytes=0;let timer:any,killTimer:any;
 const result=await new Promise<any>(resolveDone=>{
  let settled=false;const finish=(value:any)=>{if(settled)return;settled=true;clearTimeout(timer);clearTimeout(killTimer);resolveDone(value)};
  const terminate=(code:string)=>{if(terminationCode||settled)return;terminationCode=code;try{if(child.connected&&typeof child.send==='function')child.send({type:'cancel'},()=>{});else child.kill('SIGTERM')}catch{try{child.kill('SIGTERM')}catch{}}killTimer=setTimeout(()=>{try{child.kill('SIGKILL')}catch{}finish({ok:false,errorCode:terminationCode,last,workerExitUnconfirmed:true,inFlightWriteMayHaveCommitted:true})},grace)};
  child.on('message',(m:any)=>{try{requireSafe(encoded(m,65536).length<=65536,'EVIDENCE_BOUND');if(m?.type==='status')last=m.value}catch{terminate('WORKER_OUTPUT_BOUND')}});
  const drain=(chunk:any)=>{outputBytes+=chunk.length;if(outputBytes>65536)terminate('WORKER_OUTPUT_BOUND')};child.stdout?.on('data',drain);child.stderr?.on('data',drain);
  child.once('error',()=>child.pid?terminate('WORKER_FAILED'):finish({ok:false,errorCode:'WORKER_FAILED',last}));
  child.once('close',(code:number)=>finish(terminationCode?{ok:false,errorCode:terminationCode,last,inFlightWriteMayHaveCommitted:!!last?.writeIntents?.some((i:any)=>i.status==='PENDING'||i.status==='UNCERTAIN')}:code===0&&last?.ok===true?last:{ok:false,errorCode:last?.errorCode||'WORKER_FAILED',last}));
  timer=setTimeout(()=>terminate('WORKER_TIMEOUT'),ms);
 });return result;
}
async function worker(){let evidence:EvidenceJournal|undefined;const budget=new Budget(),cancel=(message:any)=>{if(message?.type==='cancel')budget.abort()},disconnected=()=>budget.abort();process.on('message',cancel);process.once('disconnect',disconnected);
 try{parseTarget(process.argv.slice(2));evidence=await createEvidence();budget.check();const p=await livePorts(budget,evidence),result=await runHarness(p,budget);process.exitCode=result.ok?0:1}
 catch(e){const failure={ok:false,errorCode:failureCode(e),phase:'BOOTSTRAP',target:TARGET.id};try{await evidence?.failure(failure)}catch{}try{process.send?.({type:'status',value:failure},()=>{})}catch{}process.stderr.write(JSON.stringify(failure)+'\n');process.exitCode=1}
 finally{process.removeListener('message',cancel);process.removeListener('disconnect',disconnected);await evidence?.close()}
}
async function main(){
 let child:any,hardExit:any;
 try{parseTarget(process.argv.slice(2));if(process.send){await worker();return}
  hardExit=setTimeout(()=>{if(child&&child.exitCode===null&&child.signalCode===null)try{child.kill('SIGKILL')}catch{}process.stderr.write(JSON.stringify({ok:false,errorCode:'SUPERVISOR_DEADLINE',target:TARGET.id,inFlightWriteMayHaveCommitted:true,automaticReplay:false})+'\n');process.exit(1)},RUN_LIMIT_MS+TERMINATION_GRACE_MS+REPORT_GRACE_MS);hardExit.unref();
  const file=fileURLToPath(import.meta.url),result=await supervise(()=>{child=fork(file,process.argv.slice(2),{silent:true,windowsHide:true,env:{...process.env,NODE_OPTIONS:undefined,NODE_PATH:undefined}});return child});
  if(!result.ok){try{await exclusive(join(TARGET.qa,'ingestion-supervisor-failure.json'),result)}catch{result.supervisorEvidenceSaved=false}process.stderr.write(JSON.stringify(result)+'\n');process.exitCode=1}else console.log(JSON.stringify(result));
 }catch(e){process.stderr.write(JSON.stringify({ok:false,errorCode:failureCode(e),target:TARGET.id})+'\n');process.exitCode=1}finally{clearTimeout(hardExit)}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main();
