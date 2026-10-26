import {execFile} from 'node:child_process';
import {readFile,lstat} from 'node:fs/promises';
import {isIP} from 'node:net';
import type {Alert,Observation} from '../../packages/contracts/console.ts';
export class UpstreamError extends Error{status=503;constructor(message='CrowdSec unavailable or invalid response'){super(message)}}
export async function execute(args:string[],input?:string){return new Promise<string>((resolve,reject)=>{if(input!==undefined&&input.length>8192)return reject(new UpstreamError());const child=execFile('docker',args,{timeout:5000,maxBuffer:2*1024*1024,encoding:'utf8',windowsHide:true,shell:false,env:{...process.env,DOCKER_HOST:undefined,DOCKER_CONTEXT:undefined}},(error,out)=>{if(error)reject(new UpstreamError());else resolve(out)});if(input!==undefined){child.stdin?.on('error',()=>{});child.stdin?.end(input)}})}
const object=(x:any)=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const str=(x:any,max=256)=>{if(typeof x!=='string'||x.length>max)throw new UpstreamError('Invalid CrowdSec response');return x};
const date=(x:any)=>{const s=str(x,64);if(!Number.isFinite(Date.parse(s)))throw new UpstreamError('Invalid CrowdSec timestamp');return s};
const metaKeys=new Set(['datasource_path','datasource_type','log_type','service','source_ip','timestamp','http_path','http_status','http_verb','target_user','ASNNumber','IsoCode']);
export function alertRecord(a:any):Alert{
 if(!object(a)||!Number.isSafeInteger(a.id)||a.id<1||!object(a.source)||!Array.isArray(a.events)||!Number.isSafeInteger(a.events_count)||a.events_count<0)throw new UpstreamError('Invalid alert shape');
 const scope=str(a.source.scope,32),source=str(a.source.value,128);if(scope==='Ip'&&!isIP(source))throw new UpstreamError('Invalid source IP');
 const scenario=str(a.scenario,160);if(!/^[\w./:-]+$/.test(scenario))throw new UpstreamError('Invalid scenario');
 const events=a.events.slice(0,100).map((e:any)=>{if(!object(e)||!Array.isArray(e.meta))throw new UpstreamError('Invalid event');const meta:Record<string,string>={};for(const m of e.meta.slice(0,40)){if(object(m)&&metaKeys.has(m.key))meta[m.key]=str(m.value,1024)}return {timestamp:str(e.timestamp||'',128),meta}});
 return {id:a.id,scenario,source,scope,startedAt:date(a.start_at),stoppedAt:date(a.stop_at),createdAt:date(a.created_at),eventCount:Number.isSafeInteger(a.events_count)?a.events_count:events.length,scenarioVersion:typeof a.scenario_version==='string'?str(a.scenario_version,32):null,events,decisions:Array.isArray(a.decisions)?a.decisions.slice(0,20).map((d:any)=>({type:str(d.type,32),duration:typeof d.duration==='string'?str(d.duration,64):null})):[]};
}
function metricsRecord(m:any){if(!object(m)||!object(m.acquisition)||!object(m.parsers)||!object(m.scenarios))throw new UpstreamError('Unknown metrics schema');const result:any={};for(const kind of ['acquisition','parsers','scenarios']){result[kind]={};const entries=Object.entries(m[kind]);if(entries.length>500)throw new UpstreamError('Too many metric series');for(const[key,values]of entries){str(key,256);if(!object(values))throw new UpstreamError();const clean:any={};for(const[k,v]of Object.entries(values)){if(!/^[a-z_]+$/.test(k)||typeof v!=='number'||!Number.isFinite(v)||v<0)throw new UpstreamError('Invalid counter');clean[k]=v}result[kind][key]=clean}}return result}
export class CrowdSec{
 config:any;lastContainer:any=null;lastMetricDocument:any=null;run:typeof execute;flight:Promise<Observation>|null=null;cached:Observation|null=null;queue:Promise<any>=Promise.resolve();pending=0;
 constructor(config:any,run=execute){if(!config||!/^[a-zA-Z0-9_.-]{1,64}$/.test(config.context)||! /^[0-9a-f]{64}$/.test(config.containerId)||!config.owner||!config.rootHash||! /^qa-[a-z0-9-]+$/.test(config.installationId))throw Error('Explicit test installation configuration required');this.config=config;this.run=run}
 static async load(file:string){const info=await lstat(file);if(!info.isFile()||info.isSymbolicLink()||info.size>16384||(process.platform!=='win32'&&(info.mode&0o077)))throw Error('Adapter file must be a private regular file');return new CrowdSec(JSON.parse(await readFile(file,'utf8')))}
 call(args:string[],input?:string,notAfter?:number){if(this.pending>=8)return Promise.reject(new UpstreamError('Adapter busy'));const queued=Date.now();this.pending++;const pending=this.queue.then(()=>{if(notAfter!==undefined&&Date.now()>=notAfter)throw new UpstreamError('Approval expired before dispatch');if(Date.now()-queued>5000)throw new UpstreamError('Observation deadline exceeded');return this.run(['--context',this.config.context,...args],input)}).finally(()=>{this.pending--});this.queue=pending.catch(()=>{});return pending}
 async owned(){const contexts=JSON.parse(await this.call(['context','inspect',this.config.context]));const endpoint=contexts[0]?.Endpoints?.docker?.Host;if(typeof endpoint!=='string'||!(endpoint.startsWith('npipe:////./pipe/')||endpoint.startsWith('unix:///')))throw new UpstreamError('Remote context rejected');
  const data=JSON.parse(await this.call(['container','inspect',this.config.containerId]));if(!Array.isArray(data)||data.length!==1)throw new UpstreamError();const c=data[0],labels=c.Config?.Labels;const expected:any={'io.crowdsec-guard.installation':this.config.installationId,'io.crowdsec-guard.owner':this.config.owner,'io.crowdsec-guard.root':this.config.rootHash,'io.crowdsec-guard.schema':'1'};
  if(c.Id!==this.config.containerId||c.Name!=='/crowdsec-guard-'+this.config.installationId+'-engine'||!labels||Object.entries(expected).some(([k,v])=>labels[k]!==v)||c.HostConfig?.Privileged||c.Mounts?.some((m:any)=>m.Destination==='/var/run/docker.sock'))throw new UpstreamError('Resource ownership or isolation mismatch');this.lastContainer=c;return c;
 }
 async read(operation:'alerts'|'detail'|'metrics'|'scenarios',id?:number){const commands:any={alerts:['alerts','list','--limit','201','-o','json'],metrics:['metrics','show','-o','json'],scenarios:['scenarios','list','-o','json']};
  if(operation==='detail'){if(!Number.isSafeInteger(id)||Number(id)<1)throw new UpstreamError();commands.detail=['alerts','inspect',String(id),'--details','-o','json']}
  if(!Object.hasOwn(commands,operation))throw new UpstreamError('Operation not permitted');return JSON.parse(await this.call(['exec',this.config.containerId,'cscli',...commands[operation]]));
 }
 async detail(id:number){const c=await this.owned();if(!c.State?.Running)throw new UpstreamError('Engine stopped');const raw=await this.read('detail',id);const a=alertRecord(Array.isArray(raw)&&raw.length===1?raw[0]:raw);if(a.id!==id)throw new UpstreamError('Alert ID mismatch');return a}
 snapshot(){if(this.flight)return this.flight;if(this.cached&&Date.now()-Date.parse(this.cached.observedAt)<3000)return Promise.resolve(this.cached);
  this.flight=this.observe().then(v=>{this.cached=v;return v}).finally(()=>{this.flight=null});return this.flight;
 }
 async observe():Promise<Observation>{const c=await this.owned();const base:any={observedAt:new Date().toISOString(),engine:{state:c.State?.Running?'running':'stopped',lapi:false,freshness:'UNAVAILABLE'},alerts:null,window:{limit:200,truncated:false,description:'At most the latest 200 local alerts; CAPI alerts excluded.'},metrics:null,scenarios:null,warnings:[]};if(!c.State?.Running){base.warnings.push('Engine stopped. Stored alerts cannot be read until an authorized operator starts it.');return base}
  const raw=await this.read('alerts');if(!Array.isArray(raw)||raw.length>201)throw new UpstreamError('Unknown alerts schema');base.alerts=raw.slice(0,200).map(alertRecord);base.window.truncated=raw.length>200;base.engine.lapi=true;base.engine.freshness='LIVE';
  try{const rawMetrics=await this.read('metrics');base.metrics=metricsRecord(rawMetrics);this.lastMetricDocument=rawMetrics}catch{base.warnings.push('Metrics unavailable; source health is unknown.')}
  try{const s=await this.read('scenarios');if(!object(s)||!Array.isArray(s.scenarios)||s.scenarios.length>500)throw new UpstreamError();base.scenarios=s.scenarios.filter((x:any)=>x.status==='enabled').map((x:any)=>str(x.name,160))}catch{base.warnings.push('Installed scenario observation unavailable.')}
  return base;
 }
}
