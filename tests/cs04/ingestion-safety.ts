// No top-level I/O. Importing these guards never opens logs or contacts Docker.
import {constants} from 'node:fs';
import * as fs from 'node:fs/promises';
import {resolve,join,dirname,parse,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';

export const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
export const TARGET=Object.freeze({
 qa:join(ROOT,'runtime/qa-cs04-20261024/integration-e3db1ae7'),
 id:'eab16c3f3d6b699854c96103b1482dfa4fe946bc2301626b0614db1416e497b4',
 installation:'qa-cs04-b3974d67',project:'crowdsec-guard-qa-cs04-b3974d67',
 name:'crowdsec-guard-qa-cs04-b3974d67-engine',
 imageId:'sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a',
 image:'crowdsecurity/crowdsec:v1.8.1@sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a',
 composeHash:'aad4462e26ff602fe54f07b634ae76b6916ce2a5954024944e67f2b78cf703f0',
 manifestHash:'c83bd4d4bf32b50d571b98cb4779ec103438debc9c100679b7ecfea01b0decbf',
 plan:'plan-6b5964849219b85c',
 sources:Object.freeze({ssh:'src-a80e0225f99d3852',nginx:'src-781118fded87f039'})
});
export const RUN_LIMIT_MS=180000,TERMINATION_GRACE_MS=3000,REPORT_GRACE_MS=5000;
export class IngestionFault extends Error{code:string;constructor(code:string){super(code);this.code=code}}
export function requireSafe(value:any,code:string):asserts value{if(!value)throw new IngestionFault(code)}
export const hash=(value:string|Buffer)=>createHash('sha256').update(value).digest('hex');
export const pathKey=(value:string)=>process.platform==='win32'?resolve(value).toLowerCase():resolve(value);
export const fileIdentity=(s:any)=>`${s.dev}:${s.ino}`;
export function parseTarget(args:string[]){
 requireSafe(args.length===4&&args[0]==='--qa'&&args[2]==='--container-id','ARGUMENTS');
 requireSafe(!args[1].split(/[\\/]/).includes('..')&&pathKey(args[1])===pathKey(TARGET.qa),'QA_ROOT');
 requireSafe(args[3]===TARGET.id,'CONTAINER_ID');return TARGET;
}
export class Budget{
 end:number;clock:()=>number;controller=new AbortController();
 constructor(ms=RUN_LIMIT_MS,clock=()=>performance.now()){requireSafe(ms>0&&ms<=RUN_LIMIT_MS,'DEADLINE_CONFIG');this.clock=clock;this.end=clock()+ms}
 get signal(){return this.controller.signal}
 abort(){this.controller.abort()}
 check(){requireSafe(!this.signal.aborted&&this.clock()<this.end,'DEADLINE')}
 remaining(){this.check();return Math.max(1,Math.floor(this.end-this.clock()))}
 // Race READ-ONLY operations only. Log writes are awaited/drained, never detached.
 async read<T>(operation:()=>Promise<T>):Promise<T>{this.check();let timer:any,onAbort:any;try{return await Promise.race([Promise.resolve().then(operation),new Promise<never>((_,reject)=>{onAbort=()=>reject(new IngestionFault('DEADLINE'));this.signal.addEventListener('abort',onAbort,{once:true});timer=setTimeout(()=>{this.abort();reject(new IngestionFault('DEADLINE'))},this.remaining())})])}finally{clearTimeout(timer);if(onAbort)this.signal.removeEventListener('abort',onAbort)}}
}
export type FileIO={lstat:typeof fs.lstat;realpath:typeof fs.realpath;open:typeof fs.open};
export const nativeIO:FileIO={lstat:fs.lstat,realpath:fs.realpath,open:fs.open};
export async function unlinkedPath(path:string,io:FileIO=nativeIO,directory=false){
 const full=resolve(path);let current=parse(full).root;
 for(const part of full.slice(current.length).split(sep).filter(Boolean)){
  current=join(current,part);const s=await io.lstat(current,{bigint:true});
  requireSafe(!s.isSymbolicLink(),'PATH_LINK');
  requireSafe(current===full?(directory?s.isDirectory():s.isFile()):s.isDirectory(),'PATH_KIND');
 }
 requireSafe(pathKey(await io.realpath(full))===pathKey(full),'PATH_ALIAS');return io.lstat(full,{bigint:true});
}
export async function readBounded(path:string,max=128*1024){
 const original=await unlinkedPath(path);requireSafe(original.size<=BigInt(max)&&original.nlink===1n,'CONTROL_FILE_BOUND');
 const h=await fs.open(path,constants.O_RDONLY|(process.platform==='win32'?0:constants.O_NOFOLLOW));
 try{const opened=await h.stat({bigint:true});requireSafe(opened.isFile()&&fileIdentity(opened)===fileIdentity(original)&&opened.nlink===1n&&opened.size<=BigInt(max),'CONTROL_FILE_IDENTITY');
  const buffer=Buffer.alloc(Number(opened.size)+1);let used=0;
  while(used<buffer.length){const r=await h.read(buffer,used,buffer.length-used,used);if(!r.bytesRead)break;used+=r.bytesRead}
  requireSafe(used<=max&&used===Number(opened.size),'CONTROL_FILE_CHANGED');
  const after=await unlinkedPath(path);requireSafe(fileIdentity(after)===fileIdentity(opened)&&after.size===opened.size,'CONTROL_FILE_CHANGED');return buffer.subarray(0,used);
 }finally{await h.close()}
}
export async function jsonFile(path:string,max=128*1024){try{return JSON.parse((await readBounded(path,max)).toString('utf8'))}catch(e){if(e instanceof IngestionFault)throw e;throw new IngestionFault('CONTROL_JSON')}}
export function validateBundle(b:any){
 const a=b.adapter,r=b.registration,p=b.preflight,c=b.created,m=b.manifest,db=b.registry,s=b.compose?.services?.crowdsec;
 requireSafe(a?.context==='desktop-linux'&&a.installationId===TARGET.installation&&[TARGET.id,'0'.repeat(64)].includes(a.containerId),'ADAPTER_IDENTITY');
 requireSafe(/^[a-f0-9]{32}$/.test(a.owner)&&/^[a-f0-9]{64}$/.test(a.rootHash),'OWNERSHIP_FORMAT');
 requireSafe(a.rootHash===b.actualRootHash&&r?.format_version===1&&r.installation_id===TARGET.installation&&r.docker_context==='desktop-linux'&&r.owner_token===a.owner&&r.root_hash===a.rootHash,'REGISTRATION');
 requireSafe(p?.installationId===TARGET.installation&&p.project===TARGET.project&&p.composeHash===TARGET.composeHash&&p.imageId===TARGET.imageId,'APPROVED_PLAN');
 requireSafe(c?.verdict==='CREATE PASS'&&c.installationId===TARGET.installation&&c.project===TARGET.project&&c.container?.id===TARGET.id&&c.container.name===TARGET.name&&c.container.ownershipLabelsVerified===true,'CREATE_IDENTITY');
 requireSafe(b.composeHash===TARGET.composeHash&&b.compose.name===TARGET.project&&Object.keys(b.compose.services).length===1&&s?.container_name===TARGET.name&&s.image===TARGET.image,'COMPOSE_IDENTITY');
 const identity={installationId:TARGET.installation,rootHash:a.rootHash,ownerHash:hash(a.owner)};
 requireSafe(b.manifestHash===TARGET.manifestHash,'APPROVED_FILE_IDENTITIES');
 requireSafe(JSON.stringify(m?.identity)===JSON.stringify(identity)&&JSON.stringify(db?.identity)===JSON.stringify(identity),'REGISTRY_IDENTITY');
 const labels={'io.crowdsec-guard.installation':TARGET.installation,'io.crowdsec-guard.owner':a.owner,'io.crowdsec-guard.root':a.rootHash,'io.crowdsec-guard.schema':'1'};
 requireSafe(Object.entries(labels).every(([k,v])=>s.labels?.[k]===v),'COMPOSE_OWNERSHIP');
 requireSafe(db.version===1&&db.sources?.length===2&&m.sources?.length===2,'SOURCE_COUNT');
 const sources=[];
 for(const type of ['ssh','nginx'] as const){const id=TARGET.sources[type],src=db.sources.find((x:any)=>x.type===type),entry=m.sources.find((x:any)=>x.type===type);
  requireSafe(src&&entry&&src.id===id&&entry.id===id&&src.enabled===true&&!src.removed,'SOURCE_IDENTITY');
  requireSafe(src.path===join(TARGET.qa,type+'.log')&&entry.path===src.path&&src.containerPath===`/guard/sources/${id}.log`&&entry.containerPath===src.containerPath,'SOURCE_PATH');
  requireSafe(typeof entry.fileIdentity==='string'&&/^\d+:[1-9]\d*$/.test(entry.fileIdentity),'SOURCE_FILE_IDENTITY');sources.push({...src,fileIdentity:entry.fileIdentity});
 }
 return {config:{...a,containerId:TARGET.id},sources,labels};
}
export function verifyEngine(c:any,b:any,startedAt?:string){
 const s=b.compose.services.crowdsec,h=c?.HostConfig,labels=b.labels;
 requireSafe(c?.Id===TARGET.id&&c.Name==='/'+TARGET.name&&c.State?.Running,'ENGINE_IDENTITY');
 requireSafe(c.Config?.Image===TARGET.image&&c.Image===TARGET.imageId&&Object.entries(labels).every(([k,v])=>c.Config.Labels?.[k]===v)&&c.Config.Labels['com.docker.compose.project']===TARGET.project&&c.Config.Labels['com.docker.compose.service']==='crowdsec','ENGINE_OWNERSHIP');
 requireSafe(c.RestartCount===0&&(!startedAt||c.State.StartedAt===startedAt),'ENGINE_RESTART');
 requireSafe(h&&!h.Privileged&&!h.CapAdd?.length&&!h.CapDrop?.length&&h.SecurityOpt?.length===1&&h.SecurityOpt[0]==='no-new-privileges:true','ENGINE_PRIVILEGE');
 requireSafe(!h.PidMode&&h.IpcMode==='private'&&!h.UTSMode&&!h.UsernsMode&&!h.Devices?.length&&!h.DeviceRequests?.length&&!h.VolumesFrom?.length,'ENGINE_NAMESPACE');
 requireSafe(h.NetworkMode===TARGET.project+'-guardnet'&&Object.keys(c.NetworkSettings?.Networks||{}).length===1&&c.NetworkSettings.Networks[h.NetworkMode],'ENGINE_NETWORK');
 requireSafe(!Object.keys(h.PortBindings||{}).length&&!h.PublishAllPorts&&Object.values(c.NetworkSettings?.Ports||{}).every((v:any)=>v===null||Array.isArray(v)&&!v.length),'ENGINE_PORTS');
 requireSafe(h.RestartPolicy?.Name==='no'&&!h.AutoRemove&&h.Memory===1073741824&&h.PidsLimit===256,'ENGINE_LIMITS');
 requireSafe(!h.DeviceCgroupRules?.length&&!h.Links?.length&&h.ReadonlyRootfs===false&&h.LogConfig?.Type==='json-file'&&h.LogConfig.Config?.['max-size']==='10m'&&h.LogConfig.Config?.['max-file']==='3','ENGINE_HOST_SETTINGS');
 requireSafe(Object.entries(s.environment).every(([k,v])=>c.Config.Env?.includes(k+'='+v)),'ENGINE_ENVIRONMENT');
 requireSafe(c.Mounts?.length===6&&!c.Mounts.some((m:any)=>String(m.Source).includes('docker.sock')||String(m.Destination).includes('docker.sock')),'ENGINE_MOUNTS');
 for(const m of s.volumes){const actual=c.Mounts.find((x:any)=>x.Destination===m.target);
  requireSafe(actual&&(m.type==='bind'?actual.Type==='bind'&&actual.RW===false&&pathKey(actual.Source)===pathKey(m.source):actual.Type==='volume'&&actual.Name===b.compose.volumes[m.source].name),'ENGINE_MOUNT_IDENTITY');
 }
 return c.State.StartedAt;
}
export class VerifiedLog{
 path:string;expected:string;handle:any;io:FileIO;size=0n;attemptedBytes=0;writtenBytes=0;closed=false;failed=false;
 constructor(path:string,expected:string,handle:any,io:FileIO){this.path=path;this.expected=expected;this.handle=handle;this.io=io}
 static async acquire(source:any,io:FileIO=nativeIO){
  requireSafe(['ssh','nginx'].includes(source.type)&&source.path===join(TARGET.qa,source.type+'.log'),'LOG_PATH');
  const initial=await unlinkedPath(source.path,io);requireSafe(initial.size===0n&&initial.nlink===1n&&fileIdentity(initial)===source.fileIdentity,'LOG_INITIAL_IDENTITY');
  // No O_CREAT/O_TRUNC. Windows follows no pathname after the handle is validated;
  // POSIX also rejects a final symlink at open via O_NOFOLLOW.
  const h=await io.open(source.path,constants.O_WRONLY|constants.O_APPEND|(process.platform==='win32'?0:constants.O_NOFOLLOW));
  const lease=new VerifiedLog(source.path,source.fileIdentity,h,io);try{await lease.verify();return lease}catch(e){await h.close();throw e}
 }
 async verify(){
  requireSafe(!this.closed,'LOG_CLOSED');const opened=await this.handle.stat({bigint:true}),path=await unlinkedPath(this.path,this.io);
  requireSafe(opened.isFile()&&opened.ino>0n&&opened.nlink===1n&&path.nlink===1n&&fileIdentity(opened)===this.expected&&fileIdentity(path)===this.expected,'LOG_REPLACED');
  requireSafe(opened.size===this.size&&path.size===this.size,'LOG_EXTERNAL_WRITE');
 }
 async append(text:string,budget:Budget){
  requireSafe(!this.failed,'LOG_POISONED');
  try{
  budget.check();const bytes=Buffer.from(text,'utf8');requireSafe(bytes.length>0&&bytes.length<=16384&&this.attemptedBytes+bytes.length<=32768,'LOG_WRITE_BOUND');
  await this.verify();budget.check();this.attemptedBytes+=bytes.length;
  // Only this retained, validated handle is written, never a reopened pathname.
  const result=await this.handle.write(bytes,0,bytes.length,null);this.writtenBytes+=result.bytesWritten;this.size+=BigInt(result.bytesWritten);
  requireSafe(result.bytesWritten===bytes.length,'PARTIAL_WRITE');await this.handle.sync();await this.verify();budget.check();
  }catch(e){this.failed=true;throw e}
 }
 async close(){if(!this.closed){this.closed=true;await this.handle.close()}}
}
export function failureCode(e:any){return e instanceof IngestionFault&&/^[A-Z_]{1,64}$/.test(e.code)?e.code:'INTERNAL_ERROR'}
