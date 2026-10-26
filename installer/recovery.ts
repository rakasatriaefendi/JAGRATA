import {readFile,lstat,open,rename,mkdir,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {nonce,present,exclusive} from './state.ts';
import {sign,verify} from './control.ts';
import {inspectProcess,selfIdentity,sameProcess,type ProcessIdentity,type Inspection} from './process.ts';
import {windowsPrivacy,fail} from './platform.ts';
import {noLinks} from '../apps/manager/sources.ts';
const digest=(b:Buffer|string)=>createHash('sha256').update(b).digest('hex');
export function sealed(key:string,data:any){return {...data,seal:sign(key,data).proof}}
export function checkRecord(config:any,key:string,value:any){
 if(value?.id!==config.id||value.rootHash!==config.rootHash||!/^[a-f0-9]{48}$/.test(value.instance||''))throw Error('Ownership record mismatch');
 if(value.version!==2)throw Error('Legacy record lacks authenticated OS creation metadata');
 const {seal,...body}=value;verify(key,{payload:JSON.stringify(body),proof:seal});
 const i=value.osIdentity;
 if(!i||!['win32','linux'].includes(i.platform)||!Number.isSafeInteger(i.pid)||i.pid<1||!i.boot||!i.created||!i.executable||!i.owner||!/^[a-f0-9]{64}$/.test(i.commandHash))throw Error('Invalid OS process identity');
 if(value.pid!==undefined&&value.pid!==i.pid)throw Error('PID identity mismatch');
 return value;
}
export async function readLifecycle(state:string){
 const records:any={};for(const name of ['start.lock','process.json']){const path=join(state,name);if(!await present(path))continue;await noLinks(path);if(process.platform==='win32')await windowsPrivacy([path]);const h=await open(path,'r');try{const s=await h.stat({bigint:true});if(!s.isFile()||s.nlink!==1n||s.ino<=0n||s.size>16384n)throw Error('Invalid lifecycle file identity');const raw=await h.readFile();const again=await lstat(path,{bigint:true});if(s.ino!==again.ino||s.dev!==again.dev||digest(await readFile(path))!==digest(raw))throw Error('Lifecycle file replaced');records[name]={value:JSON.parse(raw.toString()),raw:raw.toString(),hash:digest(raw),ino:String(s.ino),dev:String(s.dev)}}finally{await h.close()}}
 return records;
}
export async function assess(config:any,key:string,records:any,self:ProcessIdentity,inspect:(pid:number)=>Promise<Inspection>=inspectProcess){
 const lock=records['start.lock']?.value,worker=records['process.json']?.value;
 if(!lock&&!worker)return {state:'EMPTY',reason:'No lifecycle records'};
 try{for(const r of [lock,worker].filter(Boolean))checkRecord(config,key,r);if(!lock||worker&&lock.instance!==worker.instance)throw Error('Incomplete or conflicting ownership');}catch{return {state:'RECOVERY_REQUIRED',reason:'Legacy, invalid or conflicting ownership record; preserve evidence and request reviewed operator recovery.'}}
 async function dead(i:ProcessIdentity){if(i.platform!==self.platform)return null;if(i.boot!==self.boot)return true;const observed=await inspect(i.pid);if(observed.state==='UNKNOWN'||observed.boot!==self.boot)return null;if(observed.state==='ABSENT')return true;const current=observed.identity;if(!current||current.pid!==i.pid||current.boot!==i.boot||current.platform!==i.platform)return null;if(current.created!==i.created)return true;return sameProcess(i,current)?false:null}
 const workerDead=worker?await dead(worker.osIdentity):undefined;
 if(workerDead===false)return {state:'LIVE',reason:'Exact OS process still exists; listener absence does not permit recovery'};
 if(workerDead===null)return {state:'RECOVERY_REQUIRED',reason:'Worker OS identity cannot be established'};
 const parentDead=await dead(lock.osIdentity);
 if(parentDead!==true)return {state:'RECOVERY_REQUIRED',reason:'Launcher is live or its OS identity is ambiguous'};
 if(!worker&&lock.osIdentity.boot===self.boot)return {state:'RECOVERY_REQUIRED',reason:'Launch may have produced an unrecorded worker; same-boot lock-only recovery is unsafe'};
 return {state:'ORPHAN',reason:worker?'Recorded launcher and worker conclusively ended':'Authenticated launch belongs to a previous OS boot'};
}
// Serialize every participating writer. An interrupted guard is intentionally NOT
// auto-deleted: operator review is required rather than recursively guessing ownership.
export async function withOperation<T>(state:string,config:any,key:string,action:()=>Promise<T>):Promise<T>{
 await noLinks(state,false);if(process.platform==='win32')await windowsPrivacy([state]);
 const path=join(state,'lifecycle-operation.lock'),instance=nonce();
 const own=sealed(key,{version:2,id:config.id,rootHash:config.rootHash,instance,osIdentity:await selfIdentity()});
 await exclusive(path,JSON.stringify(own)+'\n').catch(()=>fail('RECOVERY_REQUIRED: lifecycle operation already pending or interrupted; no stale lock was removed.'));
 const s=await lstat(path,{bigint:true}),raw=await readFile(path);
 if(!s.isFile()||s.ino<=0n||s.nlink!==1n)fail('RECOVERY_REQUIRED: operation lock filesystem identity unavailable; guard preserved.');
 try{return await action()}finally{await noLinks(path);const current=await lstat(path,{bigint:true});if(current.ino!==s.ino||current.dev!==s.dev||digest(await readFile(path))!==digest(raw))fail('RECOVERY_REQUIRED: operation lock replaced; preserved without deletion.');await unlink(path)}
}
export async function assertNoPending(state:string){if(await present(join(state,'recovery.pending.json')))fail('RECOVERY_REQUIRED: interrupted archive transaction; preserve pending evidence for operator review.')}
export async function archiveRecords(state:string,config:any,key:string,records:any,reason:string,io={rename},reservedId=nonce()){
 await assertNoPending(state);const archive=join(state,'lifecycle-evidence');
 if(!await present(archive)){await mkdir(archive,{mode:0o700});if(process.platform==='win32')await windowsPrivacy([archive],true)}
 await noLinks(archive,false);if(process.platform==='win32')await windowsPrivacy([archive]);
 if(!/^[a-f0-9]{48}$/.test(reservedId))throw Error('Invalid archive transaction identity');
 const id=reservedId,dir=join(archive,id);await mkdir(dir,{mode:0o700});
 const pending=join(state,'recovery.pending.json');
 await exclusive(pending,JSON.stringify({version:1,id:config.id,rootHash:config.rootHash,archive:id,reason,at:new Date().toISOString(),records})+'\n');
 for(const [name,record]of Object.entries(records) as [string,any][]){
  if(!['start.lock','process.json'].includes(name))throw Error('Invalid archive target');
  const path=join(state,name);await noLinks(path);const s=await lstat(path,{bigint:true});
  if(String(s.ino)!==record.ino||String(s.dev)!==record.dev||s.nlink!==1n||digest(await readFile(path))!==record.hash)fail('RECOVERY_REQUIRED: lifecycle record replaced; archive interrupted and evidence retained.');
  await exclusive(join(dir,name+'.snapshot'),record.raw);
  await io.rename(path,join(dir,name));
  const moved=await lstat(join(dir,name),{bigint:true});
  if(String(moved.ino)!==record.ino||digest(await readFile(join(dir,name)))!==record.hash)fail('RECOVERY_REQUIRED: archive identity changed; evidence retained, startup blocked.');
 }
 await io.rename(pending,join(dir,'transaction.json'));return {archive:id,reason};
}
export async function finalizeOwn(state:string,config:any,key:string,instance:string){
 return withOperation(state,config,key,async()=>{await assertNoPending(state);const records=await readLifecycle(state);if(!Object.keys(records).length)return;for(const r of Object.values(records) as any[]){checkRecord(config,key,r.value);if(r.value.instance!==instance)throw Error('Shutdown ownership mismatch; no records changed')}
 const worker=records['process.json']?.value;if(worker&&!sameProcess(worker.osIdentity,await selfIdentity()))throw Error('Only exact owning worker may finalize records');
 return archiveRecords(state,config,key,records,'verified-worker-shutdown');});
}
