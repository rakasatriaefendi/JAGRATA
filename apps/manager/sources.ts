import {readFile,lstat,realpath,mkdir,open,rename,unlink} from 'node:fs/promises';
import {resolve,relative,join,dirname,parse,isAbsolute,sep} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {windowsPrivacy} from '../../installer/platform.ts';

export const connectors={
 ssh:{name:'SSH authentication file',label:'syslog',collection:'crowdsecurity/sshd',parser:'crowdsecurity/sshd-logs',format:'Syslog SSH authentication records (sshd). Example location: /var/log/auth.log or /var/log/secure.'},
 nginx:{name:'Nginx access file',label:'nginx',collection:'crowdsecurity/nginx',parser:'crowdsecurity/nginx-logs',format:'Nginx combined access log. Example location: /var/log/nginx/access.log. Custom formats need separate parser validation.'}
};
const digest=(x:string)=>createHash('sha256').update(x).digest('hex');
const idPattern=/^src-[a-f0-9]{16}$/;
export function sourceError(message:string,status=400){return Object.assign(Error(message),{status,public:true})}
function check(ok:any,message:string,status=400):asserts ok{if(!ok)throw sourceError(message,status)}
export async function noLinks(path:string,file=true){
 const full=resolve(path);let current=parse(full).root;
 for(const part of full.slice(current.length).split(sep).filter(Boolean)){current=join(current,part);const s=await lstat(current);check(!s.isSymbolicLink(),'Symlinks and reparse points are not supported.');if(current!==full)check(s.isDirectory(),'Invalid parent directory.');else check(file?s.isFile():s.isDirectory(),'Select a regular file.');}
 check((await realpath(full)).toLowerCase()===full.toLowerCase(),'Path alias rejected.');return full;
}
export function sourceInput(input:any){
 check(input&&typeof input==='object'&&!Array.isArray(input),'Source settings required.');
 check(Object.keys(input).every(k=>['name','type','path','enabled','consent'].includes(k)),'Unsupported source settings. Arbitrary YAML and commands are rejected.');
 check(typeof input.name==='string'&&input.name.trim().length>0&&input.name.trim().length<=80&&!/[\x00-\x1f\x7f]/.test(input.name),'Use a display name of 1â€“80 characters.');
 check(typeof input.type==='string'&&Object.hasOwn(connectors,input.type),'Only SSH and Nginx file sources are supported.');
 check(typeof input.path==='string'&&input.path.length<=1024&&isAbsolute(input.path)&&!input.path.split(/[\\/]/).includes('..')&&!/[\x00-\x1f\x7f*?$\[\]{}\n]/.test(input.path),'Choose one absolute local file path without traversal or wildcards.');
 if(process.platform==='win32')check(/^[A-Za-z]:[\\/]/.test(input.path)&&!input.path.slice(2).includes(':')&&!input.path.split(/[\\/]/).some((p:string)=>/[. ]$/.test(p)||/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p)),'UNC, device paths, alternate streams and ambiguous Windows paths are rejected.');
 check(typeof input.enabled==='boolean'&&input.consent===true,'Explicit file-selection consent is required.');
 return {name:input.name.trim(),type:input.type,path:resolve(input.path),enabled:input.enabled,consent:true};
}
export function acquisition(s:any){check(idPattern.test(s.id)&&Object.hasOwn(connectors,s.type),'Invalid acquisition source.');return `source: file\npoll_without_inotify: true\nfilenames:\n  - /guard/sources/${s.id}.log\nlabels:\n  type: ${connectors[s.type as keyof typeof connectors].label}\n`;}
export class Sources{
 dir:string;adapter:any;identity:any;tail:Promise<any>=Promise.resolve();pending=0;
 constructor(dir:string,adapter:any){this.dir=resolve(dir);this.adapter=adapter;const c=adapter.config;this.identity={installationId:c.installationId,rootHash:c.rootHash,ownerHash:digest(c.owner)};}
 async init(){
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'../../runtime');const inside=relative(root,this.dir);
  check(inside&&!inside.startsWith('..')&&!isAbsolute(inside),'Source state must remain below project runtime/.',403);
  await noLinks(dirname(this.dir),false);
  try{await mkdir(this.dir,{mode:0o700});if(process.platform==='win32')await windowsPrivacy([this.dir],true)}catch(e:any){if(e.code!=='EEXIST')throw e}
  await noLinks(this.dir,false);if(process.platform==='win32')await windowsPrivacy([this.dir]);else check(((await lstat(this.dir)).mode&0o077)===0,'Source state directory must be private.',403);
 }
 async load(){
  await this.init();let raw:string;
  try{const f=join(this.dir,'sources.json');await noLinks(f);const stat=await lstat(f);check(stat.size<=128*1024,'Source registry exceeds its limit.',409);raw=await readFile(f,'utf8')}catch(e:any){if(e.code==='ENOENT')return {version:1,identity:this.identity,revision:0,sources:[],audit:[]};throw e}
  let db:any;try{db=JSON.parse(raw)}catch{throw sourceError('Source registry is malformed; preserved for recovery.',409)}
  check(db?.version===1&&JSON.stringify(db.identity)===JSON.stringify(this.identity),'Cross-installation source registry rejected.',403);
  check(Number.isSafeInteger(db.revision)&&db.revision>=0&&Array.isArray(db.sources)&&db.sources.length<=64&&Array.isArray(db.audit)&&db.audit.length<=100,'Invalid source registry.',409);
  const ids=new Set();for(const s of db.sources){check(idPattern.test(s.id)&&!ids.has(s.id),'Invalid or duplicate source ID.',409);ids.add(s.id);sourceInput({name:s.name,type:s.type,path:s.path,enabled:s.enabled,consent:true});check(s.containerPath===`/guard/sources/${s.id}.log`,'Invalid container path.',409)}return db;
 }
 async validate(input:any){const s=sourceInput(input);try{await noLinks(s.path);const f=await lstat(s.path,{bigint:true});check(f.ino>0n,'Filesystem cannot provide a stable file identity.');return {valid:true,checkedAt:new Date().toISOString(),fileIdentity:`${f.dev}:${f.ino}`,message:'Regular local file verified. Contents were not read. Docker access, format and parsing require operator apply and engine evidence.',label:connectors[s.type as keyof typeof connectors].label}}catch(e:any){if(e.public)throw e;throw sourceError('Selected file is missing or cannot be inspected. Check its exact path and permissions.');}}
 async change(action:string,input:any){
  check(['save','remove'].includes(action),'Operation unsupported.');check(input&&Number.isSafeInteger(input.revision),'Registry revision required.',409);
  check(this.pending<8,'Configuration writer is busy. Retry later.',429);this.pending++;const queued=Date.now();
  const work=this.tail.then(async()=>{check(Date.now()-queued<10000,'Configuration write expired. Refresh and retry.',409);await this.init();const lock=join(this.dir,'sources.lock');let handle;
   try{handle=await open(lock,'wx',0o600)}catch{throw sourceError('Another configuration write is pending. Retry after reviewing the source list.',409)}
   try{const db=await this.load();check(input.revision===db.revision,'Configuration changed. Refresh before saving.',409);let s:any;
    if(input.id!==undefined){check(idPattern.test(input.id),'Invalid source ID.');s=db.sources.find((x:any)=>x.id===input.id&&!x.removed);check(s,'Source not found.',404)}
    if(action==='remove'){check(s&&input.confirm===true,'Confirm removal explicitly.');s.removed=true;s.enabled=false;s.validated=null;}
    else {const value=sourceInput(input.source);check(!db.sources.some((x:any)=>!x.removed&&x.id!==s?.id&&(process.platform==='win32'?x.path.toLowerCase()===value.path.toLowerCase():x.path===value.path)),'This file already has an acquisition.');
     const selected=await this.validate(value).catch(()=>null);
     if(selected)for(const other of db.sources.filter((x:any)=>!x.removed&&x.id!==s?.id)){const existing=await this.validate({name:other.name,type:other.type,path:other.path,enabled:other.enabled,consent:true}).catch(()=>null);check(!existing||existing.fileIdentity!==selected.fileIdentity,'This file identity already has an acquisition (hard-link alias).');}
     if(s){const same=JSON.stringify([s.name,s.type,s.path,s.enabled])===JSON.stringify([value.name,value.type,value.path,value.enabled]);if(same)return db;Object.assign(s,value,{validated:null})}
     else{check(db.sources.length<64,'Registry limit reached (64 including retained removal records).',409);const id='src-'+randomBytes(8).toString('hex');s={...value,id,containerPath:`/guard/sources/${id}.log`,validated:null};db.sources.push(s)}
     // Saving is a draft; validation is separate from format and engine evidence.
    }
    db.revision++;db.audit=[...db.audit,{at:new Date().toISOString(),action,id:s.id,revision:db.revision}].slice(-100);
    const temp=join(this.dir,'sources.pending-'+randomBytes(8).toString('hex'));const f=await open(temp,'wx',0o600);try{await f.writeFile(JSON.stringify(db,null,2)+'\n')}finally{await f.close()}await rename(temp,join(this.dir,'sources.json'));return db;
   }finally{await handle.close();await unlink(lock)}
  }).finally(()=>{this.pending--});this.tail=work.catch(()=>{});return work;
 }
 async list(){
  const db=await this.load();let snapshot:any=null,engine:any=null;
  try{engine=await this.adapter.owned();if(engine.State?.Running)snapshot=await this.adapter.snapshot()}catch{}
  const sources=[];
  for(const s of db.sources){
   const fileMount=engine?.Mounts?.find((m:any)=>m.Destination===s.containerPath);
   // Mounts alone never prove the acquisition config was loaded.
   const counters=snapshot?.metrics?.acquisition?.['file:'+s.containerPath]??null;
   const parser=connectors[s.type as keyof typeof connectors].parser;
   const parserCounters=snapshot?.metrics?.parsers?.[parser]??null;
   let valid=null,validationError='';try{valid=await this.validate({name:s.name,type:s.type,path:s.path,enabled:s.enabled,consent:true})}catch(e:any){validationError=e.public?e.message:'Validation unavailable.'}
   const mapped=!!fileMount&&fileMount.Type==='bind'&&fileMount.RW===false&&typeof fileMount.Source==='string'&&(process.platform==='win32'?fileMount.Source.replace(/^\/run\/desktop\/mnt\/host\/([a-z])\//,(_:string,d:string)=>d.toUpperCase()+':/').replaceAll('\\','/').toLowerCase()===s.path.replaceAll('\\','/').toLowerCase():fileMount.Source===s.path);
   let configMounted=false;
   const conf=engine?.Mounts?.find((m:any)=>m.Destination===`/etc/crowdsec/acquis.d/guard-${s.id}.yaml`);
   if(conf?.Type==='bind'&&conf.RW===false&&typeof conf.Source==='string'){
    let host=conf.Source.replace(/^\/run\/desktop\/mnt\/host\/([a-z])\//,(_:string,d:string)=>d.toUpperCase()+':/');
    const rel=relative(join(this.dir,'plans'),host);
    if(rel&&!rel.startsWith('..')&&!isAbsolute(rel))try{
     await noLinks(host);const st=await lstat(host),manifestFile=join(dirname(host),'manifest.json');await noLinks(manifestFile);check((await lstat(manifestFile)).size<128*1024,'Plan manifest too large.');
     const manifest=JSON.parse(await readFile(manifestFile,'utf8')),selected=manifest.sources?.find((x:any)=>x.id===s.id);
     configMounted=JSON.stringify(manifest.identity)===JSON.stringify(this.identity)&&selected?.path===s.path&&selected.type===s.type&&selected.fileIdentity===valid?.fileIdentity&&st.size<2048&&await readFile(host,'utf8')===acquisition(s)&&Date.parse(engine.State.StartedAt)>=st.mtimeMs;
    }catch{}
   }
   const applied=mapped&&configMounted;
   const observed=!!(applied&&counters?.reads>0&&counters?.parsed>0);
   const state=s.removed?'REMOVED':!s.enabled?'DISABLED':validationError?'ERROR':observed?'OBSERVED':applied?'APPLIED':valid?'VALIDATED':'DRAFT';
   const associated=(snapshot?.alerts||[]).filter((a:any)=>a.events.some((e:any)=>e.meta.datasource_path===s.containerPath)).map((a:any)=>a.id);
   sources.push({...s,status:state,validation:valid,validationError,mapped,configMounted,engineMayStillRead:!!fileMount&&(!s.enabled||s.removed||!applied),counters:applied?counters:null,parserCounters,parserScope:'Engine-wide; not attributable to this file alone',alertIds:associated,observedAt:snapshot?.observedAt??null,lastActivity:null,activityNote:'Current counters are cumulative. Last log activity is not available.',label:connectors[s.type as keyof typeof connectors].label});
  }
  return {revision:db.revision,installationId:this.identity.installationId,connectors,sources,engineAvailable:!!snapshot,audit:db.audit,applyNotice:'All sources belong to this installation\'s single engine. Saving does not change Docker. Changed mounts may require operator-approved recreation of the same service with its existing persistent volumes; this Console never performs it.'};
 }
}
