// Not reachable through HTTP. An operator must separately approve a private scoped grant.
import {mkdir,open,readFile,lstat,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {noLinks,sourceError} from './sources.ts';
import {fixedRead} from './security-read.ts';
import {decisionRecords,protection} from './remediation.ts';
import {windowsPrivacy} from '../../installer/platform.ts';
const check=(ok:any,message:string)=>{if(!ok)throw sourceError(message,403)};
const digest=(v:any)=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
export interface DecisionGrant {planSHA256:string;containerId:string;imageId:string;actor:string;expiresAt:string;operation:'create'|'revoke';mayEnforce:true;confirmation:string}
export class ApprovedDecisionAdapter{
 adapter:any;dir:string;policy:any;clock:()=>number;queue:Promise<any>=Promise.resolve();
 constructor(adapter:any,privateJournalDirectory:string,policy:any,clock=Date.now){this.adapter=adapter;this.dir=privateJournalDirectory;this.policy=policy;this.clock=clock}
 async read(){return decisionRecords(JSON.parse(await fixedRead(this.adapter,'decisions')),new Date(this.clock()).toISOString()).records}
 async execute(plan:any,grant:DecisionGrant){const work=this.queue.then(()=>this.apply(plan,grant));this.queue=work.catch(()=>{});return work}
 async apply(plan:any,grant:DecisionGrant){
  const {sha256,...body}=plan;check(digest(body)===sha256,'Plan integrity mismatch.');
  check(grant&&grant.planSHA256===sha256&&grant.actor===plan.actor&&grant.containerId===plan.installation.id&&grant.imageId===plan.installation.imageId,'Exact private operator grant required.');
  check(grant.mayEnforce===true&&grant.operation==='create'&&grant.confirmation===plan.confirmation,'Explicit enforcement-aware create confirmation required.');
  check(this.clock()<Date.parse(grant.expiresAt)&&this.clock()<Date.parse(plan.expiresAt),'Approval expired.');
  check(plan.kind==='decision-create'&&plan.sourceVersion?.startsWith('v1.8.1-'),'Only audited decision integration permitted.');
  check(/^[a-f0-9]{32}$/.test(plan.id)&&typeof plan.target==='string','Invalid plan identity.');
  const policy=await this.policy.list();check(!protection(plan.target,[...policy.entries.filter((e:any)=>e.active),...plan.managementCidrs.map((target:string)=>({target,reason:'Management'}))]).length,'Protected target.');
  const c=await this.adapter.owned();check(c.State.Running&&c.Id===grant.containerId&&c.Image===grant.imageId,'Engine identity changed.');
  const liveVersion=(await fixedRead(this.adapter,'version')).match(/^version:\s*(\S+)/m)?.[1];check(liveVersion===plan.sourceVersion,'Engine version changed since review.');
  const command=plan.commands?.[0]?.argv;check(Array.isArray(command)&&command.length===10&&command[0]==='decisions'&&command[1]==='add'&&command[2]==='--ip'&&command[3]===plan.target&&command[4]==='--duration'&&/^\d{1,4}m$/.test(command[5])&&Number(command[5].slice(0,-1))>=1&&Number(command[5].slice(0,-1))<=1440&&command[6]==='--reason'&&command[7].startsWith('jagrata/'+plan.id+':')&&command[8]==='--type'&&command[9]==='ban','Unexpected decision argv.');
  // Current compiled plans have ten arguments. Reject all additional switches.
  return this.createWithIntent(plan,command,c,grant);
 }
 async createWithIntent(plan:any,command:string[],c:any,grant:DecisionGrant){
  let created=false;try{await mkdir(this.dir,{mode:0o700});created=true}catch(e:any){if(e.code!=='EEXIST')throw e}await noLinks(this.dir,false);if(process.platform==='win32')await windowsPrivacy([this.dir],created);else{const st=await lstat(this.dir);check(st.uid===process.getuid?.()&&!(st.mode&0o077),'Private action directory required.')}
  const file=join(this.dir,plan.id+'.json');const handle=await open(file,'wx',0o600).catch(()=>{throw sourceError('Action already attempted; reconcile its receipt, never replay.',409)});
  const intent={phase:'INTENT',planSHA256:plan.sha256,containerId:c.Id,imageId:c.Image,actor:plan.actor,target:plan.target,reason:command[7],at:new Date(this.clock()).toISOString()};
  try{await handle.writeFile(JSON.stringify(intent));await handle.sync()}finally{await handle.close()}
  const before=await this.read();const baseline=await open(join(this.dir,plan.id+'.before.json'),'wx',0o600);try{await baseline.writeFile(JSON.stringify({decisionIds:before.map((d:any)=>d.id),at:new Date(this.clock()).toISOString()}));await baseline.sync()}finally{await baseline.close()}
  // No automatic retry after the write boundary, including uncertain CLI failure.
  const policy=await this.policy.list();check((policy.revision??null)===plan.policyRevision,'Protected policy revision changed.');check(!protection(plan.target,[...policy.entries.filter((e:any)=>e.active),...plan.managementCidrs.map((target:string)=>({target,reason:'Management'}))]).length,'Protected target.');const fresh=await this.adapter.owned();check(fresh.Id===c.Id&&fresh.Image===c.Image&&fresh.State.Running,'Engine identity changed before apply.');check(this.clock()<Date.parse(grant.expiresAt)&&this.clock()<Date.parse(plan.expiresAt),'Approval expired before apply.');
  await this.adapter.call(['exec',c.Id,'cscli',...command],undefined,Math.min(Date.parse(grant.expiresAt),Date.parse(plan.expiresAt)));const after=await this.read();
  const owned=after.filter((d:any)=>d.target===plan.target&&d.origin==='cscli'&&d.scenario===command[7]&&!before.some((b:any)=>b.id===d.id));
  check(owned.length===1,'Apply outcome uncertain; preserve INTENT and reconcile authoritatively.');
  const result={...intent,phase:'VERIFIED',decisionId:owned[0].id,receiptAt:new Date(this.clock()).toISOString(),enforcement:'NOT_VERIFIED'};
  const pending=file+'.verified';const f=await open(pending,'wx',0o600);try{await f.writeFile(JSON.stringify(result));await f.sync()}finally{await f.close()}await rename(pending,file);return result;
 }
 async revoke(plan:any,grant:DecisionGrant){const work=this.queue.then(()=>this.revokeAuthorized(plan,grant));this.queue=work.catch(()=>{});return work}
 async revokeAuthorized(plan:any,grant:DecisionGrant){
  check(grant&&grant.operation==='revoke'&&grant.mayEnforce===true&&grant.planSHA256===plan.sha256&&grant.confirmation===plan.confirmation&&grant.actor===plan.actor&&this.clock()<Date.parse(grant.expiresAt),'Separate exact reversal approval required.');
  check(/^[a-f0-9]{32}$/.test(plan.id),'Invalid receipt identity.');const file=join(this.dir,plan.id+'.json');await noLinks(file);const stat=await lstat(file);check(stat.isFile()&&stat.nlink===1&&stat.size<16384,'Private action receipt required.');const receipt=JSON.parse(await readFile(file,'utf8'));
  if(process.platform==='win32')await windowsPrivacy([this.dir,file]);else check(!(stat.mode&0o077)&&stat.uid===process.getuid?.(),'Private receipt required.');
  check(receipt.phase==='VERIFIED'&&receipt.planSHA256===plan.sha256&&receipt.actor===grant.actor&&receipt.containerId===grant.containerId&&receipt.imageId===grant.imageId,'Only verified JAGRATA-owned decisions may be reversed.');
  const c=await this.adapter.owned();check(c.State.Running&&c.Id===grant.containerId&&c.Image===grant.imageId,'Engine identity changed.');const records=await this.read(),d=records.find((x:any)=>x.id===receipt.decisionId);
  if(!d)return {state:'ALREADY_ABSENT',enforcement:'NOT_VERIFIED'};
  check(d.target===receipt.target&&d.origin==='cscli'&&d.scenario===receipt.reason,'Decision ownership changed.');
  const journal=join(this.dir,plan.id+'.revoke.json');const intent=await open(journal,'wx',0o600).catch(()=>{throw sourceError('Reversal already attempted; inspect its receipt before further action.',409)});try{await intent.writeFile(JSON.stringify({phase:'INTENT',decisionId:d.id,actor:grant.actor,at:new Date(this.clock()).toISOString()}));await intent.sync()}finally{await intent.close()}
  check(this.clock()<Date.parse(grant.expiresAt),'Reversal approval expired before dispatch.');await this.adapter.call(['exec',c.Id,'cscli','decisions','delete','--id',String(d.id)],undefined,Date.parse(grant.expiresAt));
  check(!(await this.read()).some((x:any)=>x.id===d.id),'Reversal outcome uncertain; no automatic retry.');const result={state:'VERIFIED_ABSENT',decisionId:d.id,enforcement:'NOT_VERIFIED'};const pending=await open(journal+'.verified','wx',0o600);try{await pending.writeFile(JSON.stringify(result));await pending.sync()}finally{await pending.close()}await rename(journal+'.verified',journal);return result;
 }
}
