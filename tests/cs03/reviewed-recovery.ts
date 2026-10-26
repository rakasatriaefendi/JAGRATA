// One-off operator-reviewed legacy archive, NOT a new product CLI.
// Never called by start. Requires separate exact approval; does not start Manager.
import {readFile,readdir,lstat,writeFile} from 'node:fs/promises';
import {resolve,join,relative} from 'node:path';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {validate,fingerprint} from '../../installer/state.ts';
import {inspectProcess,selfIdentity} from '../../installer/process.ts';
import {readLifecycle,withOperation,archiveRecords} from '../../installer/recovery.ts';
import {run} from '../../installer/platform.ts';
import {noLinks} from '../../apps/manager/sources.ts';
const root=resolve('.'),state=join(root,'runtime/console'),out=join(root,'runtime/qa-lifecycle-recovery-20261026');
const digest=(b:string|Buffer)=>createHash('sha256').update(b).digest('hex');
export async function workersAbsent(){
 const script=String.raw`$ErrorActionPreference='Stop'
$root=$env:GUARD_REVIEW_ROOT.Replace('\','/').ToLowerInvariant()
$nodes=@(Get-CimInstance Win32_Process -Filter "Name='node.exe'")
$unknown=@($nodes|Where-Object{!$_.CommandLine}).Count
$matches=@($nodes|Where-Object{$_.CommandLine -and ($_.CommandLine.Replace('\','/').ToLowerInvariant().Contains($root+'/installer/worker.ts') -or $_.CommandLine.Replace('\','/').ToLowerInvariant().Contains($root+'/apps/manager/server.ts'))}).Count
@{unknown=$unknown;matches=$matches}|ConvertTo-Json -Compress`;
 assert.equal(process.platform,'win32','Reviewed legacy recovery is Windows-specific');
 const result=JSON.parse(await run(join(process.env.SystemRoot!,'System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{timeout:4000,env:{...process.env,GUARD_REVIEW_ROOT:root}}));
 assert.equal(result.unknown,0,'Uninspectable Node process: recovery refused');assert.equal(result.matches,0,'Existing worker/server candidate: recovery refused');
}
async function files(){const result:any={};async function scan(dir:string){for(const e of await readdir(dir,{withFileTypes:true})){assert(!e.isSymbolicLink());const p=join(dir,e.name);if(e.isDirectory())await scan(p);else result[relative(root,p).replaceAll('\\','/')]=digest(await readFile(p))}}await scan(state);return result}
async function main(){
 assert.equal(process.argv.length,4);assert.equal(process.argv[2],'--approved-review-sha256');
 await noLinks(out,false);await noLinks(join(out,'recovery-proposal.json'));
 const raw=await readFile(join(out,'recovery-proposal.json'));assert.equal(digest(raw),process.argv[3],'Exact reviewed proposal required');const review=JSON.parse(raw.toString());
 assert.equal(digest(await readFile(resolve('tests/cs03/reviewed-recovery.ts'))),review.helperSHA256,'Reviewed helper changed');
 const {config,key}=await validate(root,state); // Accepted source fingerprint is mandatory.
 assert.equal(await fingerprint(root),review.acceptedSourceFingerprint);assert.equal(config.id,review.installationId);assert.equal(config.rootHash,review.rootHash);
 const before=await files();assert.deepEqual(before,review.expectedFilesAfterReceiptApproval);
 const boot=(await selfIdentity()).boot;assert.equal(boot,review.reviewedBoot,'OS reboot since review: fresh review required');
 const bootMs=Number((BigInt(boot)-621355968000000000n)/10000n);
 async function verifyLegacy(){const records=await readLifecycle(state);assert.deepEqual(Object.keys(records).sort(),['process.json','start.lock']);
  for(const [name,r]of Object.entries(records) as [string,any][]){assert.equal(r.hash,review.records[name].hash);assert.equal(r.ino,review.records[name].ino);assert.equal(r.dev,review.records[name].dev);assert.equal(r.value.version,1);assert.equal(r.value.id,config.id);assert.equal(r.value.rootHash,config.rootHash);assert.equal(r.value.instance,review.instance);const st=await lstat(join(state,name));assert(st.mtimeMs<bootMs&&st.birthtimeMs<bootMs,'Lifecycle file does not predate this OS boot')}
  assert.equal((await inspectProcess(records['process.json'].value.pid)).state,'ABSENT','Recorded PID must still be conclusively absent');await workersAbsent();return records;
 }
 await verifyLegacy();
 const journal=join(out,'recovery-apply.json');await writeFile(journal,JSON.stringify({phase:'PREPARED',at:new Date().toISOString(),reviewSHA256:digest(raw),before},null,2),{flag:'wx',mode:0o600});
 const archived=await withOperation(state,config,key,async()=>archiveRecords(state,config,key,await verifyLegacy(),'separately-approved-exact-legacy-archive',undefined,review.archiveId));
 const after=await files();for(const [name,h]of Object.entries(before))if(!['runtime/console/start.lock','runtime/console/process.json'].includes(name))assert.equal(after[name],h);
 assert(!after['runtime/console/start.lock']&&!after['runtime/console/process.json']);
 await writeFile(journal,JSON.stringify({phase:'VERIFIED',at:new Date().toISOString(),archived,before,after,startedManager:false,dockerOperations:false},null,2));
 console.log(JSON.stringify({result:'PASS',archive:archived.archive,manager:'NOT_STARTED',dockerOperations:false}));
}
if(process.argv[1]&&resolve(process.argv[1])===resolve('tests/cs03/reviewed-recovery.ts'))main().catch(e=>{console.error(JSON.stringify({result:'FAIL',error:String(e),automaticRetry:false,automaticRollback:false}));process.exitCode=1});
