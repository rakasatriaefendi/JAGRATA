// Single separately approved receipt publication; no service/Docker operations.
import {readFile,writeFile,open,lstat,rename,readdir} from 'node:fs/promises';
import {resolve,join,relative} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import {fingerprint,validate} from '../../installer/state.ts';
import {noLinks} from '../../apps/manager/sources.ts';
import {windowsPrivacy} from '../../installer/platform.ts';
const root=resolve('.'),state=join(root,'runtime/console'),out=join(root,'runtime/qa-ui-sidebar-timezone-20261026');
const target=join(state,'setup.json'),evidence=join(out,'receipt-approval-apply.json');
const previous='2e452da297e4836e31fcd9a8e3a54f3d74f71008450304ba0a33cbe68aaabd4a';
const approved='5db1e05c939ab61b66dd52627f4edf420e2939c9182936a96970959296664ec1';
const candidateHash='c43bd7be70e4b9154a2bd169ea507e3e23e026af7c5728f254ae22f56f32a0e2';
const hash=(data:any)=>createHash('sha256').update(data).digest('hex');
async function snapshot(){const files:Record<string,string>={};async function scan(dir:string){for(const e of await readdir(dir,{withFileTypes:true})){const p=join(dir,e.name);assert(!e.isSymbolicLink(),'Linked installation state refused');if(e.isDirectory())await scan(p);else{assert(e.isFile());const s=await lstat(p,{bigint:true});assert(s.ino>0n&&s.nlink===1n);files[relative(root,p).replaceAll('\\','/')]=hash(await readFile(p))}}}await scan(state);return files}
let published=false,journal:any,originalHandle:any;
try{
 const candidatePath=join(out,'setup-fingerprint-candidate.json');
 for(const p of [target,candidatePath])await noLinks(p);
 await noLinks(out,false);
 if(process.platform==='win32')await windowsPrivacy([out,state,target,candidatePath]);
 const review=JSON.parse(await readFile(join(out,'fingerprint-review.json'),'utf8'));
 assert.equal(review.target,'runtime/console/setup.json');assert.equal(review.field,'fingerprint');
 assert.equal(review.previousFingerprint,previous);assert.equal(review.reviewedSourceFingerprint,approved);assert.equal(review.candidateSHA256,candidateHash);
 assert.equal(await fingerprint(root),approved,'Source revision changed');
 for(const [file,expected]of Object.entries(review.sourceHashes))assert.equal(hash(await readFile(join(root,file))),expected,'Reviewed source changed: '+file);
 const before=await snapshot(),saved=JSON.parse(await readFile(join(out,'active-recursive-comparison.json'),'utf8'));
 assert.deepEqual(before,saved.files,'Existing state changed since review');
 const checked=await validate(root,state,false); // Static ownership, credentials, certificate, binding; no engine query.
 assert.equal(checked.adapter.config.containerId,'eab16c3f3d6b699854c96103b1482dfa4fe946bc2301626b0614db1416e497b4');
 assert.equal(checked.adapter.config.installationId,'qa-cs04-b3974d67');
 originalHandle=await open(target,'r');const identity=await originalHandle.stat({bigint:true});
 assert(identity.isFile()&&identity.ino>0n&&identity.nlink===1n&&identity.size<65536n);
 const original=await originalHandle.readFile();assert.equal(hash(original),review.originalReceiptSHA256);
 const candidate=await readFile(candidatePath);assert.equal(hash(candidate),candidateHash);
 const old=JSON.parse(original.toString());assert.equal(old.fingerprint,previous);assert.equal(old.phase,'READY');
 assert.deepEqual(JSON.parse(candidate.toString()),{...old,fingerprint:approved});
 const matches=[...original.toString().matchAll(/("fingerprint"\s*:\s*")[a-f0-9]{64}/g)];assert.equal(matches.length,1);
 assert.equal(candidate.toString(),original.toString().replace(/("fingerprint"\s*:\s*")[a-f0-9]{64}/,(_m,a)=>a+approved));
 journal={at:new Date().toISOString(),phase:'PREPARED',published:false,target:'runtime/console/setup.json',previousFingerprint:previous,approvedFingerprint:approved,originalReceiptSHA256:hash(original),candidateSHA256:candidateHash,before};
 await writeFile(evidence,JSON.stringify(journal,null,2)+'\n',{flag:'wx',mode:0o600});
 const temp=join(state,'setup.json.approved-'+randomBytes(8).toString('hex'));
 const handle=await open(temp,'wx',0o600);try{await handle.writeFile(candidate);await handle.sync()}finally{await handle.close()}
 if(process.platform==='win32')await windowsPrivacy([temp]);
 await noLinks(target);const current=await lstat(target,{bigint:true});assert.equal(current.ino,identity.ino);assert.equal(current.dev,identity.dev);assert.equal(current.nlink,1n);
 assert.equal(hash(await readFile(target)),review.originalReceiptSHA256);assert.equal(await fingerprint(root),approved);
 const prepublish=await snapshot();delete prepublish[relative(root,temp).replaceAll('\\','/')];assert.deepEqual(prepublish,before);
 await originalHandle.close();originalHandle=null;await rename(temp,target);published=true;
 journal={...journal,phase:'PUBLISHED',published};await writeFile(evidence,JSON.stringify(journal,null,2)+'\n');
 await validate(root,state);const after=await snapshot();assert.deepEqual(after,{...before,'runtime/console/setup.json':candidateHash});
 journal={...journal,phase:'VERIFIED',finishedAt:new Date().toISOString(),after,onlyChangedField:'fingerprint',otherInstallationFilesUnchanged:Object.keys(before).length-1,sourceValidation:'PASS',liveEngineVerification:'NOT_EXECUTED',serviceOrDockerOperations:false};
 await writeFile(evidence,JSON.stringify(journal,null,2)+'\n');
 console.log(JSON.stringify({result:'PASS',published,onlyChangedField:'runtime/console/setup.json:fingerprint',sourceValidation:'PASS',otherInstallationFilesUnchanged:journal.otherInstallationFilesUnchanged,liveEngineVerification:'NOT_EXECUTED',serviceOrDockerOperations:false}));
}catch(e:any){if(journal)await writeFile(evidence,JSON.stringify({...journal,phase:'FAILED',published,error:String(e)},null,2)+'\n').catch(()=>{});console.error(JSON.stringify({result:'FAIL',published,error:String(e),automaticRetry:false,automaticRollback:false}));process.exitCode=1}
finally{await originalHandle?.close()}
