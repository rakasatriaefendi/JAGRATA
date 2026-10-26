// One approved receipt-field publication. No setup, lifecycle invocation or Docker mutation.
import {readFile,writeFile,open,lstat,rename} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import {capture,request} from '../jagrata/preservation.ts';
const out=resolve('runtime/qa-ui-i18n-20261025');
import {fingerprint,validate} from '../../installer/state.ts';
import {noLinks} from '../../apps/manager/sources.ts';
import {windowsPrivacy} from '../../installer/platform.ts';
const previous='a10e566c5b94630017322d2f2c2d79f6605671383ebad5e61ef14a550cee45b6';
const approved='2e452da297e4836e31fcd9a8e3a54f3d74f71008450304ba0a33cbe68aaabd4a';
const root=resolve('.'),state=join(root,'runtime/console'),target=join(state,'setup.json');
const hash=(b:any)=>createHash('sha256').update(b).digest('hex');
const evidence=join(out,'receipt-approval-apply.json');let published=false,journal:any,originalHandle:any;
try{
 await noLinks(target);await noLinks(out,false);
 if(process.platform==='win32')await windowsPrivacy([out,state,target]);
 const review=JSON.parse(await readFile(join(out,'fingerprint-review.json'),'utf8'));
 assert.equal(review.target,target);assert.equal(review.field,'fingerprint');assert.equal(review.previousFingerprint,previous);assert.equal(review.reviewedSourceFingerprint,approved);
 assert.equal(await fingerprint(root),approved,'Approved source revision changed; no publication');
 const saved=JSON.parse(await readFile(join(out,'after.json'),'utf8')),before=await capture();
 for(const key of ['files','containers','inventory','health','packageHash','scripts'])assert.deepEqual(before[key],saved[key],key+' changed since review; no publication');
 const owned=await validate(root,state,false);await owned.adapter.owned();
 assert.equal(owned.adapter.config.containerId,'eab16c3f3d6b699854c96103b1482dfa4fe946bc2301626b0614db1416e497b4');
 assert.equal(before.sourceGate,'SOURCE_FINGERPRINT_REVALIDATION_REQUIRED');
 originalHandle=await open(target,'r');const identity=await originalHandle.stat({bigint:true});
 assert(identity.isFile()&&identity.nlink===1n&&identity.ino>0n&&identity.size<65536n);
 const original=await originalHandle.readFile();assert.equal(hash(original),review.expectedExistingSHA256);
 const candidate=await readFile(join(out,'setup-fingerprint-candidate.json'));assert.equal(hash(candidate),review.candidateSHA256);
 const old=JSON.parse(original.toString('utf8'));assert.equal(old.fingerprint,previous);assert.equal(old.phase,'READY');
 assert.deepEqual(JSON.parse(candidate.toString('utf8')),{...old,fingerprint:approved});
 const matches=[...original.toString('utf8').matchAll(/("fingerprint"\s*:\s*")[a-f0-9]{64}("?)/g)];assert.equal(matches.length,1);
 assert.equal(candidate.toString('utf8'),original.toString('utf8').replace(/("fingerprint"\s*:\s*")[a-f0-9]{64}("?)/,(_m,a,b)=>a+approved+b));
 journal={at:new Date().toISOString(),phase:'PREPARED',published:false,target,previousFingerprint:previous,approvedFingerprint:approved,beforeReceiptHash:hash(original),candidateHash:hash(candidate),before};
 await writeFile(evidence,JSON.stringify(journal,null,2)+'\n',{flag:'wx',mode:0o600});
 const temp=join(state,'setup.json.approved-'+randomBytes(8).toString('hex'));
 const handle=await open(temp,'wx',0o600);try{await handle.writeFile(candidate);await handle.sync()}finally{await handle.close()}
 if(process.platform==='win32')await windowsPrivacy([temp]);
 await noLinks(target);const current=await lstat(target,{bigint:true});assert.equal(current.ino,identity.ino);assert.equal(current.dev,identity.dev);assert.equal(hash(await readFile(target)),review.expectedExistingSHA256);
 assert.equal(await fingerprint(root),approved,'Source changed before publication');
 await originalHandle.close();originalHandle=null;
 await rename(temp,target);published=true;journal.published=true;journal.phase='PUBLISHED';
 await writeFile(evidence,JSON.stringify(journal,null,2)+'\n');
 const validated=await validate(root,state);await validated.adapter.owned();
 assert.equal(hash(await readFile(target)),review.candidateSHA256);
 const after=await capture(),expected={...before.files,'runtime/console/setup.json':review.candidateSHA256};assert.deepEqual(after.files,expected,'Unexpected persistent file change');
 for(const key of ['containers','inventory','health','packageHash','scripts'])assert.deepEqual(after[key],before[key],key+' preservation failed');
 assert.equal(after.sourceGate,'PASS');
 const page=await request('/'),session=await request('/api/session');assert(page.tlsAuthorized&&session.tlsAuthorized);assert.equal(page.status,200);assert(page.body.includes('language-picker'));assert.equal(session.status,401);const asset=await request('/client.js');assert(asset.tlsAuthorized&&asset.status===200&&asset.body.includes('window.JAGRATA_LOCALES=')&&asset.body.includes('jagrata-language'));
 journal={...journal,phase:'VERIFIED',finishedAt:new Date().toISOString(),after,tlsVerified:true,anonymousSessionStatus:401,localI18nextAssetVerified:true,onlyChangedField:'fingerprint',otherActiveStateFilesUnchanged:17};
 await writeFile(evidence,JSON.stringify(journal,null,2)+'\n');
 console.log(JSON.stringify({result:'PASS',changedField:'runtime/console/setup.json:fingerprint',sourceValidation:after.sourceGate,application:after.health.state,url:after.health.url,pid:after.health.pid,otherStateFilesUnchanged:17,tlsVerified:true,dockerPreserved:true}));
}catch(e:any){if(journal)await writeFile(evidence,JSON.stringify({...journal,phase:'FAILED',published,error:String(e)},null,2)+'\n').catch(()=>{});console.error(JSON.stringify({result:'FAIL',published,error:String(e),automaticRetry:false,automaticRollback:false}));process.exitCode=1}
finally{await originalHandle?.close()}
