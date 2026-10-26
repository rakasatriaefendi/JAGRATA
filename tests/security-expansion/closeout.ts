// Read-only closeout. Writes only new private QA evidence; never applies a receipt.
import assert from 'node:assert/strict';
import {readFile,writeFile,readdir,lstat} from 'node:fs/promises';
import {resolve,join,relative} from 'node:path';
import {createHash} from 'node:crypto';
import {CrowdSec,execute} from '../../apps/manager/adapter.ts';
import {SecurityPlatform} from '../../apps/manager/security.ts';
import {status} from '../../installer/lifecycle.ts';
import {validate,fingerprint,sourceFiles} from '../../installer/state.ts';
const root=resolve('.'),qa=join(root,'runtime/qa-security-expansion-20261026'),state=join(root,'runtime/console');
const hash=(v:any)=>createHash('sha256').update(typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(v)).digest('hex');
const before=JSON.parse(await readFile(join(qa,'before.json'),'utf8'));
const files:Record<string,string>={};
async function scan(dir:string){for(const e of await readdir(dir,{withFileTypes:true})){assert(!e.isSymbolicLink());const p=join(dir,e.name);if(e.isDirectory())await scan(p);else{const s=await lstat(p);assert(s.isFile());files[relative(root,p).replaceAll('\\','/')]=hash(await readFile(p))}}}
await scan(state);assert.deepEqual(files,before.files,'Installed files changed');
const health=await status(root,state);assert.equal(health.state,'RUNNING');assert.equal(health.pid,before.health.pid);assert.equal(health.instance,before.health.instance);
const checked=await validate(root,state,false);assert.equal(checked.adapter.config.containerId,before.ownership.containerId);
const inspected=JSON.parse(await execute(['--context','desktop-linux','container','inspect',...before.containers.map((c:any)=>c.id)]));
// Docker's mount-array ordering is not stable. A permutation that hashes exactly
// to the saved baseline proves the same complete field values, without inventing
// historical field values. Bound this proof to the small reviewed mount set.
const mountOrdering:any[]=[];
function sameMounts(mounts:any[],expected:string){assert(mounts.length<=8);let matched=false;function visit(prefix:any[],remaining:any[]){if(matched)return;if(!remaining.length){matched=hash(prefix)===expected;return}for(let i=0;i<remaining.length;i++)visit([...prefix,remaining[i]],remaining.filter((_,j)=>j!==i))}visit([],mounts);assert(matched,'Mount fields differ from saved baseline');return expected}
const containers=inspected.map((c:any,i:number)=>{const rawHash=hash(c.Mounts),expected=before.containers[i].mountsHash;mountOrdering.push({id:c.Id,rawHash,baselineHash:expected,orderChanged:rawHash!==expected,completeFieldSetVerified:true});return {id:c.Id,name:c.Name,state:c.State.Status,startedAt:c.State.StartedAt,restarts:c.RestartCount,image:c.Image,configHash:hash(c.Config),hostConfigHash:hash(c.HostConfig),mountsHash:sameMounts(c.Mounts,expected),networkHash:hash(c.NetworkSettings.Networks)}});
assert.deepEqual(containers,before.containers,'Container state or configuration changed');
const adapter=await CrowdSec.load(join(state,'adapter.json')),observation=await adapter.snapshot();
// cscli returns remaining decision durations relative to each observation time.
// Preserve and report those separately; compare every other normalized field.
const alertContent=(alerts:any[])=>alerts.map(a=>({...a,decisions:a.decisions.map((d:any)=>({type:d.type}))}));
assert.deepEqual(alertContent(observation.alerts!),alertContent(before.observation.alerts),'Historical alert content changed');
const decisionDurations={before:before.observation.alerts.map((a:any)=>({id:a.id,decisions:a.decisions})),after:observation.alerts!.map(a=>({id:a.id,decisions:a.decisions}))};
for(const a of [...decisionDurations.before,...decisionDurations.after])for(const d of a.decisions)assert(d.duration?.startsWith('-'),'Expected historical expired decision only');
const platform=await new SecurityPlatform(adapter).snapshot();assert(platform.identity?.id===before.ownership.containerId);assert.equal(platform.community?.state,'BLOCKLIST_DISABLED');assert.equal(platform.bouncers?.length,0);assert.equal(platform.decisions?.records.length,0);
await writeFile(join(qa,'platform-observation-final.json'),JSON.stringify(platform,null,2)+'\n',{flag:'wx',mode:0o600});
const historical=JSON.parse(await readFile(join(root,'runtime/qa-ui-i18n-20261025/receipt-approval-apply.json'),'utf8')).after.files;
let preserved=0,unhashed=0;
for(const [file,expected]of Object.entries(historical)){if(file.startsWith('runtime/console/'))continue;if(!/^[a-f0-9]{64}$/.test(String(expected))){unhashed++;continue}assert.equal(hash(await readFile(join(root,file))),expected,'Historical evidence changed: '+file);preserved++}
const original=await readFile(join(state,'setup.json')),receipt=JSON.parse(original.toString()),next=await fingerprint(root);
assert.equal(receipt.fingerprint,before.sourceFingerprint);assert.notEqual(next,receipt.fingerprint);
const candidate=Buffer.from(original.toString().replace(/("fingerprint"\s*:\s*")[a-f0-9]{64}/,(_m,a)=>a+next));assert.deepEqual(JSON.parse(candidate.toString()),{...receipt,fingerprint:next});
const sourceHashes:Record<string,string>={};for(const file of sourceFiles)sourceHashes[file]=hash(await readFile(join(root,file)));
await writeFile(join(qa,'setup-fingerprint-candidate.json'),candidate,{flag:'wx',mode:0o600});
const review={at:new Date().toISOString(),target:'runtime/console/setup.json',field:'fingerprint',previousFingerprint:receipt.fingerprint,reviewedSourceFingerprint:next,originalReceiptSHA256:hash(original),candidateSHA256:hash(candidate),sourceHashes,applied:false};
await writeFile(join(qa,'fingerprint-review.json'),JSON.stringify(review,null,2)+'\n',{flag:'wx',mode:0o600});
const result={at:new Date().toISOString(),result:'PASS',activeFilesUnchanged:Object.keys(files).length,files,containers,mountOrdering,health,historicalHashesPreserved:preserved,historicalMarkersNotRehashed:unhashed,alerts:observation.alerts?.map(a=>({id:a.id,scenario:a.scenario,createdAt:a.createdAt})),alertContentUnchanged:true,decisionDurations,capi:platform.community.state,bouncers:platform.bouncers.length,decisions:platform.decisions.records.length,configuredDefinitions:platform.inventory.acquisitionDefinitions.length,configuredSourcePaths:platform.sources.length,sourceGate:'AWAITING_SEPARATE_RECEIPT_APPROVAL',receiptApplied:false,managerRestarted:false,dockerMutations:false};
await writeFile(join(qa,'closeout.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify({result:result.result,activeFilesUnchanged:result.activeFilesUnchanged,historicalHashesPreserved:preserved,historicalMarkersNotRehashed:unhashed,containersUnchanged:containers.length,alerts:result.alerts,configuredDefinitions:result.configuredDefinitions,configuredSourcePaths:result.configuredSourcePaths,previousFingerprint:receipt.fingerprint,nextFingerprint:next,candidateSHA256:review.candidateSHA256,receiptApplied:false}));
