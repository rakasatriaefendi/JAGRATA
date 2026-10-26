// Read-only Docker/evidence preservation. No exec into the older engines.
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve,join} from 'node:path';
import {execute,CrowdSec} from '../../apps/manager/adapter.ts';
import {windowsPrivacy} from '../../installer/platform.ts';
const root=resolve('runtime/qa-cs04-20261024/integration-e3db1ae7');
const out=resolve('runtime/qa-cs05-preservation');let created=false;try{await mkdir(out,{mode:0o700});created=true}catch(e:any){if(e.code!=='EEXIST')throw e}if(process.platform==='win32')await windowsPrivacy([out],created);
const ids=['eab16c3f3d6b699854c96103b1482dfa4fe946bc2301626b0614db1416e497b4','63a6462c8beba871d6f2adb0b52bc8ab09dc6950c38c9559780f7c88d52fd307','ebe24d67e2fe2b81a53d5de96e777b7ba00f955e5b4df547bb55fe5487fcf07b'];
const hash=(v:any)=>createHash('sha256').update(typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(v)).digest('hex');
const files:any={};for(const file of ['runtime/qa-cs01-98d2e1ede4/after-alerts.json','runtime/qa-cs01-98d2e1ede4/after-metrics.json','runtime/qa-cs01-98d2e1ede4/evidence.json','fixtures/logs/ssh/auth.log','fixtures/logs/web/access.log',...['ssh.log','nginx.log','registration.json','adapter-verified.json','sources/sources.json','ingestion-results.json','append-started.json','ingestion-evidence/journal.ndjson','ingestion-evidence/final-acceptance-20261025.json'].map(f=>join(root,f))])files[file]=hash(await readFile(file));
const cs=JSON.parse(await execute(['--context','desktop-linux','container','inspect',...ids]));
const containers=cs.map((c:any)=>({id:c.Id,name:c.Name,image:c.Image,state:c.State.Status,pid:c.State.Pid,startedAt:c.State.StartedAt,restarts:c.RestartCount,config:hash(c.Config),hostConfig:hash(c.HostConfig),mounts:hash([...c.Mounts].sort((a,b)=>a.Destination.localeCompare(b.Destination))),networks:hash(c.NetworkSettings.Networks)}));
const a=await CrowdSec.load(join(root,'adapter-verified.json'));await a.owned();
if(a.config.containerId!==ids[0])throw Error('QA identity mismatch');
const live=process.argv.includes('--after')?null:JSON.parse(await a.call(['exec',ids[0],'cscli','decisions','list','--limit','201','-o','json']));
const data={at:new Date().toISOString(),containers,files,liveDecisions:live};
if(process.argv.includes('--after')){const before=JSON.parse(await readFile(join(out,'before.json'),'utf8'));if(JSON.stringify(before.containers)!==JSON.stringify(containers)||JSON.stringify(before.files)!==JSON.stringify(files))throw Error('Preservation mismatch');}
await writeFile(join(out,process.argv.includes('--after')?'after.json':'before.json'),JSON.stringify(data,null,2),{flag:'wx',mode:0o600});
console.log(JSON.stringify({preserved:process.argv.includes('--after'),containers:containers.map(c=>({id:c.id,state:c.state})),decisionIds:live?.flatMap((a:any)=>a.decisions.map((d:any)=>d.id))},null,2));
