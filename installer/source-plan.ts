// Generates a candidate deployment only. This module never executes Docker.
import {mkdir,open} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomBytes} from 'node:crypto';
import {Sources,acquisition,noLinks,sourceError} from '../apps/manager/sources.ts';
import {CrowdSec} from '../apps/manager/adapter.ts';
export const engineImage='crowdsecurity/crowdsec:v1.8.1@sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a';
export async function sourcePlan(store:Sources){
 const db=await store.load(),enabled=db.sources.filter((s:any)=>s.enabled&&!s.removed);
 if(!enabled.length)throw sourceError('Enable at least one source before generating a candidate deployment.');
 const inodes=new Set(),fileIdentities=new Map();for(const s of enabled){const v=await store.validate({name:s.name,type:s.type,path:s.path,enabled:s.enabled,consent:true});if(inodes.has(v.fileIdentity))throw sourceError('Two sources resolve to the same file identity.');inodes.add(v.fileIdentity);fileIdentities.set(s.id,v.fileIdentity)}
 const plans=join(store.dir,'plans');try{await mkdir(plans,{mode:0o700})}catch(e:any){if(e.code!=='EEXIST')throw e}await noLinks(plans,false);
 const out=join(plans,'plan-'+randomBytes(8).toString('hex'));await mkdir(out,{mode:0o700});
 const write=async(name:string,data:string)=>{const f=await open(join(out,name),'wx',0o600);try{await f.writeFile(data)}finally{await f.close()}};
 const c=store.adapter.config,id=c.installationId,base='crowdsec-guard-'+id;
 const labels={'io.crowdsec-guard.installation':id,'io.crowdsec-guard.owner':c.owner,'io.crowdsec-guard.root':c.rootHash,'io.crowdsec-guard.schema':'1'};
 const mounts:any[]=[{type:'volume',source:'data',target:'/var/lib/crowdsec/data'},{type:'volume',source:'config',target:'/etc/crowdsec'}];
 for(const s of enabled){const name=`guard-${s.id}.yaml`;await write(name,acquisition(s));mounts.push({type:'bind',source:s.path,target:s.containerPath,read_only:true,bind:{create_host_path:false}},{type:'bind',source:join(out,name),target:'/etc/crowdsec/acquis.d/'+name,read_only:true,bind:{create_host_path:false}})}
 const compose={name:base,services:{crowdsec:{image:engineImage,container_name:base+'-engine',labels,restart:'no',security_opt:['no-new-privileges:true'],pids_limit:256,mem_limit:'1g',logging:{driver:'json-file',options:{'max-size':'10m','max-file':'3'}},environment:{COLLECTIONS:'crowdsecurity/linux crowdsecurity/sshd crowdsecurity/nginx',DISABLE_ONLINE_API:'true',NO_HUB_UPGRADE:'true',TZ:'UTC'},volumes:mounts,networks:['guardnet']}},volumes:{data:{name:base+'-data',labels},config:{name:base+'-config',labels}},networks:{guardnet:{name:base+'-guardnet',labels,driver:'bridge'}}};
 await write('compose.json',JSON.stringify(compose,null,2)+'\n');
 await write('manifest.json',JSON.stringify({version:1,identity:store.identity,revision:db.revision,createdAt:new Date().toISOString(),sources:enabled.map((s:any)=>({id:s.id,type:s.type,path:s.path,containerPath:s.containerPath,fileIdentity:fileIdentities.get(s.id)})),notice:'Candidate only. Operator must review identity, exact files, existing resources and image platform. Never recreate either protected CS01/legacy engine.'},null,2)+'\n');
 return {file:join(out,'compose.json'),installationId:id,container:base+'-engine',volumes:[base+'-data',base+'-config'],network:base+'-guardnet',sourceCount:enabled.length,notice:'Candidate for this installation\'s single engine and Compose project, containing all enabled sources. Adding a source does not allocate another engine, project, network or data volume. Changed mounts may require separately approved recreation of the same service, retaining its installation identity and persistent volumes. No Docker operation performed; never run up or recreate blindly.'};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const args=process.argv.slice(2);if(args.length!==4||args[0]!=='--adapter'||args[2]!=='--sources'){console.error('Usage: node installer/source-plan.ts --adapter <private adapter.json> --sources <project-local sources directory>');process.exitCode=1}
 else try{console.log(JSON.stringify(await sourcePlan(new Sources(resolve(args[3]),await CrowdSec.load(resolve(args[1])))),null,2))}catch(e:any){console.error(e.public?e.message:'Plan refused. Check explicit private configuration; no Docker operation ran.');process.exitCode=1}
}
