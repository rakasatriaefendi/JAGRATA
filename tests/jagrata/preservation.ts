// Read-only installation/Docker/evidence capture; writes only a new task evidence file.
import {readFile,readdir,lstat,mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {resolve,join,relative} from 'node:path';
import {pathToFileURL} from 'node:url';
import https from 'node:https';
import {status} from '../../installer/lifecycle.ts';
import {validate} from '../../installer/state.ts';
import {execute} from '../../apps/manager/adapter.ts';
const root=resolve('.'),state=join(root,'runtime/console');
export const out=join(root,'runtime/qa-jagrata-preservation-20261025');
const digest=(x:any)=>createHash('sha256').update(typeof x==='string'||Buffer.isBuffer(x)?x:JSON.stringify(x)).digest('hex');
async function files(dir:string,acc:any,strict=false){let entries;try{entries=await readdir(dir,{withFileTypes:true})}catch(e:any){if(!strict&&['EPERM','EACCES'].includes(e.code)){acc[relative(root,dir).replaceAll('\\','/')]='UNREADABLE_'+e.code;return}throw e}for(const e of entries){const p=join(dir,e.name),key=relative(root,p).replaceAll('\\','/');if(e.isSymbolicLink()){if(strict)throw Error('Linked active state refused');const s=await lstat(p,{bigint:true});acc[key]='LINK_NOT_FOLLOWED:'+s.dev+':'+s.ino;continue}if(e.isDirectory())await files(p,acc,strict);else if(e.isFile()){try{const hash=createHash('sha256');for await(const b of createReadStream(p))hash.update(b);acc[key]=hash.digest('hex')}catch(error:any){if(!strict&&['EPERM','EACCES'].includes(error.code))acc[key]='UNREADABLE_'+error.code;else throw error}}}}
export async function capture(){
 const hashes:any={};await files(state,hashes,true);
 for(const d of await readdir(join(root,'runtime'),{withFileTypes:true}))if(d.isDirectory()&&/^qa-cs0[1-5](?:-|$)/.test(d.name))await files(join(root,'runtime',d.name),hashes);
 for(const d of ['docs/design/cs02','docs/design/cs04','docs/design/cs05']){try{await files(join(root,d),hashes)}catch(e:any){if(e.code!=='ENOENT')throw e}}
 for(const name of await readdir(join(root,'docs')))if(/^CS0[1-5].*\.md$/.test(name))hashes['docs/'+name]=digest(await readFile(join(root,'docs',name)));
 for(const p of ['fixtures/logs/ssh/auth.log','fixtures/logs/web/access.log'])hashes[p]=digest(await readFile(join(root,p)));
 const ids=['eab16c3f3d6b699854c96103b1482dfa4fe946bc2301626b0614db1416e497b4','63a6462c8beba871d6f2adb0b52bc8ab09dc6950c38c9559780f7c88d52fd307','ebe24d67e2fe2b81a53d5de96e777b7ba00f955e5b4df547bb55fe5487fcf07b'];
 const data=JSON.parse(await execute(['--context','desktop-linux','container','inspect',...ids]));
 const containers=data.map((c:any)=>({id:c.Id,state:c.State.Status,pid:c.State.Pid,startedAt:c.State.StartedAt,restarts:c.RestartCount,image:c.Image,config:digest(c.Config),hostConfig:digest(c.HostConfig),mounts:digest([...c.Mounts].sort((a,b)=>a.Destination.localeCompare(b.Destination))),networks:digest(c.NetworkSettings.Networks)}));
 const inventory:any={};for(const kind of ['container','network','volume'])inventory[kind]=(await execute(['--context','desktop-linux',kind,'ls','--format','{{json .}}'])).trim().split('\n').filter(Boolean).map(l=>{const x=JSON.parse(l);return kind==='container'?{id:x.ID,names:x.Names}:kind==='network'?{id:x.ID,name:x.Name}:{name:x.Name}}).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
 const health=await status(root,state);if(health.state!=='RUNNING'||health.url!=='https://127.0.0.1:44351/')throw Error('Expected running existing Console not verified');
 let sourceGate='PASS';try{await validate(root,state)}catch(e:any){if(!String(e.message).includes('Application sources/lockfile changed'))throw e;sourceGate='SOURCE_FINGERPRINT_REVALIDATION_REQUIRED'}
 const pkg=await readFile(join(root,'package.json'));
 return {at:new Date().toISOString(),files:hashes,containers,inventory,health,sourceGate,packageHash:digest(pkg),scripts:JSON.parse(pkg.toString()).scripts};
}
export async function request(path:string){const ca=await readFile(join(state,'tls.crt'));return new Promise<any>((done,reject)=>{const r=https.get({hostname:'127.0.0.1',port:44351,path,ca,rejectUnauthorized:true,timeout:5000},res=>{const authorized=res.socket.authorized;let text='';res.on('data',b=>{text+=b;if(text.length>2*1024*1024)r.destroy(Error('Response limit'))});res.on('end',()=>done({status:res.statusCode,body:text,tlsAuthorized:authorized}))});r.on('error',reject);r.on('timeout',()=>r.destroy(Error('HTTPS deadline')))})}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const after=process.argv.includes('--after');const result=await capture();
 if(after){const previous=JSON.parse(await readFile(join(out,'before.json'),'utf8'));for(const k of ['files','containers','inventory','health','packageHash','scripts'])if(digest(previous[k])!==digest(result[k]))throw Error('Preservation mismatch: '+k)}else{let created=false;try{await mkdir(out,{mode:0o700});created=true}catch(e:any){if(e.code!=='EEXIST')throw e}if(process.platform==='win32'){const {windowsPrivacy}=await import('../../installer/platform.ts');await windowsPrivacy([out],created)}}
 const web=await request('/');if(web.status!==200||!web.tlsAuthorized)throw Error('Existing HTTPS endpoint failed verification');
 await writeFile(join(out,after?'after.json':'before.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({preserved:after,files:Object.keys(result.files).length,application:result.health.state,url:result.health.url,sourceGate:result.sourceGate,tlsVerified:true}));
}
