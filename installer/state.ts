import {createHash,randomBytes,createPrivateKey,createPublicKey,X509Certificate} from 'node:crypto';
import {readFile,open,lstat,mkdir,readdir,realpath,rename,unlink} from 'node:fs/promises';
import {resolve,relative,sep,dirname,join,isAbsolute} from 'node:path';
import {Auth} from '../apps/manager/auth.ts';
import {CrowdSec} from '../apps/manager/adapter.ts';
import {fail,windowsPrivacy} from './platform.ts';

export const nonce=()=>randomBytes(24).toString('hex');
export const hash=(value:string|Buffer)=>createHash('sha256').update(value).digest('hex');
export const sleep=(ms:number)=>new Promise(r=>setTimeout(r,ms));
export async function present(path:string){try{await lstat(path);return true}catch(e:any){if(e.code==='ENOENT')return false;throw e}}

export async function identity(root:string){const path=await realpath(root);return hash(process.platform==='win32'?path.toLowerCase():path)}
export async function localPath(root:string,relativePath:string){
    if(typeof relativePath!=='string'||isAbsolute(relativePath)||relativePath.includes('..'))fail('State path must be a relative directory below runtime/.');
    const path=resolve(root,relativePath),parts=relative(root,path).split(sep);
    if(parts[0]!=='runtime'||parts.length<2||parts.some(p=>!p||p==='..'))fail('State must be below this repository runtime/ directory.');
    let parent=root;
    for(const part of parts){parent=join(parent,part);try{const info=await lstat(parent);if(info.isSymbolicLink()||!info.isDirectory())fail('Linked or non-directory state paths are not allowed.')}catch(e:any){if(e.code!=='ENOENT')throw e}}
    return path;
}

export async function privateFile(path:string,max=16384){
    const info=await lstat(path).catch(()=>fail('A required private file is missing. Rerun setup with its explicit inputs.'));
    if(!info.isFile()||info.isSymbolicLink()||info.size>max||(process.platform!=='win32'&&(info.mode&0o077)))fail('Required state must be a private, bounded regular file.');
    return readFile(path,'utf8');
}
export async function json(path:string){try{return JSON.parse(await privateFile(path))}catch{fail('Configuration is missing, malformed or not private. No file was overwritten.')}}
export async function exclusive(path:string,data:string){const file=await open(path,'wx',0o600);try{await file.writeFile(data)}finally{await file.close()}}
export async function atomic(path:string,data:any){
    if(await present(path))await privateFile(path,128*1024);
    const temporary=path+'.pending-'+nonce();await exclusive(temporary,JSON.stringify(data,null,2)+'\n');await rename(temporary,path);
}

export async function secureDirectory(root:string,state:string){
    await localPath(root,relative(root,state));
    if(!await present(state))await mkdir(state,{recursive:true,mode:0o700});
    const entries=await readdir(state);
    const rootHash=await identity(root);
    if(entries.length){const journal=await json(join(state,'setup.json'));if(journal.rootHash!==rootHash||!/^console-[a-f0-9]{24}$/.test(journal.id))fail('State belongs to another or unknown installation; choose an empty directory.');}
    if(process.platform==='win32')await windowsPrivacy([state],entries.length===0);
    else {const info=await lstat(state);if((info.mode&0o077)||info.uid!==process.getuid?.())fail('State directory must be owned by this user with mode700.');}
    return rootHash;
}

export const sourceFiles=[
    'package.json','package-lock.json','.npmrc',
    'apps/manager/package.json','apps/manager/package-lock.json','apps/manager/server.ts',
    'apps/manager/auth.ts','apps/manager/adapter.ts','apps/manager/sources.ts','apps/manager/remediation.ts','apps/manager/security.ts','apps/manager/security-read.ts','apps/manager/security-plans.ts','apps/manager/security-actions.ts','apps/manager/security-external.ts','packages/contracts/security.ts','apps/console/index.html',
    'apps/console/client.js','apps/console/styles.css','packages/contracts/console.ts',
    'docs/design/cs01-5/prototype/styles.css','installer/worker.ts','installer/lifecycle.ts',
    'installer/state.ts','installer/control.ts','installer/platform.ts','installer/setup.ts','installer/process.ts','installer/recovery.ts',
    'installer/cli.ts','installer/source-plan.ts','installer/prerequisites.ts','apps/manager/password.ts'
];
export async function fingerprint(root:string){const parts=[];for(const file of sourceFiles)parts.push(file+':'+hash(await readFile(join(root,file))));return hash(parts.join('\n'))}

export function configValid(config:any,rootHash:string){
    if(!config||config.version!==1||config.rootHash!==rootHash||!/^console-[a-f0-9]{24}$/.test(config.id)||config.listenHost!=='127.0.0.1'||config.engineMode!=='explicit-existing-read-only'||!Number.isInteger(config.port)||config.port<1024||config.port>65535||!/^[a-f0-9]{64}$/.test(config.controlKeyHash))fail('Incompatible application configuration or moved root. No automatic adoption/migration.');
    return config;
}
export async function controlIdentity(root:string,state:string){
    await localPath(root,relative(root,state));
    const config=configValid(await json(join(state,'config.json')),await identity(root));
    const journal=await json(join(state,'setup.json'));
    if(journal.id!==config.id||journal.rootHash!==config.rootHash)fail('Application ownership journal mismatch.');
    const key=(await privateFile(join(state,'control.key'))).trim();
    if(!/^[a-f0-9]{64}$/.test(key)||hash(key)!==config.controlKeyHash)fail('Control identity mismatch; no process stopped.');
    if(process.platform==='win32')await windowsPrivacy([state,join(state,'config.json'),join(state,'setup.json'),join(state,'control.key')]);
    return {config,key};
}
export async function validate(root:string,state:string,requireReady=true){
    await localPath(root,relative(root,state));
    const config=configValid(await json(join(state,'config.json')),await identity(root));
    const journal=await json(join(state,'setup.json'));
    if(journal.id!==config.id||journal.rootHash!==config.rootHash||(requireReady&&journal.phase!=='READY'))fail('Setup is incomplete. Rerun the same setup command; existing files will be validated and preserved.');
    const paths=['config.json','setup.json','admin.json','adapter.json','tls.crt','tls.key','control.key'].map(name=>join(state,name));
    for(const file of paths)await privateFile(file,65536);
    if(process.platform==='win32')await windowsPrivacy([state,...paths]);
    const key=(await privateFile(join(state,'control.key'))).trim();
    if(!/^[a-f0-9]{64}$/.test(key)||hash(key)!==config.controlKeyHash)fail('Application control identity mismatch; refusing lifecycle actions.');
    await Auth.load(join(state,'admin.json'));
    const adapter=await CrowdSec.load(join(state,'adapter.json'));
    const cert=new X509Certificate(await privateFile(join(state,'tls.crt'),65536));
    const privateKey=createPrivateKey(await privateFile(join(state,'tls.key'),65536));
    if(!cert.checkIP('127.0.0.1')||Date.parse(cert.validTo)<=Date.now()+60_000||Date.parse(cert.validFrom)>Date.now()||!cert.publicKey.export({type:'spki',format:'der'}).equals(createPublicKey(privateKey).export({type:'spki',format:'der'})))fail('TLS certificate is expired, mismatched, or lacks IP SAN127.0.0.1. Supply a valid matching pair; files are preserved.');
    if(requireReady&&journal.fingerprint!==await fingerprint(root))fail('Application sources/lockfile changed. Stop the application and rerun setup.');
    return {config,key,adapter,cert:await readFile(join(state,'tls.crt'))};
}

export async function removeOwn(path:string,instance:string,rootHash:string){
    try {const value=await json(path);if(value.instance===instance&&value.rootHash===rootHash)await unlink(path);}catch{}
}
export async function log(state:string,event:string){
    const path=join(state,'application.log');let old='';
    if(await present(path))old=await privateFile(path,65536);
    const line=JSON.stringify({at:new Date().toISOString(),event})+'\n';
    // This is the launcher's own bounded event log, never a customer/engine log.
    const content=(old+line).slice(-60000);const temporary=path+'.pending-'+nonce();await exclusive(temporary,content);await rename(temporary,path);
}
