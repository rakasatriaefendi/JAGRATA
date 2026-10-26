import {readFile,readdir} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {findNpm,run,verifyVersions,fail} from './platform.ts';
import {present} from './state.ts';
export async function prerequisites(context:string,dependencies:any={}){
    const execute=dependencies.run||run;
    const npm=dependencies.npm===undefined?findNpm():dependencies.npm;
    if(!npm)fail('npm is missing. Install a compatible Node.js/npm distribution separately; no global installation attempted.');
    let npmVersion:string;
    try{npmVersion=dependencies.npmVersion||JSON.parse(await readFile(join(dirname(npm),'../package.json'),'utf8')).version;}catch{fail('npm installation metadata is missing or broken.');}
    verifyVersions(dependencies.nodeVersion||process.versions.node,npmVersion);
    await execute('docker',['--version']).catch(()=>fail('Docker CLI is missing. Install Docker separately.'));
    if(!/^[a-zA-Z0-9_.-]{1,64}$/.test(context))fail('An explicit local Docker context is required.');
    const prefix=['--context',context];
    let parsed:any;
    try{parsed=JSON.parse(await execute('docker',[...prefix,'context','inspect',context]));}catch{fail('Docker context is missing or unreadable. No daemon contacted.');}
    const endpoint=parsed[0]?.Endpoints?.docker?.Host;
    if(typeof endpoint!=='string'||!(endpoint.startsWith('npipe:////./pipe/')||endpoint.startsWith('unix:///')))fail('Remote Docker context rejected before daemon access. Select a local Linux engine.');
    const daemon=await execute('docker',[...prefix,'info','--format','{{.OSType}}|{{.Architecture}}|{{.ServerVersion}}']).catch(()=>fail('Docker CLI exists but the local daemon is unavailable. Start Docker yourself; setup will not start it.'));
    if(!daemon.startsWith('linux|'))fail('A local Linux container engine is required; Windows containers are unsupported.');
    const compose=await execute('docker',[...prefix,'compose','version','--short']).catch(()=>fail('Docker Compose v2 support is missing. Install/enable it separately.'));
    const version=compose.replace(/^v/,'').split('.').map(Number);
    if(version[0]!==2||version[1]<20)fail('Docker Compose2.20+ is required by the existing engine configuration.');
    return {npm,npmVersion,context,daemon,compose,platform:process.platform,architecture:process.arch};
}

export async function registrations(root:string){
    const candidates=[join(root,'config/installation.json')];
    const directory=join(root,'runtime');
    if(await present(directory))for(const entry of await readdir(directory,{withFileTypes:true})){
        if(entry.isDirectory()&&!entry.isSymbolicLink()&&entry.name.startsWith('qa-'))candidates.push(join(directory,entry.name,'config/installation.json'));
    }
    const found=[];
    for(const path of candidates){try{const text=await readFile(path,'utf8');if(text.length>16384)continue;const data=JSON.parse(text);if(/^qa-[a-z0-9-]+$/.test(data.installation_id)&&/^[a-zA-Z0-9_.-]{1,64}$/.test(data.docker_context))found.push({path,id:data.installation_id,context:data.docker_context});}catch{}}
    return found;
}
export async function knownContainers(context:string,execute=run){
    return execute('docker',['--context',context,'container','ls','-a','--no-trunc','--filter','name=^/crowdsec-guard','--format','{{.ID}}|{{.Names}}|{{.Status}}']);
}
