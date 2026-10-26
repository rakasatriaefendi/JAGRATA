import net from 'node:net';
import https from 'node:https';
import {spawn} from 'node:child_process';
import {join,relative} from 'node:path';
import {json,validate,present,exclusive,nonce,sleep,controlIdentity,privateFile} from './state.ts';
import {request} from './control.ts';
import {fail,GuardError,windowsWorker} from './platform.ts';
import {inspectProcess,selfIdentity} from './process.ts';
import {sealed,checkRecord,readLifecycle,assess,withOperation,assertNoPending,archiveRecords} from './recovery.ts';

export function freePort(port:number){return new Promise<void>((resolve,reject)=>{const server=net.createServer();server.once('error',()=>reject(new GuardError('Console port '+port+' is occupied. Choose another --port during setup; no process was killed.')));server.listen(port,'127.0.0.1',()=>server.close(()=>resolve()))})}

export function probe(port:number,cert:Buffer,path:string){return new Promise<{status:number;body:string}>((resolve,reject)=>{
    const req=https.get({hostname:'127.0.0.1',port,path,ca:cert,timeout:2500},res=>{let text='';res.on('data',chunk=>{text+=String(chunk);if(text.length>65536)req.destroy(Error('Readiness response too large'))});res.on('end',()=>resolve({status:res.statusCode||0,body:text}))});
    const deadline=setTimeout(()=>req.destroy(Error('Readiness absolute deadline')),2500);
    req.on('timeout',()=>req.destroy(Error('Readiness timeout')));req.on('error',reject);req.on('close',()=>clearTimeout(deadline));
})}
export async function webReady(port:number,cert:Buffer){
    const [page,api]=await Promise.all([probe(port,cert,'/'),probe(port,cert,'/api/session')]);
    return page.status===200&&page.body.includes('id="login-form"')&&api.status===401&&JSON.parse(api.body).error==='Authentication required';
}
export async function status(root:string,state:string){
    const {config,key}=await controlIdentity(root,state);
    const path=join(state,'process.json');
    if(await present(join(state,'recovery.pending.json')))return {state:'RECOVERY_REQUIRED',healthy:false,detail:'Interrupted archive transaction; no automatic retry.'};
    if(!await present(path)){
        if(await present(join(state,'start.lock')))return {state:'RECOVERY_REQUIRED',healthy:false,detail:'Start lock exists without a verified worker; run start for bounded ownership assessment. No manual lock deletion.'};
        if(await present(join(state,'lifecycle-operation.lock')))return {state:'RECOVERY_REQUIRED',healthy:false,detail:'Lifecycle operation pending or interrupted; preserve its guard.'};
        return {state:'STOPPED',healthy:false};
    }
    try {
        const record=await json(path);
        if(record.version===2){checkRecord(config,key,record);const result=await assess(config,key,await readLifecycle(state),await selfIdentity());if(result.state!=='LIVE')return {state:'RECOVERY_REQUIRED',healthy:false,detail:result.reason};}
        else if(record.version===1&&(await inspectProcess(record.pid)).state==='ABSENT')return {state:'RECOVERY_REQUIRED',healthy:false,detail:'Legacy worker PID is absent, but legacy launch ownership cannot be recovered automatically.'};
        const proof=await request(config,key,record,'status');
        const healthy=proof.phase==='RUNNING'&&await privateFile(join(state,'tls.crt'),65536).then(cert=>webReady(config.port,Buffer.from(cert))).catch(()=>false);
        return {state:healthy?'RUNNING':'UNVERIFIED',phase:proof.phase,healthy,pid:proof.pid,url:`https://127.0.0.1:${config.port}/`,instance:record.instance};
    } catch {return {state:'UNVERIFIED',healthy:false,detail:'Process ownership/health could not be verified. No process will be signaled by PID or port.'};}
}
export async function start(root:string,state:string){
    const {config,key}=await validate(root,state);let instance='',child:any,already:any;
    await withOperation(state,config,key,async()=>{
        await assertNoPending(state);
        const records=await readLifecycle(state);
        if(Object.keys(records).length){
            const result=await assess(config,key,records,await selfIdentity());
            if(result.state==='LIVE'||records['process.json']?.value.version===1){
                const current=await status(root,state);if(current.state==='RUNNING'){already={...current,alreadyRunning:true};return;}
                fail('RECOVERY_REQUIRED: pending or stale ownership remains; live/legacy readiness was not verified. No recovery or probe retry.');
            }
            if(result.state!=='ORPHAN')fail('RECOVERY_REQUIRED: pending or stale ownership record. '+result.reason+' No process was signaled or record removed.');
            await archiveRecords(state,config,key,records,result.reason);
        }
        await freePort(config.port);instance=nonce();
        await exclusive(join(state,'start.lock'),JSON.stringify(sealed(key,{version:2,id:config.id,rootHash:config.rootHash,instance,at:new Date().toISOString(),osIdentity:await selfIdentity()}))+'\n');
        const args=[join(root,'installer/worker.ts'),'--state',relative(root,state),'--instance',instance];
        try{
            if(process.platform==='win32')child={pid:await windowsWorker(root,args)};
            else{child=spawn(process.execPath,args,{cwd:root,detached:true,stdio:'ignore',env:{...process.env,NODE_OPTIONS:undefined,NODE_PATH:undefined,GUARD_ADMIN_FILE:undefined,GUARD_ADAPTER_FILE:undefined,GUARD_TLS_CERT:undefined,GUARD_TLS_KEY:undefined,GUARD_PORT:undefined}});child.on('error',()=>{});child.unref();}
        }catch{fail('RECOVERY_REQUIRED: worker launch outcome uncertain; ownership records preserved.');}
    });
    if(already)return already;
    // Filesystem readiness only: worker publishes ready after HTTPS launch.
    // Exactly one on-demand status/HTTPS pair, no HTTP polling loop.
    for(let i=0;i<100;i++){
        if(await present(join(state,'process.json'))){const record=await json(join(state,'process.json'));checkRecord(config,key,record);
            if(record.instance!==instance||record.pid!==child.pid)fail('RECOVERY_REQUIRED: worker identity changed; no retry.');
            if(record.ready){const current=await status(root,state);if(current.state==='RUNNING'&&current.instance===instance&&current.pid===child.pid)return current;fail('UNVERIFIED: worker did not pass the single bounded readiness probe; no retry.');}
        }else if(!await present(join(state,'start.lock')))fail('Application worker exited during startup. Its own lifecycle evidence was archived.');
        await sleep(200);
    }
    fail('RECOVERY_REQUIRED: startup deadline expired; no forced termination or repeated HTTP probes. Inspect ownership evidence.');
}
export async function stop(root:string,state:string){
    const {config,key}=await controlIdentity(root,state);
    if(!await present(join(state,'process.json'))){if(await present(join(state,'start.lock')))fail('Ownership lock exists but process cannot be verified. No process stopped. See recovery instructions.');return {state:'STOPPED',alreadyStopped:true};}
    const record=await json(join(state,'process.json'));
    try {if(record.version===2){checkRecord(config,key,record);const result=await assess(config,key,await readLifecycle(state),await selfIdentity());if(result.state!=='LIVE')throw Error('Unverified OS process');}await request(config,key,record,'status');await request(config,key,record,'stop');}catch{fail('Ownership handshake failed. No OS process signal, PID-based kill or Docker command was issued.');}
    for(let i=0;i<50;i++){if(!await present(join(state,'process.json'))&&!await present(join(state,'start.lock')))return {state:'STOPPED'};await sleep(100)}
    fail('Verified worker is shutting down but completion is not confirmed. No forced kill was attempted.');
}
