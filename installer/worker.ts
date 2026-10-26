import {dirname,resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {localPath,validate,json,atomic,exclusive,log,identity} from './state.ts';
import {serve} from './control.ts';
import {selfIdentity} from './process.ts';
import {sealed,checkRecord,withOperation,assertNoPending,finalizeOwn} from './recovery.ts';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
let state='',instance='',rootHash='',phase='STARTING',manager:any,control:any,closing=false;
let config:any,key='',record:any,published=false;
async function shutdown(code=0){
    if(closing)return;closing=true;phase='STOPPING';
    const deadline=setTimeout(()=>process.exit(1),6000);deadline.unref();
    try{
    if(manager){manager.closeAllConnections();await new Promise<void>(r=>manager.close(()=>r()))}
    if(control)await new Promise<void>(r=>control.close(()=>r()));
    if(published){await finalizeOwn(state,config,key,instance);await log(state,code?'startup-failed':'application-stopped').catch(()=>{});}
    }catch{code=1}finally{clearTimeout(deadline)}
    process.exit(code);
}
const watchdog=setTimeout(()=>shutdown(1),25000);watchdog.unref();
try {
    if(process.argv[2]!=='--state'||process.argv[4]!=='--instance'||!/^[a-f0-9]{48}$/.test(process.argv[5]||''))throw Error('Invalid worker invocation');
    state=await localPath(root,process.argv[3]);instance=process.argv[5];
    rootHash=await identity(root);
    const lock=await json(join(state,'start.lock'));
    if(lock.instance!==instance||lock.rootHash!==rootHash)throw Error('Worker lock mismatch');
    ({config,key}=await validate(root,state));checkRecord(config,key,lock);
    if(lock.id!==config.id)throw Error('Worker installation mismatch');
    process.once('SIGINT',()=>void shutdown());process.once('SIGTERM',()=>void shutdown());
    process.once('uncaughtException',()=>void shutdown(1));process.once('unhandledRejection',()=>void shutdown(1));
    await log(state,'application-starting');
    control=await serve(config,key,instance,()=>({phase}),()=>void shutdown());
    record={version:2,id:config.id,rootHash,instance,pid:process.pid,controlPort:control.address().port,startedAt:new Date().toISOString(),ready:false,osIdentity:await selfIdentity()};
    await withOperation(state,config,key,async()=>{await assertNoPending(state);const current=checkRecord(config,key,await json(join(state,'start.lock')));if(current.instance!==instance)throw Error('Worker lock changed');await exclusive(join(state,'process.json'),JSON.stringify(sealed(key,record))+'\n');published=true});
    Object.assign(process.env,{GUARD_ADMIN_FILE:join(state,'admin.json'),GUARD_ADAPTER_FILE:join(state,'adapter.json'),GUARD_TLS_CERT:join(state,'tls.crt'),GUARD_TLS_KEY:join(state,'tls.key'),GUARD_PORT:String(config.port)});
    const {launch}=await import('../apps/manager/server.ts');manager=await launch();phase='RUNNING';
    await withOperation(state,config,key,async()=>{const current=checkRecord(config,key,await json(join(state,'process.json')));if(current.instance!==instance)throw Error('Worker record changed');await atomic(join(state,'process.json'),sealed(key,{...record,ready:true}))});
    clearTimeout(watchdog);await log(state,'application-ready');
} catch {clearTimeout(watchdog);await shutdown(1)}
