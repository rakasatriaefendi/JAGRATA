// Explicit Windows end-to-end application test. No Docker lifecycle operations.
import {execFile} from 'node:child_process';
import {mkdir,readFile,writeFile,copyFile} from 'node:fs/promises';
import {resolve,join,dirname,relative} from 'node:path';
import {randomBytes} from 'node:crypto';
import https from 'node:https';
import net from 'node:net';
import assert from 'node:assert/strict';
import {parse} from '../../installer/cli.ts';
import {registration} from '../../installer/setup.ts';
import {prerequisites} from '../../installer/prerequisites.ts';
import {sourceFiles,exclusive,hash,present,json} from '../../installer/state.ts';
import {windowsPrivacy,run} from '../../installer/platform.ts';
import {bootstrap} from '../../apps/manager/auth.ts';

if(process.platform!=='win32')throw Error('Native PowerShell acceptance requires Windows; no cross-platform PASS inferred.');
const {options}=parse(['setup',...process.argv.slice(2)]);
if(!options.registration||!/^[a-f0-9]{64}$/.test(options.containerId||''))throw Error('Explicit --registration and --container-id are required.');
const reg=await registration(resolve(options.registration)),root=resolve('.'),qa=join(root,'runtime/qa-cs03-20261024/native-'+randomBytes(4).toString('hex'));
await mkdir(qa,{recursive:true});
const fixtureRoot=join(qa,'application with spaces ü');await mkdir(fixtureRoot);
for(const file of [...sourceFiles,'setup.ps1','guard.ps1','setup.sh','guard.sh','config/console-launcher.example.json']){
    await mkdir(dirname(join(fixtureRoot,file)),{recursive:true});await copyFile(join(root,file),join(fixtureRoot,file));
}
const input=join(qa,'private-input');await mkdir(input);await windowsPrivacy([input],true);
const admin=join(input,'admin.json'),password=randomBytes(28).toString('base64url');await bootstrap(admin,'native-auditor',password);
const stateRelative='runtime/console',state=join(fixtureRoot,stateRelative),checks:string[]=[];
const ps=join(process.env.SystemRoot!,'System32/WindowsPowerShell/v1.0/powershell.exe');
async function command(script:string,args:string[],cwd=fixtureRoot,scriptRoot=fixtureRoot){
    return new Promise<{code:number;out:string}>(resolveDone=>execFile(ps,['-NoProfile','-ExecutionPolicy','Bypass','-File',join(scriptRoot,script),...args],{cwd,timeout:20000,windowsHide:true,encoding:'utf8',maxBuffer:256*1024},(error:any,out,err)=>resolveDone({code:error?(Number.isInteger(error.code)&&error.code!==0?error.code:1):0,out:String(out)+String(err)})));
}
function check(value:any,message:string){assert(value,message);checks.push(message)}
const listener=net.createServer();await new Promise<void>(r=>listener.listen(0,'127.0.0.1',r));const port=(listener.address() as any).port;await new Promise<void>(r=>listener.close(()=>r()));
async function inventory(){
    const results=[];for(const target of [options.containerId,'crowdsec-guard-engine']){
        const full=JSON.parse(await run('docker',['--context',reg.docker_context,'container','inspect',target]));const c=full[0];
        results.push({id:c.Id,name:c.Name,state:c.State.Status,image:c.Image,ports:c.HostConfig.PortBindings,mounts:c.Mounts.map((m:any)=>({type:m.Type,name:m.Name,destination:m.Destination,rw:m.RW,sourceHash:hash(m.Source)})).sort((a:any,b:any)=>a.destination.localeCompare(b.destination))});
    }
    return results;
}
await prerequisites(reg.docker_context);
const originalStateRelative=relative(root,join(qa,'root-console'));
const before=await inventory();await exclusive(join(qa,'docker-before.json'),JSON.stringify(before,null,2));
const setupArgs=['-NonInteractive','-Registration',resolve(options.registration),'-ContainerId',options.containerId,'-AdminFile',admin,'-Port',String(port)];
const secrets=[password,reg.owner_token];
let outputs='';
async function invoke(script:string,args:string[],expected=0,cwd?:string){const began=Date.now();console.log('Native step: '+script+' '+args[0]);const result=await command(script,args,cwd);console.log('Native result: '+result.code+' in '+(Date.now()-began)+'ms');outputs+=result.out;if(result.code!==expected)await writeFile(join(qa,'failure.json'),JSON.stringify({script,code:result.code,output:secrets.reduce((text,secret)=>text.split(secret).join('[REDACTED]'),result.out)},null,2));check(result.code===expected,script+' '+args[0]+' exit '+expected);if(result.code!==expected)throw Error('Native command refused; sanitized setup/lifecycle output available in process memory only.');return result.out}
function http(path:string,init:any={},certState=state){return new Promise<any>((resolveDone,reject)=>{
    // Use the generated certificate explicitly; never disable TLS validation globally.
    readFile(join(certState,'tls.crt')).then(cert=>{const request=https.request({hostname:'127.0.0.1',port,path,ca:cert,timeout:5000,...init},response=>{let body='';response.on('data',chunk=>{body+=String(chunk);if(body.length>2*1024*1024)request.destroy(Error('Response bound'))});response.on('end',()=>resolveDone({status:response.statusCode,headers:response.headers,body}))});request.on('error',reject);request.on('timeout',()=>request.destroy(Error('Timeout')));if(init.body)request.write(init.body);request.end()}).catch(reject);
})}
try {
    await invoke('setup.ps1',setupArgs);check((await json(join(state,'setup.json'))).phase==='READY','root setup activates only a validated READY receipt');
    check(await present(join(state,'npm-cache')),'npm cache is project-local');
    const preserved=['config.json','admin.json','adapter.json','tls.crt','tls.key','control.key','setup.json'];const hashes=await Promise.all(preserved.map(async name=>hash(await readFile(join(state,name)))));
    await invoke('setup.ps1',setupArgs);check(JSON.stringify(hashes)===JSON.stringify(await Promise.all(preserved.map(async name=>hash(await readFile(join(state,name)))))),'repeat root setup preserves configuration, keys and administrator byte-for-byte');
    await invoke('guard.ps1',['status'],3);
    await invoke('guard.ps1',['start']);check((await http('/')).status===200,'Console login HTML is ready');check((await http('/api/session')).status===401,'Manager requires authentication');
    const first=await json(join(state,'process.json'));
    await invoke('setup.ps1',setupArgs);check((await json(join(state,'process.json'))).pid===first.pid,'repeat setup preserves a running application without restart');
    const duplicate=await invoke('guard.ps1',['start']);check(duplicate.includes('alreadyRunning'),'root duplicate start is idempotent');check((await json(join(state,'process.json'))).pid===first.pid,'duplicate does not replace process');
    await invoke('guard.ps1',['status']);await invoke('guard.ps1',['doctor']);
    const login=await http('/api/login',{method:'POST',headers:{Origin:`https://127.0.0.1:${port}`,'Content-Type':'application/json','X-Guard-Login':'1'},body:JSON.stringify({username:'native-auditor',password})});
    check(login.status===200,'root-launched application accepts securely bootstrapped administrator');
    const cookie=login.headers['set-cookie'][0];check(['Secure','HttpOnly','SameSite=Strict'].every(flag=>cookie.includes(flag)),'secure session cookie retained');
    const authenticated={headers:{Cookie:cookie.split(';')[0]}};
    const snapshot=await http('/api/snapshot',authenticated);check(snapshot.status===200,'actual authenticated CrowdSec snapshot succeeds');
    const data=JSON.parse(snapshot.body);check(data.engine.freshness==='LIVE'&&data.engine.lapi,'actual engine observation is LIVE');
    for(const [id,ip,scenario,events] of [[1,'203.0.113.50','crowdsecurity/ssh-bf',6],[2,'198.51.100.77','crowdsecurity/http-probing',11]]){
        const response=await http('/api/alerts/'+id,authenticated);check(response.status===200,'actual alert '+id+' remains accessible');
        const a=JSON.parse(response.body).alert;check(a.id===id&&a.source===ip&&a.scenario===scenario&&a.eventCount===events&&a.startedAt==='2026-10-23T05:52:17Z','alert '+id+' matches retained CS01 evidence');
    }
    check((await http('/client.js')).status===200&&(await http('/design.css')).status===200,'actual Console script/shared theme remain available');
    await invoke('guard.ps1',['stop']);await invoke('guard.ps1',['status'],3);check(!await present(join(state,'process.json'))&&!await present(join(state,'start.lock')),'safe stop removes only matching application process records');
    await invoke('guard.ps1',['start']);const second=await json(join(state,'process.json'));check(second.instance!==first.instance,'restart produces a new process incarnation');check((await http('/api/session',authenticated)).status===401,'restart invalidates former sessions');
    await invoke('guard.ps1',['stop']);
    // Also execute the same root wrappers in the actual repository, with isolated
    // --State below this QA directory. No default user installation is created.
    const actualSetup=await command('setup.ps1',[...setupArgs,'-State',originalStateRelative],root,root);
    outputs+=actualSetup.out;check(actualSetup.code===0,'actual repository root setup succeeds with project-local npm ci');
    const actualStart=await command('guard.ps1',['start','-State',originalStateRelative],root,root);outputs+=actualStart.out;check(actualStart.code===0,'actual repository root guard start succeeds');
    const actualState=join(root,originalStateRelative);
    check((await http('/',{},actualState)).status===200,'actual root-launched Console is ready');
    const actualLogin=await http('/api/login',{method:'POST',headers:{Origin:`https://127.0.0.1:${port}`,'Content-Type':'application/json','X-Guard-Login':'1'},body:JSON.stringify({username:'native-auditor',password})},actualState);
    check(actualLogin.status===200,'actual root-launched Manager login succeeds');
    const actualSnapshot=await http('/api/snapshot',{headers:{Cookie:actualLogin.headers['set-cookie'][0].split(';')[0]}},actualState);
    check(actualSnapshot.status===200&&JSON.parse(actualSnapshot.body).engine.freshness==='LIVE','actual root launch retrieves real engine evidence');
    const actualStatus=await command('guard.ps1',['status','-State',originalStateRelative],root,root);check(actualStatus.code===0,'actual root status verifies service health');
    const actualStop=await command('guard.ps1',['stop','-State',originalStateRelative],root,root);check(actualStop.code===0,'actual root stop completes without Docker changes');
    check(!await present(join(actualState,'process.json'))&&!await present(join(actualState,'start.lock')),'actual root process incarnation safely released');
    const after=await inventory();check(JSON.stringify(before)===JSON.stringify(after),'both existing engine identities, running states, image IDs, ports and volume bindings are unchanged');
    for(const secret of secrets)check(!outputs.includes(secret),'no administrator password/ownership token in command output');
    await exclusive(join(qa,'results.json'),JSON.stringify({at:new Date().toISOString(),platform:process.platform,architecture:process.arch,checks,before,after,fixture:'intentional isolated application fixture with spaced/unicode path; no new Docker resources'},null,2));
    console.log(JSON.stringify({passed:checks.length,qa,engine:'existing CS01 QA, read only',applicationState:'STOPPED'},null,2));
}finally{try{await command('guard.ps1',['stop']);await command('guard.ps1',['stop','-State',originalStateRelative],root,root)}catch{}}
