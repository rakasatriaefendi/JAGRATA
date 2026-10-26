import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile,copyFile,symlink} from 'node:fs/promises';
import {join,dirname,resolve} from 'node:path';
import net from 'node:net';
import {execFile} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {prerequisites} from '../../installer/prerequisites.ts';
import {verifyVersions,windowsPrivacy,findNpm} from '../../installer/platform.ts';
import {localPath,sourceFiles,present,json,atomic,fingerprint,nonce,exclusive,identity} from '../../installer/state.ts';
import {setup} from '../../installer/setup.ts';
import {sign,verify,serve,request,connect} from '../../installer/control.ts';
import {start,stop,status,freePort} from '../../installer/lifecycle.ts';
import {bootstrap} from '../../apps/manager/auth.ts';
import {sealed} from '../../installer/recovery.ts';
import {selfIdentity} from '../../installer/process.ts';
const root=resolve('.'),qa=join(root,'runtime/qa-cs03-20261024/unit');
await mkdir(qa,{recursive:true});
const owner='1'.repeat(32),engineRoot='2'.repeat(64),containerId='3'.repeat(64);
const fakeRegistration={format_version:1,installation_id:'qa-cs03-unit',owner_token:owner,root_hash:engineRoot,docker_context:'desktop-linux'};
const calls:any[]=[];
async function mockRun(file:string,args:string[],options:any={}){
    calls.push({file,args,cwd:options.cwd});
    if(file!=='docker')return '';
    if(args[0]==='--version')return 'Docker version test';
    if(args.includes('context'))return JSON.stringify([{Endpoints:{docker:{Host:'unix:///var/run/docker.sock'}}}]);
    if(args.includes('info'))return 'linux|x86_64|test';
    if(args.includes('compose'))return '2.40.0';
    if(args.includes('image'))return 'linux|amd64';
    return containerId+'|crowdsec-guard-qa-cs03-unit-engine|running';
}
async function fakeEngine(args:string[]){
    if(args[2]==='context')return JSON.stringify([{Endpoints:{docker:{Host:'unix:///var/run/docker.sock'}}}]);
    if(args[2]==='container')return JSON.stringify([{Id:containerId,Image:'sha256:'+'4'.repeat(64),Name:'/crowdsec-guard-qa-cs03-unit-engine',Config:{Labels:{'io.crowdsec-guard.installation':fakeRegistration.installation_id,'io.crowdsec-guard.owner':owner,'io.crowdsec-guard.root':engineRoot,'io.crowdsec-guard.schema':'1'}},HostConfig:{Privileged:false},Mounts:[],State:{Running:true}}]);
    if(args.includes('alerts'))return '[]';
    if(args.includes('metrics'))return '{"acquisition":{},"parsers":{},"scenarios":{}}';
    return '{"scenarios":[]}';
}
const dependencies={npm:findNpm(),npmVersion:'11.19.0',run:mockRun,engineRun:fakeEngine};
async function port(){const server=net.createServer();await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const value=(server.address() as any).port;await new Promise<void>(r=>server.close(()=>r()));return value}
async function fixture(){
    const directory=join(qa,'project space ü '+nonce().slice(0,8));await mkdir(directory,{recursive:true});
    const files=[...sourceFiles,'config/console-launcher.example.json','setup.ps1','guard.ps1','setup.sh','guard.sh'];
    for(const file of files){await mkdir(dirname(join(directory,file)),{recursive:true});await copyFile(join(root,file),join(directory,file))}
    const input=join(directory,'runtime/input');await mkdir(input,{recursive:true,mode:0o700});
    if(process.platform==='win32')await windowsPrivacy([input],true);
    const registration=join(input,'registration.json'),adminFile=join(input,'admin.json');
    await exclusive(registration,JSON.stringify(fakeRegistration));await bootstrap(adminFile,'unit-auditor','unit-only-long-password-2026');
    const state=await localPath(directory,'runtime/console');
    const options={registration,containerId,adminFile,nonInteractive:true,port:await port(),dependencies};
    return {directory,state,options};
}
test('unsupported Node and npm versions are rejected',()=>{for(const version of ['v22.1.0','bad'])assert.throws(()=>verifyVersions(version,'11.19.0'));assert.throws(()=>verifyVersions('24.21.0','8.0.0'));verifyVersions('24.21.0','11.19.0')});
test('missing npm fails before Docker or state mutation',async()=>{await assert.rejects(prerequisites('desktop-linux',{npm:null}),/npm is missing/)});
test('missing Docker CLI is distinct from an unavailable local daemon',async()=>{
    await assert.rejects(prerequisites('desktop-linux',{...dependencies,run:async(file:string,args:string[])=>{if(args[0]==='--version')throw Error();return mockRun(file,args)}}),/CLI is missing/);
    await assert.rejects(prerequisites('desktop-linux',{...dependencies,run:async(file:string,args:string[])=>{if(args.includes('info'))throw Error();return mockRun(file,args)}}),/daemon is unavailable/);
});
test('missing or old Compose fails separately',async()=>{for(const version of [null,'1.29.0','2.19.0'])await assert.rejects(prerequisites('desktop-linux',{...dependencies,run:async(file:string,args:string[])=>{if(args.includes('compose')){if(version===null)throw Error();return version}return mockRun(file,args)}}),/Compose/)});
test('remote context is refused before daemon access',async()=>{const seen:string[][]=[];await assert.rejects(prerequisites('remote',{...dependencies,run:async(file:string,args:string[])=>{seen.push(args);if(args.includes('context'))return '[{"Endpoints":{"docker":{"Host":"tcp://remote:2375"}}}]';return mockRun(file,args)}}),/Remote/);assert(!seen.some(a=>a.includes('info')))});
test('state path traversal, external state and symlink boundaries are rejected',async()=>{for(const path of ['../elsewhere','config/console','runtime/../other','C:/outside'])await assert.rejects(localPath(root,path));const dir=await localPath(root,'runtime/qa-cs03-20261024/path with spaces');assert(dir.includes('path with spaces'))});
test('a real directory link under runtime is refused before any state access',async()=>{const area=join(qa,'link-fixture-'+nonce());await mkdir(join(area,'runtime'),{recursive:true});await mkdir(join(area,'target'));await symlink(join(area,'target'),join(area,'runtime/link'),process.platform==='win32'?'junction':'dir');await assert.rejects(localPath(area,'runtime/link'),/Linked/)});
test('HMAC protocol rejects forged identity and replay; only valid stop invokes callback',async t=>{
    const config={id:'console-test',rootHash:'root'},key=randomBytes(32).toString('hex'),instance=nonce();let stops=0;
    const server=await serve(config,key,instance,()=>({phase:'RUNNING'}),()=>{stops++});t.after(()=>new Promise<void>(r=>server.close(()=>r())));
    const record={...config,instance,pid:process.pid,controlPort:(server.address() as any).port};assert.equal((await request(config,key,record,'status')).phase,'RUNNING');
    await assert.rejects(request(config,'wrong-key',record,'stop'));assert.equal(stops,0);
    const body={op:'status',...config,instance,challenge:nonce(),at:Date.now()},wire=sign(key,body);
    assert.equal(verify(key,await connect(record.controlPort,wire)).phase,'RUNNING');await assert.rejects(connect(record.controlPort,wire));
    await request(config,key,record,'stop');await new Promise(r=>setTimeout(r,20));assert.equal(stops,1);
});
test('port conflict leaves the unrelated listener alive',async t=>{const listener=net.createServer();await new Promise<void>(r=>listener.listen(0,'127.0.0.1',r));t.after(()=>new Promise<void>(r=>listener.close(()=>r())));await assert.rejects(freePort((listener.address() as any).port),/occupied/);assert(listener.listening)});
test('Windows root wrapper reports missing Node without attempting dependencies', {skip:process.platform!=='win32'},async()=>{
    const command=join(process.env.SystemRoot!,'System32/WindowsPowerShell/v1.0/powershell.exe');
    const output=await new Promise<any>(r=>execFile(command,['-NoProfile','-ExecutionPolicy','Bypass','-File',join(root,'guard.ps1'),'version'],{env:{...process.env,PATH:''},windowsHide:true},(e,out,err)=>r({code:e?.code,out:String(out)+String(err)})));
    assert.notEqual(output.code,0);assert.match(output.out,/Node.js 24/);
});
test('fresh setup, existing-config preservation, invalid requested settings and interrupted recovery',async()=>{
    const f=await fixture();const before=calls.length;
    // Missing credentials leaves a journal, not an implicit account or reset.
    await assert.rejects(setup(f.directory,f.state,{...f.options,adminFile:undefined},()=>{}),/administrator username/);
    assert.equal((await json(join(f.state,'setup.json'))).phase,'PREPARING');assert(!await present(join(f.state,'admin.json')));
    const ready=await setup(f.directory,f.state,f.options,()=>{});assert(!ready.unchanged);
    const names=['config.json','admin.json','adapter.json','control.key','tls.key','tls.crt','setup.json'];
    const original=await Promise.all(names.map(name=>readFile(join(f.state,name),'utf8')));
    assert.equal((await setup(f.directory,f.state,f.options,()=>{})).unchanged,true);
    assert.deepEqual(await Promise.all(names.map(name=>readFile(join(f.state,name),'utf8'))),original);
    await assert.rejects(setup(f.directory,f.state,{...f.options,port:f.options.port+1},()=>{}),/port differs/);
    await assert.rejects(setup(f.directory,f.state,{...f.options,containerId:'a'.repeat(64)},()=>{}),/engine ID differs/);
    assert.equal(calls.slice(before).filter(c=>c.args.includes('ci')).length,2);
    assert(calls.slice(before).filter(c=>c.args.includes('ci')).every(c=>c.args.includes('--ignore-scripts')&&c.cwd.startsWith(f.directory)));
});
test('application lifecycle under a spaced/unicode fixture path; duplicate start, forged PID stop, restart',async t=>{
    const f=await fixture();await setup(f.directory,f.state,f.options,()=>{});
    t.after(async()=>{try{await stop(f.directory,f.state)}catch{}});
    assert.equal((await status(f.directory,f.state)).state,'STOPPED');
    const concurrent=await Promise.allSettled([start(f.directory,f.state),start(f.directory,f.state)]);
    const launched=concurrent.filter(x=>x.status==='fulfilled');assert.equal(launched.length,1,'Only one concurrent start may launch');
    const first=(launched[0] as PromiseFulfilledResult<any>).value;assert.equal(first.state,'RUNNING');
    assert((await setup(f.directory,f.state,f.options,()=>{})).unchanged);
    const duplicate=await start(f.directory,f.state);assert(duplicate.alreadyRunning);assert.equal(duplicate.pid,first.pid);
    const original=await json(join(f.state,'process.json'));await atomic(join(f.state,'process.json'),{...original,pid:original.pid+1});
    await assert.rejects(stop(f.directory,f.state),/Ownership handshake failed/);
    await atomic(join(f.state,'process.json'),original);assert.equal((await status(f.directory,f.state)).state,'RUNNING');
    // Expired/source-changed state must still permit authenticated self-stop.
    const journal=await json(join(f.state,'setup.json'));await atomic(join(f.state,'setup.json'),{...journal,fingerprint:'modified'});
    assert.equal((await stop(f.directory,f.state)).state,'STOPPED');await atomic(join(f.state,'setup.json'),journal);
    const second=await start(f.directory,f.state);assert.notEqual(second.instance,first.instance);await stop(f.directory,f.state);
    assert(!await present(join(f.state,'start.lock')));assert(!await present(join(f.state,'process.json')));
});
test('partial worker startup failure preserves state and releases only its own lock',async()=>{
    const f=await fixture();await setup(f.directory,f.state,f.options,()=>{});
    await writeFile(join(f.directory,'apps/manager/server.ts'),"throw Error('Controlled isolated startup failure');\nexport function launch(){}\n",'utf8');
    const journal=await json(join(f.state,'setup.json'));await atomic(join(f.state,'setup.json'),{...journal,fingerprint:await fingerprint(f.directory)});
    await assert.rejects(start(f.directory,f.state),/exited during startup/);
    assert(!await present(join(f.state,'start.lock')));assert(await present(join(f.state,'admin.json')));assert(await present(join(f.state,'adapter.json')));
});
test('simulated prior-boot records recover through real start, preserve evidence and remain idempotent',async t=>{
    const f=await fixture();await setup(f.directory,f.state,f.options,()=>{});
    t.after(async()=>{try{await stop(f.directory,f.state)}catch{}});
    const config=await json(join(f.state,'config.json')),key=(await readFile(join(f.state,'control.key'),'utf8')).trim(),oldInstance=nonce();
    const osIdentity={...await selfIdentity(),boot:'simulated-prior-boot'};
    const common={version:2,id:config.id,rootHash:config.rootHash,instance:oldInstance,osIdentity};
    const lock=JSON.stringify(sealed(key,common)),record=JSON.stringify(sealed(key,{...common,pid:osIdentity.pid,controlPort:f.options.port,ready:true}));
    await exclusive(join(f.state,'start.lock'),lock);await exclusive(join(f.state,'process.json'),record);
    const files=['admin.json','tls.crt','tls.key','adapter.json','config.json','setup.json','control.key'];
    const before=await Promise.all(files.map(p=>readFile(join(f.state,p),'utf8')));
    const current=await start(f.directory,f.state);assert.equal(current.state,'RUNNING');assert.notEqual(current.instance,oldInstance);
    assert.equal((await start(f.directory,f.state)).pid,current.pid);
    const {readdir}=await import('node:fs/promises');const archives=await readdir(join(f.state,'lifecycle-evidence'));let found=false;
    for(const archive of archives){const raw=await readFile(join(f.state,'lifecycle-evidence',archive,'start.lock'),'utf8');if(raw===lock){assert.equal(await readFile(join(f.state,'lifecycle-evidence',archive,'process.json'),'utf8'),record);found=true}}
    assert(found,'Exact prior-boot evidence archived');await stop(f.directory,f.state);
    assert.deepEqual(await Promise.all(files.map(p=>readFile(join(f.state,p),'utf8'))),before);
});
test('invalid configuration and orphan process records fail closed without file replacement',async t=>{
    const f=await fixture();await setup(f.directory,f.state,f.options,()=>{});
    const configuration=await readFile(join(f.state,'config.json'),'utf8'),administrator=await readFile(join(f.state,'admin.json'),'utf8');
    await writeFile(join(f.state,'config.json'),'{invalid json');await assert.rejects(start(f.directory,f.state));assert.equal(await readFile(join(f.state,'admin.json'),'utf8'),administrator);
    await writeFile(join(f.state,'config.json'),configuration);
    const sockets=new Set<any>();
    const fake=net.createServer(socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));socket.on('data',()=>socket.end('{}\n'));socket.setTimeout(1000,()=>socket.destroy())});
    await new Promise<void>(r=>fake.listen(0,'127.0.0.1',r));t.after(()=>new Promise<void>(r=>{fake.close(()=>r());for(const socket of sockets)socket.destroy()}));
    const c=JSON.parse(configuration);await atomic(join(f.state,'process.json'),{...c,instance:nonce(),pid:process.pid+1,controlPort:(fake.address() as any).port});
    assert.equal((await status(f.directory,f.state)).state,'RECOVERY_REQUIRED');await assert.rejects(start(f.directory,f.state),/pending|stale/);await assert.rejects(stop(f.directory,f.state),/handshake/);
    assert.equal(await readFile(join(f.state,'admin.json'),'utf8'),administrator);
});
