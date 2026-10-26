import {readFile,chmod,lstat,realpath} from 'node:fs/promises';
import {join,resolve,relative,isAbsolute} from 'node:path';
import {randomBytes,X509Certificate,createPrivateKey,createPublicKey} from 'node:crypto';
import {Auth,bootstrap} from '../apps/manager/auth.ts';
import {passwordInput} from '../apps/manager/password.ts';
import {CrowdSec} from '../apps/manager/adapter.ts';
import {fail,findOpenSSL,run,windowsPrivacy} from './platform.ts';
import {prerequisites,knownContainers} from './prerequisites.ts';
import {secureDirectory,present,json,privateFile,exclusive,atomic,fingerprint,validate,hash,nonce,configValid,localPath} from './state.ts';
import {freePort,status} from './lifecycle.ts';

async function copyMissing(destination:string,content:string){
    if(await present(destination)){if(await privateFile(destination,65536)!==content)fail('Existing configuration differs from requested inputs. Files are preserved; use the original inputs or a separate intentional installation.');return;}
    await exclusive(destination,content);
}
export async function registration(path:string){
    let data:any;
    try{const raw=await readFile(path,'utf8');if(raw.length>16384)throw Error();data=JSON.parse(raw);}catch{fail('Registration file is missing, oversized or invalid JSON. Supply an explicit verified engine registration.');}
    if(data.format_version!==1||!/^qa-[a-z0-9-]+$/.test(data.installation_id)||!/^[a-zA-Z0-9_.-]{1,64}$/.test(data.docker_context)||!/^[a-f0-9]{32}$/.test(data.owner_token)||!/^[a-f0-9]{64}$/.test(data.root_hash))fail('Registration is not a supported CS-01 QA installation. Legacy engines are not adopted.');
    return data;
}
export async function tlsPair(state:string,options:any){
    const certFile=join(state,'tls.crt'),keyFile=join(state,'tls.key');
    if(Boolean(options.tlsCert)!==Boolean(options.tlsKey))fail('Supply both --tls-cert and --tls-key, or neither.');
    if(options.tlsCert){
        const sourceInfo=await lstat(resolve(options.tlsCert));if(!sourceInfo.isFile()||sourceInfo.isSymbolicLink()||sourceInfo.size>65536)fail('Supplied certificate must be a bounded regular file.');
        const cert=await readFile(resolve(options.tlsCert),'utf8');const key=await privateFile(resolve(options.tlsKey),65536);
        if(process.platform==='win32')await windowsPrivacy([resolve(options.tlsKey)]);
        const x509=new X509Certificate(cert);if(!x509.checkIP('127.0.0.1')||!x509.publicKey.export({type:'spki',format:'der'}).equals(createPublicKey(createPrivateKey(key)).export({type:'spki',format:'der'})))fail('Supplied TLS key/certificate mismatch or missing localhost IP SAN.');
        await copyMissing(certFile,cert);await copyMissing(keyFile,key);return;
    }
    if(await present(certFile)&&await present(keyFile))return;
    if(await present(certFile)||await present(keyFile))fail('Interrupted TLS preparation left one half of a pair. Preserve it; rerun with the matching --tls-cert and --tls-key from retained tls-*.pending files. No overwrite attempted.');
    const openssl=findOpenSSL();if(!openssl)fail('OpenSSL is required to generate local TLS, or provide --tls-cert/--tls-key. No package or certificate trust will be installed automatically.');
    const tag=nonce(),pendingCert=join(state,'tls-'+tag+'.crt.pending'),pendingKey=join(state,'tls-'+tag+'.key.pending');
    const request=join(state,'tls-request.cnf');
    const content='[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3\n[dn]\nCN=127.0.0.1\n[v3]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n';
    await copyMissing(request,content);
    await run(openssl,['req','-x509','-newkey','rsa:2048','-sha256','-nodes','-keyout',pendingKey,'-out',pendingCert,'-days','30','-config',request],{cwd:state});
    await chmod(pendingKey,0o600);await chmod(pendingCert,0o600);
    await copyMissing(keyFile,await privateFile(pendingKey,65536));await copyMissing(certFile,await privateFile(pendingCert,65536));
}

export async function setup(root:string,state:string,options:any,announce=(message:string)=>console.log(message)){
    const adapterPath=join(state,'adapter.json');let adapterConfig:any;
    if(await present(adapterPath))adapterConfig=await json(adapterPath);
    let reg:any;
    if(options.registration)reg=await registration(resolve(options.registration));
    if(!adapterConfig&&!reg)fail('Choose an existing verified engine registration explicitly. No engine is automatically reused or created.');
    const context=adapterConfig?.context||reg.docker_context;
    const checks=await prerequisites(context,options.dependencies||{});
    announce(`Prerequisites: ${checks.platform}/${checks.architecture}; Node${process.versions.node}; npm${checks.npmVersion}; Docker ${checks.daemon}; Compose${checks.compose}.`);
    announce('Existing Guard containers (read-only identification; none will be changed):');
    announce(await knownContainers(context,options.dependencies?.run||run));
    if(!adapterConfig){
        let containerId=options.containerId;
        if(!containerId){
            if(options.nonInteractive)fail('Noninteractive setup requires an exact --container-id; no implicit engine reuse.');
            const name='crowdsec-guard-'+reg.installation_id+'-engine';
            try{const info=JSON.parse(await run('docker',['--context',context,'container','inspect',name]));containerId=info[0].Id;}catch{fail('Selected registered engine was not found. Setup never creates/starts Docker resources.');}
        }
        adapterConfig={context:reg.docker_context,containerId,installationId:reg.installation_id,owner:reg.owner_token,rootHash:reg.root_hash};
    }
    if(reg&&JSON.stringify([adapterConfig.context,adapterConfig.installationId,adapterConfig.owner,adapterConfig.rootHash])!==JSON.stringify([reg.docker_context,reg.installation_id,reg.owner_token,reg.root_hash]))fail('Requested engine registration differs from existing application binding. Existing configuration preserved.');
    if(options.containerId&&options.containerId!==adapterConfig.containerId)fail('Requested engine ID differs from the existing binding.');
    const adapter=new CrowdSec(adapterConfig,options.dependencies?.engineRun);const engine=await adapter.owned();
    if(!/^sha256:[a-f0-9]{64}$/.test(engine.Image||''))fail('Selected engine image identity could not be verified.');
    const enginePlatform=await (options.dependencies?.run||run)('docker',['--context',context,'image','inspect',engine.Image,'--format','{{.Os}}|{{.Architecture}}']);
    if(!/^linux\|(amd64|arm64)$/.test(enginePlatform))fail('Selected engine image OS/architecture is unsupported or unknown.');
    announce('Observed engine image: '+enginePlatform+'. Native Linux/macOS/ARM compatibility is not certified by a Windows run.');
    announce(`Selected read-only engine: ${adapterConfig.installationId}; ${adapterConfig.containerId}; ${engine.State?.Running?'running':'stopped'}. Engine ownership is not reassigned.`);
    if(options.confirm&&!await options.confirm())fail('No engine selected. No application configuration created.');
    if(!engine.State?.Running)fail('Selected engine is stopped. Start it separately with exact explicit approval; setup will not start it.');
    // Actual local-API readiness, without creating decisions or replaying logs.
    const observation=await adapter.snapshot();if(!observation.engine.lapi)fail('Selected engine local API is not ready. No sample data substituted.');
    const rootHash=await secureDirectory(root,state),journalPath=join(state,'setup.json');
    let journal=await present(journalPath)?await json(journalPath):{version:1,id:'console-'+randomBytes(12).toString('hex'),rootHash,phase:'PREPARING'};
    if(!await present(journalPath))await exclusive(journalPath,JSON.stringify(journal,null,2)+'\n');
    let config:any;if(await present(join(state,'config.json')))config=configValid(await json(join(state,'config.json')),rootHash);
    if(config&&options.port!==undefined&&options.port!==config.port)fail('Requested port differs from existing configuration. No settings were overwritten.');
    if(options.username&&await present(join(state,'admin.json'))&&(await Auth.load(join(state,'admin.json'))).admin.username!==options.username)fail('Requested administrator differs from existing configuration.');
    if(await present(join(state,'process.json'))||await present(join(state,'start.lock'))){
        await validate(root,state);
        if(options.adminFile&&await privateFile(resolve(options.adminFile))!==await privateFile(join(state,'admin.json')))fail('Requested administrator differs; running installation is unchanged.');
        if(options.tlsCert||options.tlsKey)await tlsPair(state,options);
        const health=await status(root,state);
        if(health.state!=='RUNNING')fail('Application has an unresolved process record. Run guard doctor; no automatic cleanup.');
        announce('Setup already complete and application healthy. No dependency reinstall, configuration overwrite or restart.');
        return {config,unchanged:true,observation};
    }
    if(options.adminFile){const source=resolve(options.adminFile);await Auth.load(source);if(process.platform==='win32')await windowsPrivacy([source]);await copyMissing(join(state,'admin.json'),await privateFile(source));}
    if(!await present(join(state,'admin.json'))){
        if(!options.username)fail('An explicit administrator username is required.');
        if(options.nonInteractive&&!options.passwordStdin)fail('Supply --password-stdin with --username, or --admin-file containing an explicitly bootstrapped hash. Plaintext password arguments/environment are unsupported.');
        const password=await passwordInput();await bootstrap(join(state,'admin.json'),options.username,password);
    }
    await Auth.load(join(state,'admin.json'));
    await copyMissing(adapterPath,JSON.stringify(adapterConfig,null,2)+'\n');
    const keyPath=join(state,'control.key');if(!await present(keyPath))await exclusive(keyPath,randomBytes(32).toString('hex')+'\n');
    const controlKeyHash=hash((await privateFile(keyPath)).trim());
    if(!config){
        const template=JSON.parse(await readFile(join(root,'config/console-launcher.example.json'),'utf8'));
        config={version:1,id:journal.id,rootHash,listenHost:template.listenHost,engineMode:template.engineMode,port:options.port??template.port,controlKeyHash};
        configValid(config,rootHash);await freePort(config.port);await exclusive(join(state,'config.json'),JSON.stringify(config,null,2)+'\n');
    }else if(config.controlKeyHash!==controlKeyHash)fail('Existing control key does not match this installation. No key was replaced.');
    await tlsPair(state,options);
    await validate(root,state,false);
    const current=await fingerprint(root);
    if(journal.phase==='READY'&&journal.fingerprint===current){announce('Setup already complete. Existing administrator, keys, configuration and dependency receipt preserved.');return {config,unchanged:true,observation};}
    journal={...journal,phase:'DEPENDENCIES'};await atomic(journalPath,journal);
    const npmrc=join(state,'npmrc');await copyMissing(npmrc,'audit=false\nfund=false\nupdate-notifier=false\nignore-scripts=true\n');
    announce('Installing locked application dependencies: npm ci (local only; lifecycle scripts disabled).');
    const execute=options.dependencies?.run||run;
    await localPath(root,relative(root,join(state,'npm-cache')));
    for(const directory of [root,join(root,'apps/manager')]){
    const location=relative(await realpath(root),await realpath(directory));if(location.startsWith('..')||isAbsolute(location))fail('Application dependency path escapes the repository.');
    const modules=join(directory,'node_modules');if(await present(modules)){const info=await lstat(modules);if(info.isSymbolicLink()||!info.isDirectory())fail('Linked/non-directory node_modules refused; no dependency cleanup attempted.');}
    await execute(process.execPath,[checks.npm,'ci','--engine-strict','--ignore-scripts','--no-audit','--no-fund','--global=false','--prefix',directory,'--workspaces=false','--cache',join(state,'npm-cache'),'--userconfig',npmrc,'--logs-max','5'],{
        cwd:directory,timeout:120000,
        env:{...process.env,NODE_OPTIONS:undefined,NODE_PATH:undefined,NPM_CONFIG_CACHE:join(state,'npm-cache'),NPM_CONFIG_UPDATE_NOTIFIER:'false',NPM_CONFIG_LOGS_MAX:'5'}
    }).catch(()=>fail('npm ci failed. Existing configuration/keys are preserved. Rerun the same setup command to resume; no rollback or global installation was attempted.'));
    }
    announce('No build script is declared: Node24 runs TypeScript directly. Checking actual entrypoints/assets.');
    for(const file of ['apps/manager/server.ts','apps/console/client.js','installer/worker.ts'])await execute(process.execPath,['--check',join(root,file)],{cwd:root});
    journal={...journal,phase:'READY',fingerprint:await fingerprint(root),npmVersion:checks.npmVersion,configuredAt:new Date().toISOString()};await atomic(journalPath,journal);
    await validate(root,state);announce(`Setup ready. Start with guard start. Console: https://127.0.0.1:${config.port}/`);
    announce('TLS is local/self-signed unless supplied. Verify the fingerprint shown by guard doctor before a browser exception. No system trust was changed.');
    return {config,unchanged:false,observation};
}
