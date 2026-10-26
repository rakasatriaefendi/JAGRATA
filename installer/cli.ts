import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createInterface} from 'node:readline/promises';
import {X509Certificate} from 'node:crypto';
import {GuardError,fail} from './platform.ts';
import {localPath,present,json,validate,privateFile} from './state.ts';
import {setup} from './setup.ts';
import {registrations,prerequisites,knownContainers} from './prerequisites.ts';
import {start,stop,status} from './lifecycle.ts';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
export function parse(args:string[]){
    const command=args.shift()||'help';const options:any={state:'runtime/console'};
    const names:any={'--state':'state','--registration':'registration','--container-id':'containerId','--username':'username','--admin-file':'adminFile','--tls-cert':'tlsCert','--tls-key':'tlsKey','--port':'port','--context':'context'};
    const switches:any={'--non-interactive':'nonInteractive','--password-stdin':'passwordStdin','--help':'help'};
    const seen=new Set();
    while(args.length){const key=args.shift()!;if(seen.has(key))fail('Repeated option rejected.');seen.add(key);
        if(switches[key]){options[switches[key]]=true;continue}
        if(!names[key]||!args.length||args[0].startsWith('--'))fail('Unknown option or missing option value. Use guard help. Password arguments are unsupported.');
        options[names[key]]=args.shift();
    }
    if(options.port!==undefined){if(!/^[0-9]{4,5}$/.test(options.port))fail('Port must be an integer from1024 to65535.');options.port=Number(options.port);if(options.port<1024||options.port>65535)fail('Port out of range.');}
    return {command,options};
}
const help=`CrowdSec Guard · CS-03 local application installer

Windows: .\\setup.ps1; .\\guard.ps1 start|stop|status|doctor
Bash:    bash ./setup.sh; bash ./guard.sh start|stop|status|doctor

Setup options (PowerShell uses -Registration, -ContainerId, etc.):
  --registration FILE --container-id EXACT_ID
  --username NAME --password-stdin    (automation: password only on stdin)
  --admin-file FILE                  (explicitly bootstrapped private hash)
  --tls-cert FILE --tls-key FILE     (otherwise existing OpenSSL generates TLS)
  --port 44331 --state runtime/console --non-interactive

guard supports --state runtime/console; doctor optionally --context LOCAL_CONTEXT.
stop manages only the proven Console/Manager process, never Docker.
No engine is implicitly adopted or provisioned. No global prerequisite installation.
Guide: docs/CS03_INSTALLATION_GUIDE.md
`;

async function main(){
    const {command,options}=parse(process.argv.slice(2));
    if(command==='help'||options.help){console.log(help);return}
    if(command==='version'){console.log('CrowdSec Guard installer0.3.0 · Console0.2.0');return}
    if(!['setup','start','stop','status','doctor'].includes(command))fail('Unsupported command. Use guard help.');
    const state=await localPath(root,options.state);
    for(const key of ['registration','adminFile','tlsCert','tlsKey'])if(options[key])options[key]=resolve(root,options[key]);
    if(command==='setup'){
        console.log('Setup configures the local application only. Both existing engines/data are preserved.');
        console.log('State/secrets stay under '+options.state+'. Git ignore does not prevent OneDrive/cloud sync; keep this project private.');
        let prompts:any;
        const ask=async(question:string)=>{if(!prompts)prompts=createInterface({input:process.stdin,output:process.stdout});return (await prompts.question(question)).trim()};
        try {
            const existing=await present(join(state,'adapter.json'));
            if(!options.nonInteractive){
                if(!process.stdin.isTTY)fail('No terminal detected. Supply --non-interactive and all required values, or run setup in an interactive terminal.');
                if(!existing&&!options.registration){
                    const choices=await registrations(root);
                    choices.forEach((choice,i)=>console.log(`${i+1}. ${choice.id} (${choice.context})`));
                    const answer=await ask('Existing engine registration (number or explicit file path): ');
                    if(!answer)fail('Explicit engine selection required. No new Docker engine will be created.');
                    options.registration=/^[0-9]+$/.test(answer)?choices[Number(answer)-1]?.path:resolve(root,answer);
                    if(!options.registration)fail('Invalid registration selection.');
                }
                if(!await present(join(state,'config.json'))&&options.port===undefined){const answer=await ask('Console port [44331]: ');if(answer){if(!/^[0-9]{4,5}$/.test(answer))fail('Invalid port.');options.port=Number(answer)}}
                if(!await present(join(state,'admin.json'))&&!options.adminFile&&!options.username)options.username=await ask('New administrator username: ');
                if(!existing)options.confirm=async()=>{const answer=await ask('Use the verified engine above for read-only Console access? [y/N]: ');prompts?.close();return /^y(es)?$/i.test(answer)};
                else prompts?.close();
            }
            const result=await setup(root,state,options);
            console.log(`Application ${result.config.id}; engine is separately managed. Run guard start, then open https://127.0.0.1:${result.config.port}/`);
        }finally{prompts?.close()}
        return;
    }
    if(command==='doctor'){
        const hasAdapter=await present(join(state,'adapter.json'));
        const context=options.context||(hasAdapter?(await json(join(state,'adapter.json'))).context:process.platform==='win32'?'desktop-linux':'default');
        if(!await present(join(state,'config.json')))fail('Application UNCONFIGURED. Run root setup; no engine is implicitly selected.');
        const current=await validate(root,state);
        const health=await status(root,state);
        console.log('Application configuration READY; Manager '+health.state);console.log(JSON.stringify(health));
        console.log('TLS SHA256 fingerprint: '+new X509Certificate(await privateFile(join(state,'tls.crt'),65536)).fingerprint256);
        console.log('TLS expires: '+new X509Certificate(await privateFile(join(state,'tls.crt'),65536)).validTo);
        try{
            const checks=await prerequisites(context);
            console.log(`Platform ${checks.platform}/${checks.architecture}; Node${process.versions.node}; npm${checks.npmVersion}; Docker ${checks.daemon}; Compose${checks.compose}`);
            const engine=await current.adapter.owned();console.log('Configured engine: '+(engine.State?.Running?'running':'stopped'));if(!engine.State?.Running)process.exitCode=1;
        }catch{console.log('Engine diagnostics unavailable. Manager lifecycle result above is independent; no engine was started.');process.exitCode=1;}
        console.log('Detection only. No Docker mutations, automatic engine start or cleanup.');
        if(!['RUNNING','STOPPED'].includes(health.state))process.exitCode=1;
        return;
    }
    const result=command==='start'?await start(root,state):command==='stop'?await stop(root,state):await status(root,state);
    console.log(JSON.stringify(result));
    if(command==='status'&&!result.healthy)process.exitCode=result.state==='STOPPED'?3:1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{console.error('[GUARD] '+(error instanceof GuardError?error.message:'Local operation failed safely. Run guard doctor and consult the installation guide; no secret diagnostic output shown.'));process.exitCode=1});
