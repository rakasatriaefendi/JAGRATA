// Explicit local setup. No resource discovery or lifecycle commands.
import {readFile,open} from 'node:fs/promises';
import {CrowdSec} from './adapter.ts';
const [registration,containerId,destination]=process.argv.slice(2);
try{
 if(!registration||!containerId||!destination)throw Error('arguments');
 const raw=await readFile(registration,'utf8');if(raw.length>16384)throw Error('registration size');
 const data=JSON.parse(raw);const config={context:data.docker_context,containerId,installationId:data.installation_id,owner:data.owner_token,rootHash:data.root_hash};
 await new CrowdSec(config).owned();
 const file=await open(destination,'wx',0o600);try{await file.writeFile(JSON.stringify(config,null,2)+'\n')}finally{await file.close()}
 console.log('Private adapter configuration created after ownership verification. No secrets printed.');
}catch{console.error('Setup refused. Usage: node apps/manager/configure.ts EXPLICIT_REGISTRATION EXACT_CONTAINER_ID NEW_PRIVATE_ADAPTER_FILE. Check local Docker, ownership, destination and permissions. No resource changed.');process.exitCode=1}
