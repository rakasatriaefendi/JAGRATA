// Creates ONLY new project-local QA files; no Docker commands or old fixture edits.
import {mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {windowsPrivacy} from '../../installer/platform.ts';
import {identity} from '../../installer/state.ts';
import {Sources,noLinks} from '../../apps/manager/sources.ts';
import {sourcePlan} from '../../installer/source-plan.ts';
await noLinks(resolve('runtime'),false);const parent=resolve('runtime/qa-cs04-20261024');await mkdir(parent,{recursive:true,mode:0o700});await noLinks(parent,false);
const qa=join(parent,'integration-'+randomBytes(4).toString('hex'));await mkdir(qa,{mode:0o700});
if(process.platform==='win32')await windowsPrivacy([qa],true);
const installationId='qa-cs04-'+randomBytes(4).toString('hex'),owner=randomBytes(16).toString('hex'),rootHash=await identity(qa);
const adapter={context:'desktop-linux',containerId:'0'.repeat(64),installationId,owner,rootHash};
const store=new Sources(join(qa,'sources'),{config:adapter});
for(const [type,name] of [['ssh','Synthetic SSH'],['nginx','Synthetic Nginx']]){const path=join(qa,type+'.log');await writeFile(path,'',{flag:'wx',mode:0o600});const db=await store.load();await store.change('save',{revision:db.revision,source:{name,type,path,enabled:true,consent:true}})}
const plan=await sourcePlan(store);
await writeFile(join(qa,'adapter.json'),JSON.stringify(adapter,null,2),{flag:'wx',mode:0o600});
await writeFile(join(qa,'registration.json'),JSON.stringify({format_version:1,installation_id:installationId,docker_context:adapter.context,owner_token:owner,root_hash:rootHash},null,2),{flag:'wx',mode:0o600});
await writeFile(join(qa,'plan.json'),JSON.stringify({...plan,qa},null,2),{flag:'wx',mode:0o600});
console.log(JSON.stringify({...plan,qa},null,2));
