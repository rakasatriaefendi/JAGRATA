// Reuse CS-04 browser regression against a separate local Console state directory.
// Source draft CRUD writes only this fresh CS-05 fixture; it never applies mounts.
import {mkdir,mkdtemp} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {spawn} from 'node:child_process';
import net from 'node:net';
import {windowsPrivacy} from '../../installer/platform.ts';
if(!process.env.GUARD_ADAPTER_FILE)throw Error('Explicit QA adapter required');
const root=resolve('runtime/qa-cs05-source-regression');await mkdir(root,{recursive:true});const qa=await mkdtemp(join(root,'case-'));if(process.platform==='win32')await windowsPrivacy([qa],true);
const listener=net.createServer();await new Promise<void>(r=>listener.listen(0,'127.0.0.1',r));const port=(listener.address() as any).port;await new Promise<void>(r=>listener.close(()=>r()));
const child=spawn(process.execPath,['tests/cs04/browser.ts'],{stdio:'inherit',windowsHide:true,env:{...process.env,GUARD_BROWSER_STATE:qa,GUARD_BROWSER_OUT:join(qa,'previews'),GUARD_BROWSER_PORT:String(port),GUARD_CS04_OBSERVED:'0'}});
child.once('error',()=>{process.exitCode=1});child.once('exit',code=>{process.exitCode=code??1});
