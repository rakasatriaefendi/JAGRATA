import {passwordInput} from './password.ts';
import {bootstrap} from './auth.ts';
import {resolve} from 'node:path';
const [file,username]=process.argv.slice(2);
if(!file||!username){console.error('Usage: node apps/manager/bootstrap.ts NEW_ADMIN_FILE USERNAME < password-on-stdin');process.exit(1)}

try{await bootstrap(resolve(file),username,await passwordInput());console.log('Administrator initialized. No credentials printed.')}catch{console.error('Bootstrap failed: verify new private destination, username and password length. Existing files are never overwritten.');process.exitCode=1}
