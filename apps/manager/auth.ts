import {randomBytes,scrypt as rawScrypt,timingSafeEqual,createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {readFile,open,lstat} from 'node:fs/promises';
const scrypt=promisify(rawScrypt);
export const token=()=>randomBytes(32).toString('base64url');
const digest=(s:string)=>createHash('sha256').update(s).digest('hex');
export async function passwordHash(password:string,salt:string){return (await scrypt(password,salt,64,{N:32768,r:8,p:1,maxmem:64*1024*1024}) as Buffer).toString('hex')}
export async function bootstrap(file:string,username:string,password:string){
 if(!/^[a-zA-Z0-9_.-]{3,64}$/.test(username)||password.length<14||password.length>256||!password.trim())throw Error('Username 3–64 characters and password 14–256 characters required.');
 const salt=token(),hash=await passwordHash(password,salt);const f=await open(file,'wx',0o600);try{await f.writeFile(JSON.stringify({version:1,username,salt,hash})+'\n')}finally{await f.close()}
}
export class Auth{
 admin:any;sessions=new Map<string,any>();attempts=new Map<string,{count:number;until:number}>();clock:()=>number;activeLogins=0;
 constructor(admin:any,clock=Date.now){if(admin.version!==1||!/^[a-zA-Z0-9_.-]{3,64}$/.test(admin.username)||!/^[0-9a-f]{128}$/.test(admin.hash)||!/^[A-Za-z0-9_-]{43}$/.test(admin.salt))throw Error('Invalid administrator state');this.admin=admin;this.clock=clock}
 static async load(file:string){const info=await lstat(file);if(!info.isFile()||info.isSymbolicLink()||info.size>16384||(process.platform!=='win32'&&(info.mode&0o077)))throw Error('Administrator file must be a private regular file');return new Auth(JSON.parse(await readFile(file,'utf8')))}
 async login(username:string,password:string,ip:string){
  const now=this.clock();for(const[k,v]of this.attempts)if(v.until<now)this.attempts.delete(k);
  const attempts=this.attempts.get(ip)||{count:0,until:now+15*60_000};if(attempts.count>=5)throw Object.assign(Error('Too many login attempts. Retry later.'),{status:429});attempts.count++;this.attempts.set(ip,attempts);
  if(this.activeLogins>=2)throw Object.assign(Error('Login busy. Retry later.'),{status:429});this.activeLogins++;
  let hash:string;try{hash=await passwordHash(password,this.admin.salt)}finally{this.activeLogins--}if(username!==this.admin.username||!timingSafeEqual(Buffer.from(hash,'hex'),Buffer.from(this.admin.hash,'hex')))return null;
  this.prune();if(this.sessions.size>=64)this.sessions.delete(this.sessions.keys().next().value!);
  const secret=token(),session={csrf:token(),expires:now+8*60*60_000,idle:now+30*60_000};this.sessions.set(digest(secret),session);return {secret,session};
 }
 prune(){const now=this.clock();for(const[k,s]of this.sessions)if(s.expires<=now||s.idle<=now)this.sessions.delete(k)}
 get(secret:string){this.prune();const s=this.sessions.get(digest(secret));if(s)s.idle=this.clock()+30*60_000;return s||null}
 logout(secret:string){this.sessions.delete(digest(secret))}
}
