// On-demand OS evidence only. No signals, process-name guessing or network calls.
import {readFile,readlink,stat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {run} from './platform.ts';
export type ProcessIdentity={platform:string;boot:string;pid:number;created:string;executable:string;commandHash:string;owner:string};
export type Inspection={state:'PRESENT'|'ABSENT'|'UNKNOWN';boot?:string;identity?:ProcessIdentity};
const hash=(x:string|Buffer)=>createHash('sha256').update(x).digest('hex');
const script=String.raw`$ErrorActionPreference='Stop'
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$env:GUARD_INSPECT_PID)
if($null -eq $p){@{state='ABSENT';boot=$boot}|ConvertTo-Json -Compress;exit}
$sid=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
if($sid.ReturnValue -ne 0 -or !$p.ExecutablePath -or !$p.CommandLine){throw 'Metadata inaccessible'}
$me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if($sid.Sid -ne $me){throw 'Different process owner'}
@{state='PRESENT';boot=$boot;identity=@{platform='win32';boot=$boot;pid=[int]$p.ProcessId;created=$p.CreationDate.ToUniversalTime().Ticks.ToString();executable=$p.ExecutablePath;command=$p.CommandLine;owner=$sid.Sid}}|ConvertTo-Json -Compress`;
export async function inspectProcess(pid:number):Promise<Inspection>{
 if(!Number.isSafeInteger(pid)||pid<1)return {state:'UNKNOWN'};
 try{
  if(process.platform==='win32'){
   const raw=JSON.parse(await run(join(process.env.SystemRoot||'C:/Windows','System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{timeout:4000,env:{...process.env,GUARD_INSPECT_PID:String(pid)}}));
   if(raw.state==='ABSENT'&&/^\d+$/.test(raw.boot))return raw;
   const i=raw.identity;if(raw.state!=='PRESENT'||i?.pid!==pid||!i.created||!i.owner||!i.command||!i.executable||i.boot!==raw.boot)return {state:'UNKNOWN'};
   i.commandHash=hash(i.command);delete i.command;return {state:'PRESENT',boot:raw.boot,identity:i};
  }
  if(process.platform==='linux'){
   const boot=(await readFile('/proc/sys/kernel/random/boot_id','utf8')).trim();await stat('/proc/self');
   let first;try{first=await readFile(`/proc/${pid}/stat`,'utf8')}catch(e:any){return e.code==='ENOENT'?{state:'ABSENT',boot}:{state:'UNKNOWN'}}
   const fields=first.slice(first.lastIndexOf(')')+2).split(' '),created=fields[19];
   const info=await stat(`/proc/${pid}`);if(info.uid!==process.getuid?.())return {state:'UNKNOWN'};
   const executable=await readlink(`/proc/${pid}/exe`),command=await readFile(`/proc/${pid}/cmdline`);
   const second=await readFile(`/proc/${pid}/stat`,'utf8');
   if(!created||!command.length||second.slice(second.lastIndexOf(')')+2).split(' ')[19]!==created)return {state:'UNKNOWN'};
   return {state:'PRESENT',boot,identity:{platform:'linux',boot,pid,created,executable,commandHash:hash(command),owner:String(info.uid)}};
  }
 }catch{}
 return {state:'UNKNOWN'};
}
export function sameProcess(a:ProcessIdentity,b:ProcessIdentity){return ['platform','boot','pid','created','executable','commandHash','owner'].every(k=>(a as any)[k]===(b as any)[k])}
let cached:Promise<ProcessIdentity>|undefined;
export async function selfIdentity(){return cached??=(async()=>{const x=await inspectProcess(process.pid);if(x.state!=='PRESENT'||!x.identity)throw Error('RECOVERY_REQUIRED: OS process identity unavailable; no lifecycle state changed.');return x.identity})()}
