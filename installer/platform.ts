import {execFile} from 'node:child_process';
import {existsSync,realpathSync} from 'node:fs';
import {dirname,join,delimiter} from 'node:path';

export class GuardError extends Error {}
export function fail(message:string):never { throw new GuardError(message); }

// Fixed executable + argv; never shell-evaluate a path, secret or user answer.
export function run(file:string,args:string[],options:any={}) {
    return new Promise<string>((resolve,reject)=>execFile(file,args,{
        timeout:10_000,maxBuffer:256*1024,encoding:'utf8',windowsHide:true,shell:false,
        env:{...process.env,NODE_OPTIONS:undefined,NODE_PATH:undefined,DOCKER_HOST:undefined,DOCKER_CONTEXT:undefined},
        ...options
    },(error,out)=>error?reject(new GuardError('External command failed; verify the named prerequisite. No secret output is shown.')):resolve(String(out).trim())));
}

export function findNpm() {
    // Invoke npm's JS entrypoint with the already verified Node. No cmd /c quoting.
    const candidates=[join(dirname(process.execPath),'node_modules/npm/bin/npm-cli.js')];
    for(const directory of (process.env.PATH||'').split(delimiter)) {
        candidates.push(join(directory,'node_modules/npm/bin/npm-cli.js'));
        for(const name of ['npm','npm.cmd']) {
            try { const target=realpathSync(join(directory,name));if(target.endsWith('npm-cli.js'))candidates.push(target); } catch {}
        }
    }
    return candidates.find(path=>existsSync(path))||null;
}

export function findOpenSSL() {
    const candidates=(process.env.PATH||'').split(delimiter).map(path=>join(path,process.platform==='win32'?'openssl.exe':'openssl'));
    if(process.platform==='win32'&&process.env.ProgramFiles)candidates.push(join(process.env.ProgramFiles,'Git/usr/bin/openssl.exe'));
    return candidates.find(path=>existsSync(path))||null;
}

export function verifyVersions(node:string,npm:string) {
    if(!/^v?\d+\.\d+\.\d+/.test(node)||Number(node.replace(/^v/,'').split('.')[0])<24)fail('Node.js 24+ is required by apps/manager/package.json.');
    if(!/^\d+\.\d+\.\d+/.test(npm)||Number(npm.split('.')[0])<9)fail('npm 9+ is required for the version-3 application lockfile.');
}

// The only PowerShell -Command text is constant. Paths enter through an environment
// variable; none are interpolated into PowerShell code. Restrict NEW state only.
const aclScript=String.raw`
$ErrorActionPreference='Stop'
$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$paths=@(ConvertFrom-Json $env:GUARD_ACL_PATHS)
if($env:GUARD_ACL_CREATE -eq '1') {
    $acl=New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true,$false)
    $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $paths[0] -AclObject $acl
}
foreach($path in $paths) {
    $acl=Get-Acl -LiteralPath $path
    if($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'Owner mismatch'}
    $rules=$acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])
    if($rules.Count -eq 0){throw 'No private access rule'}
    foreach($rule in $rules) {
        if($rule.IdentityReference.Value -ne $sid.Value -or $rule.AccessControlType -ne 'Allow'){throw 'Nonprivate ACL'}
    }
}
`;
export async function windowsPrivacy(paths:string[],create=false) {
    const encoded=Buffer.from(aclScript,'utf16le').toString('base64');
    await run(join(process.env.SystemRoot||'C:/Windows','System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',encoded],{
        env:{...process.env,GUARD_ACL_PATHS:JSON.stringify(paths),GUARD_ACL_CREATE:create?'1':'0'}
    }).catch(()=>fail('State ACL validation failed. Only the current user may own/access the application state. No existing ACLs were repaired.'));
}

// ShellExecute detaches the background worker from a caller's redirected console
// handles. No shell command is constructed: Start-Process receives an EXE path and
// a CRT-quoted argument string through environment values, then returns its PID.
export function windowsArguments(args:string[]){return args.map(value=>'"'+value.replace(/(\\*)"/g,'$1$1\\"').replace(/(\\+)$/,'$1$1')+'"').join(' ')}
export async function windowsWorker(root:string,args:string[]){
    const script="$ErrorActionPreference='Stop'; $p=Start-Process -FilePath $env:GUARD_LAUNCH_NODE -ArgumentList $env:GUARD_LAUNCH_ARGS -WorkingDirectory $env:GUARD_LAUNCH_ROOT -WindowStyle Hidden -PassThru; [Console]::Out.WriteLine($p.Id)";
    const result=await run(join(process.env.SystemRoot||'C:/Windows','System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{
        env:{...process.env,NODE_OPTIONS:undefined,NODE_PATH:undefined,GUARD_LAUNCH_NODE:process.execPath,GUARD_LAUNCH_ARGS:windowsArguments(args),GUARD_LAUNCH_ROOT:root}
    });
    if(!/^[0-9]+$/.test(result)||Number(result)<1)fail('Windows worker launch was not confirmed. Inspect doctor before retrying; no forced cleanup.');
    return Number(result);
}
export async function windowsProcessExists(pid:number){
    const script="if(Get-Process -Id ([int]$env:GUARD_PROBE_PID) -ErrorAction SilentlyContinue){[Console]::Out.WriteLine('PRESENT')}else{[Console]::Out.WriteLine('ABSENT')}";
    try {const result=await run(join(process.env.SystemRoot||'C:/Windows','System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{env:{...process.env,GUARD_PROBE_PID:String(pid)}});return result==='PRESENT'?true:result==='ABSENT'?false:null;}catch{return null;}
}
