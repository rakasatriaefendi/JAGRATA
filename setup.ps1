<# CrowdSec Guard application setup. Windows PowerShell 5.1+. #>
[CmdletBinding()]
param(
    [string]$Registration,
    [string]$ContainerId,
    [string]$Username,
    [string]$AdminFile,
    [string]$TlsCert,
    [string]$TlsKey,
    [int]$Port,
    [string]$State = 'runtime/console',
    [switch]$NonInteractive,
    [switch]$PasswordStdin,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
try {
    $guardNode = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $guardNode) { throw 'Node.js 24+ is required. Install it separately; no global packages are installed by setup.' }
    & $guardNode.Source -e 'process.exit(parseInt(process.versions.node) >= 24 ? 0 : 1)'
    if ($LASTEXITCODE -ne 0) { throw 'A working Node.js 24+ is required.' }
    $guardArgs = @((Join-Path $PSScriptRoot 'installer/cli.ts'), 'setup', '--state', $State)
    foreach ($guardPair in @(@('--registration',$Registration),@('--container-id',$ContainerId),@('--username',$Username),@('--admin-file',$AdminFile),@('--tls-cert',$TlsCert),@('--tls-key',$TlsKey))) {
        if ($guardPair[1]) { $guardArgs += @($guardPair[0],$guardPair[1]) }
    }
    if ($PSBoundParameters.ContainsKey('Port')) { $guardArgs += @('--port', [string]$Port) }
    if ($NonInteractive) { $guardArgs += '--non-interactive' }
    if ($PasswordStdin) { $guardArgs += '--password-stdin' }
    if ($Help) { $guardArgs += '--help' }
    & $guardNode.Source @guardArgs
    exit $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine('[GUARD] ' + $_.Exception.Message)
    exit 1
}
