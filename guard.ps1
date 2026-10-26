<# Application lifecycle only. Never controls the CrowdSec engine. #>
[CmdletBinding()]
param(
    [Parameter(Position=0)][ValidateSet('start','stop','status','doctor','help','version')][string]$Action = 'help',
    [string]$State = 'runtime/console',
    [string]$DockerContext
)
$ErrorActionPreference = 'Stop'
try {
    $guardNode = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $guardNode) { throw 'Node.js 24+ is required. No prerequisites will be installed automatically.' }
    & $guardNode.Source -e 'process.exit(parseInt(process.versions.node) >= 24 ? 0 : 1)'
    if ($LASTEXITCODE -ne 0) { throw 'A working Node.js 24+ is required.' }
    $guardArgs = @((Join-Path $PSScriptRoot 'installer/cli.ts'), $Action, '--state', $State)
    if ($DockerContext) { $guardArgs += @('--context',$DockerContext) }
    & $guardNode.Source @guardArgs
    exit $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine('[GUARD] ' + $_.Exception.Message)
    exit 1
}
