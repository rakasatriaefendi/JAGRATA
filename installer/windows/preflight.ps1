<# Read-only capability checks. No directory creation or write probes. #>
[CmdletBinding()]
param([string]$DockerContext)
$ErrorActionPreference = 'Stop'
try {
    $launcher = Join-Path $PSScriptRoot '..\..\scripts\lab.ps1'
    $launcherArgs = @{ Action = 'preflight'; ExpectedPlatform = 'Windows' }
    if ($DockerContext) { $launcherArgs['DockerContext'] = $DockerContext }
    & $launcher @launcherArgs
    exit $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine('[PREFLIGHT] FAIL: ' + $_.Exception.Message)
    exit 1
}
