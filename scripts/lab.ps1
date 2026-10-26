<# PowerShell 5.1 entry point. Python 3.8+ standard library; no shell re-parsing. #>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('init','validate','preflight','up','down','status','detect','backup','restore','update','reset','uninstall')]
    [string]$Action = 'validate',
    [string]$InstallationId,
    [string]$DockerContext,
    [ValidateSet('named','bind')][string]$Persistence,
    [string]$ExpectedPlatform,
    [string]$Evidence,
    [string]$Archive,
    [string]$Tag,
    [switch]$Purge,
    [switch]$KeepBackups,
    [switch]$RemoveImage
)
$ErrorActionPreference = 'Stop'
try {
    $pythonCommand = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pythonCommand) { throw 'Python 3.8+ is required. No dependency will be installed automatically.' }
    & $pythonCommand.Source -B -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)'
    $versionExit = $LASTEXITCODE
    if ($versionExit -ne 0) { throw 'A working Python 3.8+ interpreter is required.' }
    $cliArguments = @('-B', (Join-Path $PSScriptRoot 'guard_lab.py'), $Action)
    foreach ($entry in @(
        @('--installation-id', $InstallationId), @('--docker-context', $DockerContext),
        @('--persistence', $Persistence), @('--expected-platform', $ExpectedPlatform),
        @('--evidence', $Evidence), @('--archive', $Archive), @('--tag', $Tag)
    )) {
        if ($entry[1]) { $cliArguments += @($entry[0], $entry[1]) }
    }
    if ($Purge) { $cliArguments += '--purge' }
    if ($KeepBackups) { $cliArguments += '--keep-backups' }
    if ($RemoveImage) { $cliArguments += '--remove-image' }
    & $pythonCommand.Source @cliArguments
    $commandExit = $LASTEXITCODE
    exit $commandExit
} catch {
    [Console]::Error.WriteLine('[LAB] FAIL: ' + $_.Exception.Message)
    exit 1
}
