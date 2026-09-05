param([Parameter(Mandatory=$true)][string]$TargetUser,[Parameter(Mandatory=$true)][guid]$RunId)
$ErrorActionPreference = 'Stop'
$taskData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SovereignWindowsAuth'
$taskState = Join-Path $taskData ('system-auth-' + $RunId.ToString() + '.json')
$taskLog = Join-Path $taskData ('system-auth-' + $RunId.ToString() + '.log')
try {
    $taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($taskIdentity -ne 'S-1-5-18') { throw 'The test must run as SYSTEM.' }
    $ErrorActionPreference = 'Continue'
    & (Join-Path $PSScriptRoot 'swa_provider_host.exe') (Join-Path $PSScriptRoot 'SovereignCredentialProvider.dll') --authenticate-system-user $TargetUser *> $taskLog
    @{phase='finished'; exitCode=$LASTEXITCODE; executionSid=$taskIdentity; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
} catch {
    @{phase='failed'; error=$_.Exception.Message; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
}
