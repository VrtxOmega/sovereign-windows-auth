param([Parameter(Mandatory=$true)][string]$TargetSid,[Parameter(Mandatory=$true)][guid]$RunId)
$ErrorActionPreference = 'Stop'
$taskData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SovereignWindowsAuth'
$taskState = Join-Path $taskData ('system-inspect-' + $RunId.ToString() + '.json')
$taskLog = Join-Path $taskData ('system-inspect-' + $RunId.ToString() + '.log')
try {
    $taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($taskIdentity -ne 'S-1-5-18') { throw 'The system inspection did not run as SYSTEM.' }
    $taskParsedSid = [Security.Principal.SecurityIdentifier]::new($TargetSid)
    if ($taskParsedSid.Value -ne $TargetSid) { throw 'Invalid target SID.' }
    $ErrorActionPreference = 'Continue'
    & (Join-Path $PSScriptRoot 'swa_provider_host.exe') (Join-Path $PSScriptRoot 'SovereignCredentialProvider-display.dll') --registered-sid $TargetSid *> $taskLog
    $taskExit = $LASTEXITCODE
    @{phase='finished'; exitCode=$taskExit; executionSid=$taskIdentity; authenticationAttempted=$false; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
} catch {
    @{phase='failed'; error=$_.Exception.Message; authenticationAttempted=$false; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
}
