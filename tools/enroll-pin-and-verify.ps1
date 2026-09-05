$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskState = Join-Path $taskArtifacts 'pin-enrollment-state.json'
$taskRelease = Join-Path $taskRoot 'build\Release'
$taskChecks = [System.Collections.Generic.List[string]]::new()
$taskHashes = @{}
foreach ($taskFile in @('SovereignCredentialProvider.dll','fido2.dll','crypto-56.dll','cbor.dll','zlib1.dll')) {
    $taskHashes[$taskFile] = (Get-FileHash -LiteralPath (Join-Path $taskRelease $taskFile) -Algorithm SHA256).Hash
}
$Host.UI.RawUI.WindowTitle = 'Sovereign - bind Windows PIN to both YubiKeys'
function Write-TaskState([string]$phase, [string]$failure = '') {
    @{phase=$phase; error=$failure; time=(Get-Date).ToUniversalTime().ToString('o'); checks=@($taskChecks.ToArray()); signInProviderRegistered=$false} | ConvertTo-Json | Set-Content -LiteralPath $taskState
}
function Invoke-TaskCheck([string]$name, [string]$program, [string[]]$programArguments) {
    Write-TaskState $name
    $ErrorActionPreference = 'Continue'
    & (Join-Path $taskRelease $program) @programArguments 2>&1 | Tee-Object -FilePath (Join-Path $taskArtifacts ($name + '.log'))
    if ($LASTEXITCODE -ne 0) { throw "$name stopped with exit code $LASTEXITCODE. No automatic retry." }
    $taskChecks.Add($name)
}
try {
    $taskIdentity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $taskIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Enrollment requires administrator access to the USB keys and protected profile directory.' }
    Invoke-TaskCheck 'pin_enrollment_preflight' 'swa_hello_probe.exe' @('--preflight')
    Write-Host 'Enter the numerical PIN you use to unlock this PC in the masked Windows PIN dialog.'
    Write-Host 'Then follow the prompts to connect and touch each YubiKey. The PIN is encrypted separately for each key.'
    Invoke-TaskCheck 'pin_enrollment' 'swa_enroll.exe' @('--enroll-pin', (Join-Path $taskArtifacts 'public-profile.swt'), (Join-Path $taskArtifacts 'second-public-profile.swt'))
    Write-Host 'Leave ONLY the SECOND key connected. The following checks need touches, with no PIN entry.'
    Read-Host 'Press Enter when ready to test the second key'
    Invoke-TaskCheck 'pin_second_saved_profile' 'swa_enroll.exe' @('--verify')
    Read-Host 'Press Enter when ready for another touch to test the sign-in component'
    Invoke-TaskCheck 'pin_second_provider' 'swa_provider_host.exe' @((Join-Path $taskRelease 'SovereignCredentialProvider.dll'), '--authenticate')
    Write-Host 'Disconnect the second key and connect ONLY the FIRST key.'
    Read-Host 'Press Enter when ready to test the first key'
    Invoke-TaskCheck 'pin_first_provider' 'swa_provider_host.exe' @((Join-Path $taskRelease 'SovereignCredentialProvider.dll'), '--authenticate')
    Write-Host 'For the final cancellation check, DO NOT TOUCH the key.'
    Invoke-TaskCheck 'pin_provider_cancellation' 'swa_provider_host.exe' @((Join-Path $taskRelease 'SovereignCredentialProvider.dll'), '--cancel')
    foreach ($taskFile in $taskHashes.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $taskRelease $taskFile) -Algorithm SHA256).Hash -ne $taskHashes[$taskFile]) { throw 'A tested binary changed during validation.' }
    }
    @{phase='both_keys_verified'; sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; hashes=$taskHashes; checks=@($taskChecks.ToArray()); time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskArtifacts 'pin-install-receipt.json')
    Write-TaskState 'enrolled_and_all_preinstallation_checks_passed'
    Write-Host 'Both keys passed the preinstallation checks. The desktop sign-in test comes next.'
} catch {
    Write-TaskState 'stopped' $_.Exception.Message
    Write-Host $_.Exception.Message
    Write-Host 'Codex will inspect the result. Your existing Windows sign-in is still available.'
}
Read-Host 'Press Enter to close this helper'
