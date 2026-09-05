$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskState = Join-Path $taskArtifacts 'account-enrollment-state.json'
$taskRelease = Join-Path $taskRoot 'build\Release'
$Host.UI.RawUI.WindowTitle = 'Sovereign Windows sign-in - enrollment and verification'
function Write-TaskState([string]$phase) {
    @{phase=$phase; time=(Get-Date).ToUniversalTime().ToString('o'); signInProviderRegistered=$false} | ConvertTo-Json | Set-Content -LiteralPath $taskState
}
try {
    Write-TaskState 'waiting_for_one_time_Windows_credential'
    Write-Host 'Enter the Microsoft-account password in the secure enrollment window. Your YubiKey PIN unlocks the separate browser passkey.'
    & (Join-Path $taskRelease 'swa_enroll.exe') --enroll (Join-Path $taskArtifacts 'public-profile.swt') (Join-Path $taskArtifacts 'second-public-profile.swt') 2>&1 | Tee-Object -FilePath (Join-Path $taskArtifacts 'account-enroll.log')
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed; no retry has been made.' }
    Write-TaskState 'verifying_saved_profile_with_touch'
    Write-Host 'Leave the SECOND key connected for its saved-profile and provider tests.'
    & (Join-Path $taskRelease 'swa_enroll.exe') --verify 2>&1 | Tee-Object -FilePath (Join-Path $taskArtifacts 'account-verify.log')
    if ($LASTEXITCODE -ne 0) { throw 'Saved-profile authentication failed.' }
    Write-TaskState 'verifying_provider_credential_with_touch'
    & (Join-Path $taskRelease 'swa_provider_host.exe') (Join-Path $taskRelease 'SovereignCredentialProvider.dll') --authenticate 2>&1 | Tee-Object -FilePath (Join-Path $taskArtifacts 'provider-authenticate.log')
    if ($LASTEXITCODE -ne 0) { throw 'Provider authentication test failed.' }
    Write-TaskState 'verifying_first_key_independently'
    Write-Host 'Disconnect the second key and connect ONLY the FIRST key.'
    Read-Host 'Press Enter when the first key is connected'
    & (Join-Path $taskRelease 'swa_provider_host.exe') (Join-Path $taskRelease 'SovereignCredentialProvider.dll') --authenticate 2>&1 | Tee-Object -FilePath (Join-Path $taskArtifacts 'provider-first-key.log')
    if ($LASTEXITCODE -ne 0) { throw 'First-key provider authentication failed.' }
    Write-TaskState 'checking_cancellation_without_touch'
    & (Join-Path $taskRelease 'swa_provider_host.exe') (Join-Path $taskRelease 'SovereignCredentialProvider.dll') --cancel 2>&1 | Tee-Object -FilePath (Join-Path $taskArtifacts 'provider-cancel.log')
    if ($LASTEXITCODE -ne 0) { throw 'Provider cancellation test failed.' }
    Write-TaskState 'enrolled_and_all_preinstallation_checks_passed'
    Write-Host 'Our provider passed the preinstallation tests. Desktop unlock is still a separate test.'
} catch {
    @{phase='stopped'; error=$_.Exception.Message; time=(Get-Date).ToUniversalTime().ToString('o'); signInProviderRegistered=$false} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    Write-Host 'Enrollment or verification stopped. No automatic retry or Windows sign-in registration was performed.'
}
Read-Host 'Press Enter to close'
