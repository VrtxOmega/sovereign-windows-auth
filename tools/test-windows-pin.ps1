$ErrorActionPreference = 'Continue'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskState = Join-Path $taskArtifacts 'windows-pin-state.json'
$Host.UI.RawUI.WindowTitle = 'Sovereign - test this PCs Windows PIN'
@{phase='waiting_for_Windows_PIN'; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
Write-Host 'Use the numerical Windows PIN in the Windows PIN check dialog.'
& (Join-Path $taskRoot 'build/Release/swa_hello_probe.exe') 2>&1 | Out-File -FilePath (Join-Path $taskArtifacts 'windows-pin-test.log')
$taskExit = $LASTEXITCODE
@{phase='finished'; exitCode=$taskExit; time=(Get-Date).ToUniversalTime().ToString('o'); profileSaved=$false; providerRegistered=$false} | ConvertTo-Json | Set-Content -LiteralPath $taskState
if ($taskExit -eq 0) { Write-Host 'Windows accepted the PIN test. No sign-in settings have been changed.' }
else { Write-Host 'The test stopped. Review the local diagnostic result before retrying.' }
Read-Host 'Press Enter to close this helper'
