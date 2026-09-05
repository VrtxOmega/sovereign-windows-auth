$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$Host.UI.RawUI.WindowTitle = 'Sovereign Windows sign-in - native hardware test'
& (Join-Path $taskRoot 'build\Release\swa_probe.exe') --hardware-test (Join-Path $taskRoot 'artifacts\public-profile.swt') 2>&1 | Tee-Object -FilePath (Join-Path $taskRoot 'artifacts\native-hardware-proof.log')
@{exitCode=$LASTEXITCODE; completed=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskRoot 'artifacts\native-hardware-proof-state.json')
Read-Host 'Test finished. Press Enter to close'
