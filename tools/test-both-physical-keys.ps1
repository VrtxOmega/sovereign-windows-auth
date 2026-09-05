$ErrorActionPreference = 'Continue'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$Host.UI.RawUI.WindowTitle = 'Sovereign Windows sign-in - verify both physical keys'
& (Join-Path $taskRoot 'build\Release\swa_probe.exe') --two-key-fixture (Join-Path $taskArtifacts 'public-profile.swt') (Join-Path $taskArtifacts 'second-public-profile.swt') (Join-Path $taskArtifacts 'two-key-fixture.swm') 2>&1 | Tee-Object -FilePath (Join-Path $taskArtifacts 'both-physical-keys.log')
@{exitCode=$LASTEXITCODE; completed=(Get-Date).ToUniversalTime().ToString('o'); data='test_fixture_only'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskArtifacts 'both-physical-keys-state.json')
Read-Host 'Test finished. Press Enter to close'
