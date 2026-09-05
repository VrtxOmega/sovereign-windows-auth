$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskPython = Join-Path (Split-Path $taskRoot) 'yubikey\venv\Scripts\python.exe'
$Host.UI.RawUI.WindowTitle = 'Sovereign Windows sign-in - second YubiKey'
Write-Host 'Disconnect the first YubiKey. Connect ONLY your second YubiKey.'
Read-Host 'Press Enter when the second key is connected'
& $taskPython (Join-Path $PSScriptRoot 'prove_touch_secret.py') --second-key
if ($LASTEXITCODE -eq 0) {
    & $taskPython (Join-Path $PSScriptRoot 'export-public-profile.py') --second-key
}
Write-Host 'Second-key test finished. Windows sign-in is not changed by this test.'
Read-Host 'Press Enter to close'
