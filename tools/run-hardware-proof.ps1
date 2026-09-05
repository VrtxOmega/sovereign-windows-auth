$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskPython = Join-Path (Split-Path $taskRoot) 'yubikey\venv\Scripts\python.exe'
$Host.UI.RawUI.WindowTitle = 'Sovereign Windows sign-in - key hardware test'
& $taskPython (Join-Path $PSScriptRoot 'prove_touch_secret.py')
Write-Host 'Hardware test finished. This has not changed Windows sign-in.'
Read-Host 'Press Enter to close'
