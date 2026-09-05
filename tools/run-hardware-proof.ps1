$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskPython = Join-Path $taskRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) { throw 'Run tools/setup-python.ps1 first.' }
$Host.UI.RawUI.WindowTitle = 'Sovereign Windows sign-in - key hardware test'
& $taskPython (Join-Path $PSScriptRoot 'prove_touch_secret.py')
if ($LASTEXITCODE -ne 0) { throw 'First-key enrollment/proof stopped.' }
& $taskPython (Join-Path $PSScriptRoot 'export-public-profile.py')
if ($LASTEXITCODE -ne 0) { throw 'First-key public profile export failed.' }
Write-Host 'Hardware test finished. This has not changed Windows sign-in.'
Read-Host 'Press Enter to close'
