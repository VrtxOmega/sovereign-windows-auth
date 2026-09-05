param([string]$Python = 'python.exe')
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskVenv = Join-Path $taskRoot '.venv'
$taskVenvPython = Join-Path $taskVenv 'Scripts/python.exe'
if (-not (Test-Path -LiteralPath $taskVenvPython)) {
    & $Python -m venv $taskVenv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the enrollment Python environment.' }
}
& $taskVenvPython -m pip install -r (Join-Path $taskRoot 'requirements-enrollment.txt')
if ($LASTEXITCODE -ne 0) { throw 'Could not install enrollment dependencies.' }
New-Item -ItemType Directory -Path (Join-Path $taskRoot 'artifacts') -Force | Out-Null
Write-Host 'Enrollment Python environment is ready. No key or Windows sign-in changes were made.'
