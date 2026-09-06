param([string]$BuildDirectory = '', [string]$FidoRoot = '', [switch]$WithVmFilter)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $taskRoot 'build' }
if (-not $FidoRoot) { $FidoRoot = Join-Path $taskRoot 'artifacts/libfido2/libfido2-1.17.0-win' }
if (-not (Test-Path -LiteralPath (Join-Path $FidoRoot 'include/fido.h'))) {
    throw 'Run tools/fetch-dependencies.ps1 first, or supply -FidoRoot with the verified SDK.'
}
$taskCmakeCommand = Get-Command cmake.exe -ErrorAction SilentlyContinue
$taskCmake = if ($taskCmakeCommand) { $taskCmakeCommand.Source } else { $null }
if (-not $taskCmake) {
    $taskVswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $taskVswhere)) { throw 'Install Visual Studio 2022 C++ Build Tools with CMake and a Windows SDK.' }
    $taskVS = & $taskVswhere -latest -products '*' -version '[17.0,18.0)' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $taskVS) { throw 'Visual Studio 2022 C++ tools were not found.' }
    $taskCmake = Join-Path $taskVS 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
}
$taskCtest = Join-Path (Split-Path $taskCmake) 'ctest.exe'
if (-not (Test-Path -LiteralPath $taskCtest)) { throw 'ctest.exe must accompany cmake.exe.' }
$taskVmFilter = if ($WithVmFilter) { 'ON' } else { 'OFF' }
& $taskCmake -S $taskRoot -B $BuildDirectory -G 'Visual Studio 17 2022' -A x64 "-DFIDO_ROOT=$FidoRoot" "-DSWA_BUILD_VM_FILTER=$taskVmFilter"
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
& $taskCmake --build $BuildDirectory --config Release
if ($LASTEXITCODE -ne 0) { throw 'Native compilation failed' }
& $taskCtest --test-dir $BuildDirectory -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'Native tests failed' }
