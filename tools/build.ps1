$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskCmake = 'C:\BuildTools\2022\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$taskCtest = 'C:\BuildTools\2022\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe'
& $taskCmake -S $taskRoot -B (Join-Path $taskRoot 'build') -G 'Visual Studio 17 2022' -A x64
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
& $taskCmake --build (Join-Path $taskRoot 'build') --config Release
if ($LASTEXITCODE -ne 0) { throw 'Native compilation failed' }
& $taskCtest --test-dir (Join-Path $taskRoot 'build') -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'Native tests failed' }
