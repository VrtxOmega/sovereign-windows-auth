$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskState = Join-Path $taskArtifacts 'native-tools-state.json'
try {
    $taskPython = Join-Path (Split-Path $taskRoot) 'yubikey\venv\Scripts\python.exe'
    & $taskPython (Join-Path $PSScriptRoot 'inspect_key.py')
    if ($LASTEXITCODE -ne 0) { throw 'Read-only FIDO inventory failed.' }
    $taskInstaller = Join-Path $taskArtifacts 'vs_BuildTools.exe'
    $taskSignature = Get-AuthenticodeSignature -LiteralPath $taskInstaller
    if ($taskSignature.Status -ne 'Valid' -or $taskSignature.SignerCertificate.Subject -notlike 'CN=Microsoft Corporation,*') {
        throw 'Microsoft installer signature did not verify.'
    }
    @{phase='installing'; started=(Get-Date).ToUniversalTime().ToString('o'); sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $taskInstaller).Hash} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    $taskArgs = @('--quiet','--wait','--norestart','--installPath','"C:\BuildTools\2022"','--add','Microsoft.VisualStudio.Workload.VCTools','--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','--add','Microsoft.VisualStudio.Component.Windows11SDK.26100','--add','Microsoft.VisualStudio.Component.VC.CMake.Project','--addProductLang','en-US')
    $taskProcess = Start-Process -FilePath $taskInstaller -ArgumentList $taskArgs -WindowStyle Hidden -Wait -PassThru
    if ($taskProcess.ExitCode -notin @(0,3010)) { throw ('Build tools installer exit ' + $taskProcess.ExitCode) }
    @{phase='installed'; exitCode=$taskProcess.ExitCode; restartRequired=($taskProcess.ExitCode -eq 3010); finished=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
} catch {
    @{phase='failed'; error=$_.Exception.Message; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    exit 1
}
