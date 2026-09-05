$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskRelease = Join-Path $taskRoot 'build\Release'
$taskInstall = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SovereignWindowsAuth'
$taskPackage = Join-Path $taskInstall 'touch-refresh'
$taskData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SovereignWindowsAuth'
$taskState = Join-Path $taskArtifacts 'touch-refresh-state.json'
$taskServerPath = 'SOFTWARE\Classes\CLSID\{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}\InprocServer32'
$taskScheduled = $false
$taskSwitched = $false
$taskRunId = [guid]::NewGuid()
$taskName = 'SovereignRefreshCheck-' + $taskRunId.ToString()
$Host.UI.RawUI.WindowTitle = 'Sovereign - verify sign-in refresh repair'
try {
    $taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($taskIdentity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'This update needs administrator access.' }
    $taskPreviousReceipt = Get-Content -LiteralPath (Join-Path $taskArtifacts 'touch-handoff-state.json') -Raw | ConvertFrom-Json
    $taskPrevious = (Get-ItemProperty -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\' + $taskServerPath)).'(default)'
    if ($taskPrevious -ne $taskPreviousReceipt.path -or (Get-FileHash -LiteralPath $taskPrevious -Algorithm SHA256).Hash -ne $taskPreviousReceipt.hashes.'SovereignCredentialProvider.dll') { throw 'The installed revision does not match its validation record.' }
    if (Test-Path -LiteralPath $taskPackage) { throw 'A refresh package already exists; inspect before replacing it.' }
    New-Item -Path $taskPackage -ItemType Directory | Out-Null
    $taskHashes = @{}
    foreach ($taskFile in @('SovereignCredentialProvider.dll','swa_provider_host.exe','fido2.dll','crypto-56.dll','cbor.dll','zlib1.dll')) {
        Copy-Item -LiteralPath (Join-Path $taskRelease $taskFile) -Destination (Join-Path $taskPackage $taskFile)
        $taskHashes[$taskFile] = (Get-FileHash -LiteralPath (Join-Path $taskPackage $taskFile) -Algorithm SHA256).Hash
        if ($taskHashes[$taskFile] -ne (Get-FileHash -LiteralPath (Join-Path $taskRelease $taskFile) -Algorithm SHA256).Hash) { throw 'A copied binary did not match.' }
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'authenticate-provider-system.ps1') -Destination (Join-Path $taskPackage 'authenticate-provider-system.ps1')
    $taskHost = Join-Path $taskPackage 'swa_provider_host.exe'
    $taskDll = Join-Path $taskPackage 'SovereignCredentialProvider.dll'
    & $taskHost $taskDll --inspect *> (Join-Path $taskArtifacts 'touch-refresh-inspect.log')
    if ($LASTEXITCODE -ne 0) { throw 'The updated component did not pass its enrollment/display checks.' }
    @{phase='waiting_for_first_touch_test'; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    Write-Host 'Connect either ONE enrolled YubiKey. First we test the exact refresh sequence Windows used.'
    Read-Host 'Press Enter when you are ready to touch the key'
    $taskUser = ($taskIdentity.Name -split '\\')[-1]
    $taskArguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $taskPackage 'authenticate-provider-system.ps1') + '" -TargetUser "' + $taskUser + '" -RunId ' + $taskRunId.ToString()
    $taskAction = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument $taskArguments -WorkingDirectory $taskPackage
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings | Out-Null
    $taskScheduled = $true
    @{phase='testing_refresh_with_system_authentication'; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    Write-Host 'Touch the YubiKey when it blinks.'
    Start-ScheduledTask -TaskName $taskName
    $taskSystemState = Join-Path $taskData ('system-auth-' + $taskRunId.ToString() + '.json')
    $taskDeadline = (Get-Date).AddSeconds(55)
    while (-not (Test-Path -LiteralPath $taskSystemState) -and (Get-Date) -lt $taskDeadline) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path -LiteralPath $taskSystemState)) { throw 'SYSTEM authentication did not finish; no registration change.' }
    $taskResult = Get-Content -LiteralPath $taskSystemState -Raw | ConvertFrom-Json
    Copy-Item -LiteralPath $taskSystemState -Destination (Join-Path $taskArtifacts 'touch-refresh-system-state.json')
    Copy-Item -LiteralPath (Join-Path $taskData ('system-auth-' + $taskRunId.ToString() + '.log')) -Destination (Join-Path $taskArtifacts 'touch-refresh-system.log')
    if ($taskResult.phase -ne 'finished' -or $taskResult.exitCode -ne 0) { throw 'SYSTEM refresh test stopped. No automatic retry or registration change.' }
    @{phase='waiting_for_cancellation_touch_test'; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    Write-Host 'The refresh test passed. One more touch checks that canceling a successful key request still prevents sign-in.'
    Read-Host 'Press Enter when ready, then touch the key again'
    & $taskHost $taskDll --cancel-ready *> (Join-Path $taskArtifacts 'touch-refresh-cancel-ready.log')
    if ($LASTEXITCODE -ne 0) { throw 'Cancellation of a completed key proof did not pass.' }
    $taskRegistry = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $taskServer = $taskRegistry.OpenSubKey($taskServerPath,$true)
        try { $taskServer.SetValue('',$taskDll,[Microsoft.Win32.RegistryValueKind]::String); $taskSwitched=$true } finally { $taskServer.Dispose() }
        & $taskHost $taskDll --registered-sid $taskIdentity.User.Value *> (Join-Path $taskArtifacts 'touch-refresh-registered.log')
        if ($LASTEXITCODE -ne 0) { throw 'Registered component inspection failed.' }
    } finally { $taskRegistry.Dispose() }
    @{phase='installed_observed_refresh_sequence_passed'; path=$taskDll; previousPath=$taskPrevious; hashes=$taskHashes; systemAuthentication=$taskResult; completedProofCancellationPassed=$true; desktopUnlockValidated=$false; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskState
    Write-Host 'The repair is installed. The observed Windows refresh sequence and completed-proof cancellation both passed. The actual lock-screen test is next.'
} catch {
    if ($taskSwitched) { Set-Item -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\' + $taskServerPath) -Value $taskPrevious }
    @{phase='stopped';error=$_.Exception.Message;location=$_.InvocationInfo.PositionMessage;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    Write-Host $_.Exception.Message
} finally {
    if ($taskScheduled) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
}
Read-Host 'Press Enter to close this helper'
