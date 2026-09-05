$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskRelease = Join-Path $taskRoot 'build\Release'
$taskInstall = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SovereignWindowsAuth'
$taskData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SovereignWindowsAuth'
$taskState = Join-Path $taskArtifacts 'provider-display-update-state.json'
$taskHost = Join-Path $taskInstall 'swa_provider_host.exe'
$taskNewDll = Join-Path $taskInstall 'SovereignCredentialProvider-display.dll'
$taskServer = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}\InprocServer32'
$taskSwitched = $false
$taskScheduled = $false
$taskPhase = 'starting'
$taskRunId = [guid]::NewGuid()
$taskName = 'SovereignProviderInspect-' + $taskRunId.ToString()
$Host.UI.RawUI.WindowTitle = 'Sovereign - repair sign-in option display'
try {
    $taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($taskIdentity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'This repair requires administrator access.' }
    $taskPrevious = (Get-ItemProperty -LiteralPath $taskServer).'(default)'
    if ($taskPrevious -ne (Join-Path $taskInstall 'SovereignCredentialProvider.dll')) { throw 'Unexpected provider registration; no change made.' }
    $taskReceipt = Get-Content -LiteralPath (Join-Path $taskArtifacts 'pin-install-receipt.json') -Raw | ConvertFrom-Json
    if ($taskReceipt.phase -ne 'both_keys_verified' -or $taskReceipt.sid -ne $taskIdentity.User.Value -or (Get-FileHash -LiteralPath $taskPrevious -Algorithm SHA256).Hash -ne $taskReceipt.hashes.'SovereignCredentialProvider.dll') { throw 'Previous tested installation does not match.' }
    if ((Get-Item -LiteralPath $taskInstall).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected installation directory.' }
    $taskPhase = 'verifying_display_files'
    if (Test-Path -LiteralPath $taskNewDll) {
        if ((Get-FileHash -LiteralPath $taskNewDll -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath (Join-Path $taskRelease 'SovereignCredentialProvider.dll') -Algorithm SHA256).Hash) { throw 'An unexpected display revision exists; no overwrite performed.' }
    } else { Copy-Item -LiteralPath (Join-Path $taskRelease 'SovereignCredentialProvider.dll') -Destination $taskNewDll }
    Copy-Item -LiteralPath (Join-Path $taskRelease 'swa_provider_host.exe') -Destination $taskHost
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'inspect-provider-system.ps1') -Destination (Join-Path $taskInstall 'inspect-provider-system.ps1')
    $taskHash = (Get-FileHash -LiteralPath $taskNewDll -Algorithm SHA256).Hash
    if ($taskHash -ne (Get-FileHash -LiteralPath (Join-Path $taskRelease 'SovereignCredentialProvider.dll') -Algorithm SHA256).Hash) { throw 'Copied component verification failed.' }
    foreach ($taskDependency in @('fido2.dll','crypto-56.dll','cbor.dll','zlib1.dll')) {
        if ((Get-FileHash -LiteralPath (Join-Path $taskInstall $taskDependency) -Algorithm SHA256).Hash -ne $taskReceipt.hashes.$taskDependency) { throw 'An installed dependency changed.' }
    }
    & $taskHost $taskNewDll --inspect *> (Join-Path $taskArtifacts 'provider-display-admin.log')
    if ($LASTEXITCODE -ne 0) { throw 'The display revision failed its enrolled-user inspection. Registration unchanged.' }
    $taskTrace = Join-Path $taskData 'provider-trace.log'
    if (-not (Test-Path -LiteralPath $taskTrace)) { New-Item -Path $taskTrace -ItemType File | Out-Null }
    $taskPhase = 'enabling_bounded_diagnostics'
    $taskRegistry = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $taskDiagnostics = $taskRegistry.CreateSubKey('SOFTWARE\SovereignWindowsAuth',$true)
        try { $taskDiagnostics.SetValue('DiagnosticsEnabled',1,[Microsoft.Win32.RegistryValueKind]::DWord) } finally { $taskDiagnostics.Dispose() }
        $taskPhase = 'switching_registered_component'
        $taskRegistrationKey = $taskRegistry.OpenSubKey('SOFTWARE\Classes\CLSID\{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}\InprocServer32',$true)
        try { $taskRegistrationKey.SetValue('',$taskNewDll,[Microsoft.Win32.RegistryValueKind]::String) } finally { $taskRegistrationKey.Dispose() }
    } finally { $taskRegistry.Dispose() }
    $taskSwitched = $true
    & $taskHost $taskNewDll --registered-sid $taskIdentity.User.Value *> (Join-Path $taskArtifacts 'provider-display-registered.log')
    if ($LASTEXITCODE -ne 0) { throw 'The registered component could not load. Restoring the previous registration.' }
    $taskPhase = 'running_system_inspection'
    $taskArguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $taskInstall 'inspect-provider-system.ps1') + '" -TargetSid ' + $taskIdentity.User.Value + ' -RunId ' + $taskRunId.ToString()
    $taskAction = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument $taskArguments -WorkingDirectory $taskInstall
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings | Out-Null
    $taskScheduled = $true
    Start-ScheduledTask -TaskName $taskName
    @{phase='checking_system_context'; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    $taskSystemState = Join-Path $taskData ('system-inspect-' + $taskRunId.ToString() + '.json')
    $taskDeadline = (Get-Date).AddSeconds(55)
    while (-not (Test-Path -LiteralPath $taskSystemState) -and (Get-Date) -lt $taskDeadline) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path -LiteralPath $taskSystemState)) { throw 'SYSTEM inspection did not finish; restoring the previous registration.' }
    $taskResult = Get-Content -LiteralPath $taskSystemState -Raw | ConvertFrom-Json
    Copy-Item -LiteralPath $taskSystemState -Destination (Join-Path $taskArtifacts 'provider-display-system-state.json')
    Copy-Item -LiteralPath (Join-Path $taskData ('system-inspect-' + $taskRunId.ToString() + '.log')) -Destination (Join-Path $taskArtifacts 'provider-display-system.log')
    if ($taskResult.phase -ne 'finished' -or $taskResult.exitCode -ne 0 -or $taskResult.executionSid -ne 'S-1-5-18') { throw 'SYSTEM could not enumerate the enrolled sign-in option; restoring the previous registration.' }
    @{phase='updated_system_verified_desktop_test_pending'; path=$taskNewDll; sha256=$taskHash; previousPath=$taskPrevious; systemInspection=$taskResult; authenticationAttempted=$false; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskState
    Write-Host 'Windows loaded the repaired component as SYSTEM and found your sign-in option, icon, and label. The actual lock-screen test is next.'
} catch {
    if ($taskSwitched) { Set-Item -LiteralPath $taskServer -Value $taskPrevious }
    @{phase='stopped'; failedStage=$taskPhase; error=$_.Exception.Message; location=$_.InvocationInfo.PositionMessage; errorId=$_.FullyQualifiedErrorId; registrationRestored=$taskSwitched; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    Write-Host $_.Exception.Message
} finally {
    if ($taskScheduled) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}
Read-Host 'Press Enter to close this helper'
