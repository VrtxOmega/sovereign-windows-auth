$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskRelease = Join-Path $taskRoot 'build\Release'
$taskInstall = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SovereignWindowsAuth'
$taskPackage = Join-Path $taskInstall 'touch-handoff'
$taskData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SovereignWindowsAuth'
$taskState = Join-Path $taskArtifacts 'touch-handoff-state.json'
$taskServerPath = 'SOFTWARE\Classes\CLSID\{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}\InprocServer32'
$taskScheduled = $false
$taskSwitched = $false
$taskPreferences = $false
$taskRunId = [guid]::NewGuid()
$taskName = 'SovereignAuthCheck-' + $taskRunId.ToString()
$Host.UI.RawUI.WindowTitle = 'Sovereign - verify touch-only sign-in handoff'
try {
    $taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($taskIdentity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'This update needs administrator access.' }
    $taskPreviousReceipt = Get-Content -LiteralPath (Join-Path $taskArtifacts 'provider-display-update-state.json') -Raw | ConvertFrom-Json
    $taskPrevious = (Get-ItemProperty -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\' + $taskServerPath)).'(default)'
    if ($taskPrevious -ne $taskPreviousReceipt.path -or (Get-FileHash -LiteralPath $taskPrevious -Algorithm SHA256).Hash -ne $taskPreviousReceipt.sha256) { throw 'The installed revision does not match the previous validation.' }
    if (Test-Path -LiteralPath $taskPackage) { throw 'A handoff package already exists; inspect before replacing it.' }
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
    & $taskHost $taskDll --inspect *> (Join-Path $taskArtifacts 'touch-handoff-inspect.log')
    if ($LASTEXITCODE -ne 0) { throw 'The updated component did not pass its enrollment/display checks.' }
    Write-Host 'Connect either ONE enrolled YubiKey. This test runs as Windows SYSTEM and requires only a touch.'
    Read-Host 'Press Enter when the key is connected and you are ready to touch it'
    $taskUser = ($taskIdentity.Name -split '\\')[-1]
    $taskArguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $taskPackage 'authenticate-provider-system.ps1') + '" -TargetUser "' + $taskUser + '" -RunId ' + $taskRunId.ToString()
    $taskAction = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument $taskArguments -WorkingDirectory $taskPackage
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings | Out-Null
    $taskScheduled = $true
    @{phase='waiting_for_system_key_touch'; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    Write-Host 'Touch the YubiKey when it blinks.'
    Start-ScheduledTask -TaskName $taskName
    $taskSystemState = Join-Path $taskData ('system-auth-' + $taskRunId.ToString() + '.json')
    $taskDeadline = (Get-Date).AddSeconds(55)
    while (-not (Test-Path -LiteralPath $taskSystemState) -and (Get-Date) -lt $taskDeadline) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path -LiteralPath $taskSystemState)) { throw 'SYSTEM authentication did not finish; no registration change.' }
    $taskResult = Get-Content -LiteralPath $taskSystemState -Raw | ConvertFrom-Json
    Copy-Item -LiteralPath $taskSystemState -Destination (Join-Path $taskArtifacts 'touch-handoff-system-state.json')
    Copy-Item -LiteralPath (Join-Path $taskData ('system-auth-' + $taskRunId.ToString() + '.log')) -Destination (Join-Path $taskArtifacts 'touch-handoff-system.log')
    if ($taskResult.phase -ne 'finished' -or $taskResult.exitCode -ne 0) { throw 'SYSTEM authentication stopped. No automatic retry or registration change.' }
    Write-Host 'The SYSTEM authentication passed. For the cancellation check, DO NOT touch the key.'
    & $taskHost $taskDll --cancel *> (Join-Path $taskArtifacts 'touch-handoff-cancel.log')
    if ($LASTEXITCODE -ne 0) { throw 'Cancellation check did not pass.' }
    $taskRegistry = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $taskServer = $taskRegistry.OpenSubKey($taskServerPath,$true)
        try { $taskServer.SetValue('',$taskDll,[Microsoft.Win32.RegistryValueKind]::String); $taskSwitched=$true } finally { $taskServer.Dispose() }
        & $taskHost $taskDll --registered-sid $taskIdentity.User.Value *> (Join-Path $taskArtifacts 'touch-handoff-registered.log')
        if ($LASTEXITCODE -ne 0) { throw 'Registered component inspection failed.' }
        $taskEntries = @(
            @{path='SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8AF662BF-65A0-4D0A-A540-A338A999D36F}';name='Disabled';appliedValue=1;newKind='DWord'},
            @{path='SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI';name='LastLoggedOnProvider';appliedValue='{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}';newKind='String'},
            @{path='SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile';name=$taskIdentity.User.Value;appliedValue='{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}';newKind='String'}
        )
        foreach ($taskEntry in $taskEntries) {
            $taskKey = $taskRegistry.OpenSubKey($taskEntry.path,$true)
            try {
                $taskEntry.existed=$taskKey.GetValueNames() -contains $taskEntry.name
                $taskEntry.value=$taskKey.GetValue($taskEntry.name)
                $taskEntry.kind=if ($taskEntry.existed) { $taskKey.GetValueKind($taskEntry.name).ToString() } else { $taskEntry.newKind }
            } finally { $taskKey.Dispose() }
        }
        $taskBackup = Join-Path $taskInstall 'signin-preferences-before.json'
        if (Test-Path -LiteralPath $taskBackup) { throw 'A preference backup already exists; preserve it for review.' }
        @{entries=$taskEntries;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskBackup
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'restore-signin-preferences.ps1') -Destination (Join-Path $taskInstall 'restore-signin-preferences.ps1')
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'unregister-provider.ps1') -Destination (Join-Path $taskInstall 'unregister-provider.ps1')
        $taskPreferences=$true
        foreach ($taskEntry in $taskEntries) {
            $taskKey = $taskRegistry.OpenSubKey($taskEntry.path,$true)
            try { $taskKey.SetValue($taskEntry.name,$taskEntry.appliedValue,[Microsoft.Win32.RegistryValueKind]::$($taskEntry.newKind)) } finally { $taskKey.Dispose() }
        }
    } finally { $taskRegistry.Dispose() }
    @{phase='installed_system_authentication_passed'; path=$taskDll; hashes=$taskHashes; systemAuthentication=$taskResult; faceSignInDisabled=$true; pinRecoveryEnabled=$true; desktopUnlockValidated=$false; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskState
    Write-Host 'The handoff update is installed. Sovereign is preferred, the face sign-in provider is paused, and your usual PIN remains available for recovery.'
} catch {
    if ($taskPreferences) { & (Join-Path $taskInstall 'restore-signin-preferences.ps1') }
    if ($taskSwitched) { Set-Item -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\' + $taskServerPath) -Value $taskPrevious }
    @{phase='stopped';error=$_.Exception.Message;location=$_.InvocationInfo.PositionMessage;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $taskState
    Write-Host $_.Exception.Message
} finally {
    if ($taskScheduled) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
}
Read-Host 'Press Enter to close this helper'
