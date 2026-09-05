$ErrorActionPreference = 'Stop'
$taskBackupPath = Join-Path $PSScriptRoot 'signin-preferences-before.json'
if (-not (Test-Path -LiteralPath $taskBackupPath)) { return }
$taskBackup = Get-Content -LiteralPath $taskBackupPath -Raw | ConvertFrom-Json
$taskRegistry = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
try {
    foreach ($taskEntry in $taskBackup.entries) {
        if ($taskEntry.path -notin @('SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8AF662BF-65A0-4D0A-A540-A338A999D36F}','SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI','SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile')) { throw 'Unexpected preference backup path.' }
        $taskKey = $taskRegistry.OpenSubKey($taskEntry.path,$true)
        try {
            if ($null -ne $taskKey -and $taskKey.GetValue($taskEntry.name) -eq $taskEntry.appliedValue) {
                if ($taskEntry.existed) { $taskKey.SetValue($taskEntry.name,$taskEntry.value,[Microsoft.Win32.RegistryValueKind]::$($taskEntry.kind)) }
                else { $taskKey.DeleteValue($taskEntry.name,$false) }
            }
        } finally { if ($taskKey) { $taskKey.Dispose() } }
    }
} finally { $taskRegistry.Dispose() }
