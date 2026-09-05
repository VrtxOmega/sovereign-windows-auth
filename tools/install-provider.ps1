$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskRelease = Join-Path $taskRoot 'build\Release'
$taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$taskAdmin = [Security.Principal.WindowsPrincipal]::new($taskIdentity)
if (-not [Environment]::Is64BitProcess -or -not $taskAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use 64-bit PowerShell as administrator.' }
$taskReceipt = Get-Content -LiteralPath (Join-Path $taskArtifacts 'pin-install-receipt.json') -Raw | ConvertFrom-Json
if ($taskReceipt.phase -ne 'both_keys_verified' -or $taskReceipt.sid -ne $taskIdentity.User.Value) { throw 'This account needs both-key validation before installation.' }
$taskFiles = @('SovereignCredentialProvider.dll','fido2.dll','crypto-56.dll','cbor.dll','zlib1.dll')
foreach ($taskFile in $taskFiles) {
    $taskSource = Join-Path $taskRelease $taskFile
    if ((Get-FileHash -LiteralPath $taskSource -Algorithm SHA256).Hash -ne $taskReceipt.hashes.$taskFile) { throw "The tested file changed: $taskFile" }
    if ($taskFile -ne 'SovereignCredentialProvider.dll') {
        $taskSignature = Get-AuthenticodeSignature -LiteralPath $taskSource
        if ($taskSignature.Status -ne 'Valid' -or $taskSignature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Yubico AB(,|$)') { throw "Untrusted Yubico dependency: $taskFile" }
    }
}
$taskGuid = '{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}'
$taskRegistration = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\' + $taskGuid
$taskClass = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\' + $taskGuid
if ((Test-Path -LiteralPath $taskRegistration) -or (Test-Path -LiteralPath $taskClass)) { throw 'An existing Sovereign registration must be inspected before replacing it.' }
$taskInstall = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SovereignWindowsAuth'
if (Test-Path -LiteralPath $taskInstall) { throw 'An existing installation directory must be inspected before replacing it.' }
New-Item -ItemType Directory -Path $taskInstall | Out-Null
$taskAcl = [Security.AccessControl.DirectorySecurity]::new()
$taskAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
Set-Acl -LiteralPath $taskInstall -AclObject $taskAcl
foreach ($taskFile in $taskFiles) {
    $taskDestination = Join-Path $taskInstall $taskFile
    Copy-Item -LiteralPath (Join-Path $taskRelease $taskFile) -Destination $taskDestination
    if ((Get-FileHash -LiteralPath $taskDestination -Algorithm SHA256).Hash -ne $taskReceipt.hashes.$taskFile) { throw "Installed file verification failed: $taskFile" }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'unregister-provider.ps1') -Destination (Join-Path $taskInstall 'unregister-provider.ps1')
$taskRecovery = '@echo off' + "`r`n" + 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0unregister-provider.ps1"' + "`r`n" + 'pause' + "`r`n"
Set-Content -LiteralPath (Join-Path $taskInstall 'Recover-Windows-Signin.cmd') -Value $taskRecovery -Encoding ASCII
& (Join-Path $taskRelease 'swa_provider_host.exe') (Join-Path $taskInstall 'SovereignCredentialProvider.dll') *> (Join-Path $taskArtifacts 'installed-provider-contract.log')
if ($LASTEXITCODE -ne 0) { throw 'The installed provider failed its contract check. No registration was made.' }
$taskClassCreated = $false
$taskRegistrationCreated = $false
try {
    New-Item -Path $taskClass | Out-Null
    $taskClassCreated = $true
    Set-Item -LiteralPath $taskClass -Value 'Sovereign Windows authentication'
    $taskServer = New-Item -Path ($taskClass + '\InprocServer32')
    Set-Item -LiteralPath $taskServer.PSPath -Value (Join-Path $taskInstall 'SovereignCredentialProvider.dll')
    New-ItemProperty -LiteralPath $taskServer.PSPath -Name 'ThreadingModel' -Value 'Apartment' -PropertyType String | Out-Null
    New-Item -Path $taskRegistration | Out-Null
    $taskRegistrationCreated = $true
    Set-Item -LiteralPath $taskRegistration -Value 'Sovereign key'
    @{phase='registered_desktop_test_pending'; time=(Get-Date).ToUniversalTime().ToString('o'); path=$taskInstall; sid=$taskIdentity.User.Value; hashes=$taskReceipt.hashes} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskArtifacts 'provider-install-state.json')
    Write-Host 'Sovereign key is installed. Your usual Windows sign-in remains available. Desktop unlock still needs to be tested.'
} catch {
    if ($taskRegistrationCreated) { Remove-Item -LiteralPath $taskRegistration -Recurse }
    if ($taskClassCreated) { Remove-Item -LiteralPath $taskClass -Recurse }
    throw
}
