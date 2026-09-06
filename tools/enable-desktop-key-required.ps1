param(
 [Parameter(Mandatory)][string]$BuildDirectory,
 [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedFilterSha256,
 [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedProviderSha256,
 [Parameter(Mandatory)][string]$RecoveryTool,
 [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedRecoverySha256,
 [Parameter(Mandatory)][string]$RecoveryKey,
 [Parameter(Mandatory)][string[]]$ReviewedProviderIds,
 [string[]]$ReviewedHiddenBackgroundSids=@()
)
$ErrorActionPreference='Stop'
# Operator opt-in after VM recovery and physical recovery-boot validation.
# No PIN/password entry, enrollment changes, reboot, account-rights changes, or
# automatic fallback. Recovery removes only the separate filter registration.
$taskPrincipal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $taskPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run from an elevated administrator session.'}
if((Get-CimInstance Win32_ComputerSystem).PartOfDomain){throw 'Domain account coverage is outside this bounded trial.'}
$taskProviderId='{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}'
$taskFilterId='{51583B4D-1D80-4692-B4EF-1C385FBCF22D}'
$taskProviders='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$taskFilterRegistration='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\'+$taskFilterId
$taskClass='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\'+$taskFilterId
$taskConfiguration='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\SovereignWindowsAuth\DesktopFilter'
if((Test-Path -LiteralPath $taskFilterRegistration) -or (Test-Path -LiteralPath $taskClass) -or (Test-Path -LiteralPath $taskConfiguration)){
 throw 'An existing filter installation/configuration requires review; nothing will be overwritten.'
}
$taskActualIds=@(Get-ChildItem -LiteralPath $taskProviders | ForEach-Object {([guid]$_.PSChildName).ToString('B').ToUpperInvariant()} | Sort-Object)
$taskReviewedIds=@($ReviewedProviderIds | ForEach-Object {([guid]$_).ToString('B').ToUpperInvariant()} | Sort-Object)
if(Compare-Object $taskActualIds $taskReviewedIds){throw 'Provider inventory changed or was not reviewed in full.'}
foreach($taskId in @($taskProviderId,'{D6886603-9D2F-4EB2-B667-1971041FA96B}','{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}')){
 if(-not(Test-Path -LiteralPath (Join-Path $taskProviders $taskId))){throw 'Required Sovereign/PIN/password registration missing.'}
}
$taskCurrentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$taskHidden=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' -ErrorAction SilentlyContinue
$taskAdmins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})
$taskOtherUsers=@(Get-LocalUser | Where-Object {$_.Enabled -and $_.SID.Value -ne $taskCurrentSid})
foreach($taskUser in $taskOtherUsers){
 if($ReviewedHiddenBackgroundSids -notcontains $taskUser.SID.Value -or $null -eq $taskHidden -or
    $taskHidden.($taskUser.Name) -ne 0 -or $taskAdmins -contains $taskUser.SID.Value){
  throw 'An additional enabled account is not an explicitly reviewed hidden background account.'
 }
}
$taskProfileCheck=@(& (Join-Path $BuildDirectory 'swa_probe.exe') --profile-check 2>&1)
if($LASTEXITCODE -ne 0){throw 'The current protected enrollment must contain at least two keys and use the Windows PIN bridge.'}
$taskProfile=($taskProfileCheck -join '') | ConvertFrom-Json
if(-not $taskProfile.windowsPin -or $taskProfile.enrolledKeys -lt 2){throw 'Two-key PIN enrollment was not verified.'}
$taskFilterSource=(Resolve-Path -LiteralPath (Join-Path $BuildDirectory 'SovereignCredentialFilter.dll')).Path
if((Get-FileHash -LiteralPath $taskFilterSource -Algorithm SHA256).Hash -ne $ExpectedFilterSha256){throw 'Filter binary does not match the validated artifact.'}
if((Get-FileHash -LiteralPath $RecoveryTool -Algorithm SHA256).Hash -ne $ExpectedRecoverySha256){throw 'Recovery tool does not match the validated artifact.'}
$taskUsbCheck=@(& $RecoveryTool --check-usb $RecoveryKey 2>&1)
if($LASTEXITCODE -ne 0){throw 'Paired removable recovery credential could not be verified.'}
$taskProviderClass='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\'+$taskProviderId+'\InprocServer32'
$taskProviderPath=[string](Get-ItemProperty -LiteralPath $taskProviderClass).'(default)'
if((Get-FileHash -LiteralPath $taskProviderPath -Algorithm SHA256).Hash -ne $ExpectedProviderSha256){throw 'Working provider differs from the verified baseline.'}
$taskParent=Join-Path $env:ProgramFiles 'SovereignWindowsAuth'
$taskInstallDirectory=Join-Path $taskParent ('Filter-'+$ExpectedFilterSha256.Substring(0,16).ToLowerInvariant())
if((Get-Item -LiteralPath $taskParent).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Install parent is redirected.'}
if(Test-Path -LiteralPath $taskInstallDirectory){throw 'Filter staging directory already exists; inspect before repeating.'}
New-Item -ItemType Directory -Path $taskInstallDirectory | Out-Null
$taskFileAcl=[Security.AccessControl.DirectorySecurity]::new()
$taskFileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)')
Set-Acl -LiteralPath $taskInstallDirectory -AclObject $taskFileAcl
$taskDestination=Join-Path $taskInstallDirectory 'SovereignCredentialFilter.dll'
Copy-Item -LiteralPath $taskFilterSource -Destination $taskDestination
if((Get-FileHash -LiteralPath $taskDestination -Algorithm SHA256).Hash -ne $ExpectedFilterSha256){throw 'Installed filter verification failed.'}
$taskCreatedRegistration=$false
try{
 New-Item -Path $taskConfiguration | Out-Null
 $taskRegistryAcl=[Security.AccessControl.RegistrySecurity]::new()
 $taskRegistryAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)')
 Set-Acl -LiteralPath $taskConfiguration -AclObject $taskRegistryAcl
 New-ItemProperty -LiteralPath $taskConfiguration -Name Version -PropertyType DWord -Value 1 | Out-Null
 New-ItemProperty -LiteralPath $taskConfiguration -Name Mode -PropertyType DWord -Value 2 | Out-Null
 New-ItemProperty -LiteralPath $taskConfiguration -Name EnrolledAccountSid -PropertyType String -Value $taskCurrentSid | Out-Null
 New-ItemProperty -LiteralPath $taskConfiguration -Name ActivatedUtc -PropertyType String -Value ([DateTime]::UtcNow.ToString('o')) | Out-Null
 New-ItemProperty -LiteralPath $taskConfiguration -Name ProviderSha256 -PropertyType String -Value $ExpectedProviderSha256 | Out-Null
 New-Item -Path ($taskClass+'\InprocServer32') -Force | Out-Null
 Set-Item -LiteralPath ($taskClass+'\InprocServer32') -Value $taskDestination
 New-ItemProperty -LiteralPath ($taskClass+'\InprocServer32') -Name ThreadingModel -PropertyType String -Value Apartment | Out-Null
 # Registration is the final activation step. Preserve the original provider.
 New-Item -Path $taskFilterRegistration | Out-Null
 $taskCreatedRegistration=$true
 Set-Item -LiteralPath $taskFilterRegistration -Value 'Sovereign local desktop key requirement'
 if((Get-FileHash -LiteralPath $taskProviderPath -Algorithm SHA256).Hash -ne $ExpectedProviderSha256){throw 'Original provider changed during activation.'}
 [pscustomobject]@{activated=$true;filterPath=$taskDestination;enrolledKeys=$taskProfile.enrolledKeys;pinPreserved=$true;restartRequested=$false}
}catch{
 # Roll back an incomplete activation only; runtime failures require recovery.
 if($taskCreatedRegistration){Remove-Item -LiteralPath $taskFilterRegistration -ErrorAction Stop}
 throw
}
