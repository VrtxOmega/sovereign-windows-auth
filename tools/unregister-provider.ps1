$ErrorActionPreference = 'Stop'
$taskAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $taskAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this recovery script as administrator.' }
$taskGuid = '{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}'
$taskRegistration = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\' + $taskGuid
$taskClass = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\' + $taskGuid
$taskRestore = Join-Path $PSScriptRoot 'restore-signin-preferences.ps1'
if (Test-Path -LiteralPath $taskRestore) { & $taskRestore }
# Only these two exact registry keys belong to this provider. Profile and files
# remain for diagnosis; no filesystem deletion or stock-provider change occurs.
if (Test-Path -LiteralPath $taskRegistration) { Remove-Item -LiteralPath $taskRegistration -Recurse }
if (Test-Path -LiteralPath $taskClass) { Remove-Item -LiteralPath $taskClass -Recurse }
Write-Host 'Sovereign key sign-in is unregistered. Use your usual Windows sign-in. No restart was requested.'
