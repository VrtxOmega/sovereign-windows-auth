$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$taskData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SovereignWindowsAuth'
$taskTrace = Join-Path $taskData 'provider-trace.log'
try {
    if (-not ([Security.Principal.WindowsPrincipal]::new($taskIdentity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Diagnostic collection requires administrator access.' }
    if ((Get-Item -LiteralPath $taskData).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected redirected diagnostic directory.' }
    if ((Get-Item -LiteralPath $taskTrace).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected redirected trace file.' }
    Copy-Item -LiteralPath $taskTrace -Destination (Join-Path $taskArtifacts 'lock-screen-provider-trace.log')
    # This file contains only fixed stage names, counts and status codes. Grant
    # the enrolled user read access to this log only, preserving directory/profile ACLs.
    $taskAcl = Get-Acl -LiteralPath $taskTrace
    $taskRead = [Security.AccessControl.FileSystemAccessRule]::new($taskIdentity.User,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)
    $taskAcl.SetAccessRule($taskRead)
    Set-Acl -LiteralPath $taskTrace -AclObject $taskAcl
    $taskSince = (Get-Date).AddMinutes(-25)
    $taskAllowed = @('TargetUserSid','TargetUserName','LogonType','LogonProcessName','AuthenticationPackageName','Status','SubStatus','ProcessName')
    $taskEvents = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=$taskSince} -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
        $taskEvent = $_
        $taskXml = [xml]$taskEvent.ToXml()
        $taskValues = @{}
        foreach ($taskField in $taskXml.Event.EventData.Data) { if ($taskField.Name -in $taskAllowed) { $taskValues[$taskField.Name] = $taskField.'#text' } }
        @{time=$taskEvent.TimeCreated.ToUniversalTime().ToString('o');event=$taskEvent.Id;values=$taskValues}
    })
    $taskEvents | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskArtifacts 'lock-screen-security-events.json')
    @{phase='collected'; time=(Get-Date).ToUniversalTime().ToString('o'); traceReadableByEnrolledUser=$true; secretProfilePermissionsChanged=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskArtifacts 'lock-screen-diagnostics-state.json')
} catch {
    @{phase='stopped'; error=$_.Exception.Message; location=$_.InvocationInfo.PositionMessage} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskArtifacts 'lock-screen-diagnostics-state.json')
}
