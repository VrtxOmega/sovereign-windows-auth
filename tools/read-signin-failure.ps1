$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskOutput = Join-Path $taskRoot 'artifacts\windows-account-diagnostic.json'
try {
    $taskEvents = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddMinutes(-30)} -ErrorAction SilentlyContinue
    $taskRows = @()
    foreach ($taskEvent in $taskEvents) {
        [xml]$taskXml = $taskEvent.ToXml()
        $taskFields = @{}
        foreach ($taskData in $taskXml.Event.EventData.Data) { $taskFields[$taskData.Name] = $taskData.'#text' }
        if ($taskFields.ProcessName -like '*swa_enroll.exe') {
            $taskRows += [ordered]@{time=$taskEvent.TimeCreated.ToUniversalTime().ToString('o');status=$taskFields.Status;subStatus=$taskFields.SubStatus;failureReason=$taskFields.FailureReason;logonType=$taskFields.LogonType;package=$taskFields.AuthenticationPackageName;logonProcess=$taskFields.LogonProcessName}
        }
    }
    @{status='read';events=$taskRows} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $taskOutput
} catch {
    @{status='unavailable';errorType=$_.Exception.GetType().Name} | ConvertTo-Json | Set-Content -LiteralPath $taskOutput
}
