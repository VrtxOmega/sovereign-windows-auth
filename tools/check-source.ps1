$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskErrors = [System.Collections.Generic.List[string]]::new()
Get-ChildItem -LiteralPath (Join-Path $taskRoot 'tools') -Filter '*.ps1' -File | ForEach-Object {
    $taskTokens = $null
    $taskParseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$taskTokens, [ref]$taskParseErrors)
    foreach ($taskError in $taskParseErrors) { $taskErrors.Add(($_.Name + ':' + $taskError.Extent.StartLineNumber + ': ' + $taskError.Message)) }
}
if ($taskErrors.Count) { throw ($taskErrors -join "`n") }
$taskTracked = & git -C $taskRoot ls-files
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect tracked source files.' }
foreach ($taskFile in $taskTracked) {
    if ($taskFile -match '^(artifacts|build|research|\.venv|out)/' -or $taskFile -match '\.(swa|swt|swm|pfx|p12|pem|key|dmp|zip|log|dll|exe|iso|wim|hive|img|qcow2|vhd|vhdx)$') {
        throw "Private/generated material must not be tracked: $taskFile"
    }
    $taskLines = Get-Content -LiteralPath (Join-Path $taskRoot $taskFile)
    for ($taskIndex = 0; $taskIndex -lt $taskLines.Count; $taskIndex++) {
        if ($taskLines[$taskIndex] -match '-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----' -or
            $taskLines[$taskIndex] -match 'github_pat_[A-Za-z0-9_]{30,}|gh[pousr]_[A-Za-z0-9]{30,}') {
            throw ('Possible credential in ' + $taskFile + ':' + ($taskIndex + 1))
        }
    }
}
& git -C $taskRoot diff --check
if ($LASTEXITCODE -ne 0) { throw 'Source whitespace check failed.' }
Write-Host 'PowerShell syntax and tracked-source checks passed. This is a limited check, not a security audit.'
