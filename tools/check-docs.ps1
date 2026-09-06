$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskPaths = @(& git -C $taskRoot ls-files --cached --others --exclude-standard)
if ($LASTEXITCODE -ne 0) { throw 'Could not list repository files.' }
$taskFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($taskPath in $taskPaths) { $null = $taskFiles.Add($taskPath.Replace('\', '/')) }
$taskErrors = [Collections.Generic.List[string]]::new()
$taskAnchors = @{}
$taskLinkCount = 0

function Get-TaskMarkdownBody([string]$Path) {
    $taskFence = ''
    $taskBody = foreach ($taskLine in (Get-Content -LiteralPath $Path -Encoding UTF8)) {
        if ($taskLine -match '^\s*(\x60{3,}|~{3,})') {
            $taskMarker = $Matches[1]
            if (-not $taskFence) { $taskFence = $taskMarker }
            elseif ($taskMarker[0] -eq $taskFence[0] -and $taskMarker.Length -ge $taskFence.Length) { $taskFence = '' }
            continue
        }
        if (-not $taskFence) { $taskLine }
    }
    return ($taskBody -join [Environment]::NewLine)
}

function Get-TaskAnchors([string]$Path) {
    if ($taskAnchors.ContainsKey($Path)) { return ,$taskAnchors[$Path] }
    $taskResult = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $taskCounts = @{}
    foreach ($taskHeading in [regex]::Matches((Get-TaskMarkdownBody $Path), '(?m)^#{1,6}\s+(.+?)\s*#*\s*$')) {
        $taskSlug = $taskHeading.Groups[1].Value.ToLowerInvariant()
        $taskSlug = [regex]::Replace($taskSlug, '<[^>]+>', '')
        $taskSlug = [regex]::Replace($taskSlug, '[^\p{L}\p{Nd}\p{M}_\-\s]', '')
        $taskSlug = [regex]::Replace($taskSlug, '\s', '-')
        if ($taskCounts.ContainsKey($taskSlug)) {
            $taskCounts[$taskSlug]++
            $taskSlug += '-' + $taskCounts[$taskSlug]
        } else { $taskCounts[$taskSlug] = 0 }
        $null = $taskResult.Add($taskSlug)
    }
    $taskAnchors[$Path] = $taskResult
    return ,$taskResult
}

foreach ($taskRelative in ($taskPaths | Where-Object { $_ -match '\.md$' })) {
    $taskFile = Join-Path $taskRoot $taskRelative
    $taskText = Get-TaskMarkdownBody $taskFile
    $taskTargets = @([regex]::Matches($taskText, '\]\((?<target><[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)') |
        ForEach-Object { $_.Groups['target'].Value.Trim('<', '>') })
    $taskTargets += @([regex]::Matches($taskText, '\b(?:href|src)=["''](?<target>[^"'']+)["'']') |
        ForEach-Object { $_.Groups['target'].Value })
    foreach ($taskTarget in $taskTargets) {
        if ($taskTarget -match '^(?:[a-z][a-z0-9+.-]*:|//)') { continue }
        $taskLinkCount++
        $taskParts = $taskTarget -split '#', 2
        $taskPathPart = [Uri]::UnescapeDataString(($taskParts[0] -split '\?', 2)[0])
        $taskResolved = if ($taskPathPart) {
            [IO.Path]::GetFullPath((Join-Path (Split-Path $taskFile) $taskPathPart))
        } else { $taskFile }
        if (-not $taskResolved.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            $taskErrors.Add(('{0}: link leaves repository: {1}' -f $taskRelative, $taskTarget))
            continue
        }
        $taskRepoPath = $taskResolved.Substring($taskRoot.Length + 1).Replace('\', '/')
        if (-not $taskFiles.Contains($taskRepoPath)) {
            $taskErrors.Add(('{0}: missing or incorrectly cased file: {1}' -f $taskRelative, $taskTarget))
            continue
        }
        if ($taskParts.Count -eq 2 -and $taskParts[1] -and $taskResolved -match '\.md$') {
            $taskFragment = [Uri]::UnescapeDataString($taskParts[1])
            if (-not (Get-TaskAnchors $taskResolved).Contains($taskFragment)) {
                $taskErrors.Add(('{0}: missing heading: {1}' -f $taskRelative, $taskTarget))
            }
        }
    }
}
if ($taskErrors.Count) { throw ($taskErrors -join [Environment]::NewLine) }
Write-Host "Documentation checks passed: $taskLinkCount local links; tracked and untracked Markdown files checked."
Write-Host 'External URLs are not fetched by this check.'
