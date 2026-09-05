$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'artifacts'
$Host.UI.RawUI.WindowTitle = 'Sovereign - install verified Windows key sign-in'
try {
    & (Join-Path $PSScriptRoot 'install-provider.ps1') 2>&1 | Tee-Object -FilePath (Join-Path $taskArtifacts 'provider-install.log')
} catch {
    @{phase='installation_stopped'; error=$_.Exception.Message; time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskArtifacts 'provider-install-state.json')
    Write-Host $_.Exception.Message
}
Read-Host 'Press Enter to close this helper'
