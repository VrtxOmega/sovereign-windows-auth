param([string]$Destination = '')
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot
if (-not $Destination) { $Destination = Join-Path $taskRoot 'artifacts' }
$taskArtifacts = [IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path $taskArtifacts -Force | Out-Null
$taskArchive = Join-Path $taskArtifacts 'libfido2-1.17.0-win.zip'
$taskExpectedHash = '9D07F27328FC6F3D79E3E9B5EDE1C48F521D432CC62C51AC7D9F9B13B0EB428E'
if (-not (Test-Path -LiteralPath $taskArchive)) {
    Invoke-WebRequest -Uri 'https://developers.yubico.com/libfido2/Releases/libfido2-1.17.0-win.zip' -OutFile $taskArchive -TimeoutSec 120
}
if ((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash -ne $taskExpectedHash) {
    throw 'The libfido2 archive does not match the pinned hash. No files were extracted.'
}
$taskExtract = Join-Path $taskArtifacts 'libfido2'
$taskSdk = Join-Path $taskExtract 'libfido2-1.17.0-win'
if (-not (Test-Path -LiteralPath $taskExtract)) { Expand-Archive -LiteralPath $taskArchive -DestinationPath $taskExtract }
if (-not (Test-Path -LiteralPath (Join-Path $taskSdk 'include/fido.h'))) {
    throw 'SDK extraction is incomplete; inspect the dependency directory before retrying.'
}
$taskRuntime = Join-Path $taskSdk 'Win64/Release/v143/dynamic'
$taskHashes = @{
    'fido2.dll' = '574782AD7C08DC311076D1393B9A4C7D4B0A7FC5AAF868BECE28E456C38A8553'
    'crypto-56.dll' = 'B886F4C14FA6DE6580F14827E12831993632D3A6C2063979F190241B8F3819F8'
    'cbor.dll' = 'B47FAB97BB8E67743712752DB9739E6401A50D8793B807A45418E559CC4E3D31'
    'zlib1.dll' = '05DF848DB4A8AD29E915B629EE621E39F5AC672FE306EAE3F4B50F99DEEC47DC'
}
foreach ($taskName in $taskHashes.Keys) {
    $taskPath = Join-Path $taskRuntime $taskName
    if ((Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash -ne $taskHashes[$taskName]) { throw "Dependency hash mismatch: $taskName" }
    $taskSignature = Get-AuthenticodeSignature -LiteralPath $taskPath
    if ($taskSignature.Status -ne 'Valid' -or $taskSignature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Yubico AB(,|$)') {
        throw "Yubico signature did not validate: $taskName"
    }
}
Write-Host 'Pinned SDK and all four signed runtime dependencies verified.'
