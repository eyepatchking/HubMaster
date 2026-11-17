param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$Thumbprint
)
$ErrorActionPreference = 'Stop'
$certificate = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $Thumbprint)
if (-not $certificate.HasPrivateKey) { throw 'Certificate has no private key' }
$result = Set-AuthenticodeSignature -LiteralPath $Target -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.digicert.com'
if ($result.Status -ne 'Valid') { throw ("Signing failed: " + $result.StatusMessage) }
Write-Output $result
