<#
.SYNOPSIS
  Produce Certificate Observation Records from the Windows certificate store
  (draft-barcelo-opsawg-cert-observation), evidence "observed-store".

.DESCRIPTION
  Reads certificates from one or more certificate store paths (default
  Cert:\LocalMachine\My), builds a cert-observation-set and optionally writes
  it atomically to a file and/or pushes it to a collector.

  -UseDefaultCredentials authenticates the push with the computer's or user's
  Kerberos credentials (HTTP Negotiate), which suits Active Directory
  environments without distributing tokens.

.EXAMPLE
  .\Get-CertObservation.ps1
.EXAMPLE
  .\Get-CertObservation.ps1 -StorePath Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting -OutFile C:\ProgramData\cor\host.cor.json
.EXAMPLE
  .\Get-CertObservation.ps1 -PushUri https://collector.example.net/cor -UseDefaultCredentials
#>
[CmdletBinding()]
param(
    [string[]] $StorePath = @('Cert:\LocalMachine\My'),
    [string]   $Reporter  = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName),
    [int]      $ValidFor  = 3600,
    [switch]   $IncludeExpired,
    [switch]   $Minimise,
    [string]   $OutFile,
    [string]   $PushUri,
    [string]   $Token,
    [switch]   $UseDefaultCredentials
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$MediaType = 'application/cert-observation+json'

function ConvertTo-Rfc3339([datetime] $d) {
    $d.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
}

function Get-Sha256Hex([byte[]] $bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}

function Get-KeyInfo([System.Security.Cryptography.X509Certificates.X509Certificate2] $c) {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c)
    if ($rsa) { return @{ alg = 'RSA'; size = $rsa.KeySize } }
    $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($c)
    if ($ecdsa) { return @{ alg = "ECDSA"; size = $ecdsa.KeySize } }
    return @{ alg = $c.PublicKey.Oid.Value; size = $null }
}

function Get-SanList([System.Security.Cryptography.X509Certificates.X509Certificate2] $c) {
    # DnsNameList is added by the PowerShell certificate provider.
    $names = @()
    if ($c.PSObject.Properties['DnsNameList'] -and $c.DnsNameList) {
        $names += $c.DnsNameList | ForEach-Object { $_.Unicode }
    }
    $names | Select-Object -Unique
}

function Test-Chain([System.Security.Cryptography.X509Certificates.X509Certificate2] $c) {
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    try {
        $ok = $chain.Build($c)
        $fps = @($chain.ChainElements | Select-Object -Skip 1 | ForEach-Object { Get-Sha256Hex $_.Certificate.RawData })
        $anchor = if ($chain.ChainElements.Count -gt 0) {
            $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject } else { $null }
        return @{ ok = $ok; fps = $fps; anchor = $anchor }
    } finally { $chain.Dispose() }
}

$now = Get-Date
$records = foreach ($path in $StorePath) {
    foreach ($c in Get-ChildItem -Path $path | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }) {
        if (-not $IncludeExpired -and $c.NotAfter -lt $now) { continue }

        $key = Get-KeyInfo $c
        $cert = [ordered]@{ sha256 = (Get-Sha256Hex $c.RawData) }
        if (-not $Minimise) {
            $cert['subject-dn'] = $c.SubjectName.Format($false)
            $san = @(Get-SanList $c)
            if ($san.Count -gt 0) { $cert['san'] = $san }
        }
        $cert['issuer-dn']            = $c.IssuerName.Format($false)
        $cert['serial']               = $c.SerialNumber.ToLowerInvariant().TrimStart('0')
        $cert['not-before']           = ConvertTo-Rfc3339 $c.NotBefore
        $cert['not-after']            = ConvertTo-Rfc3339 $c.NotAfter
        $cert['public-key-algorithm'] = $key.alg
        if ($key.size) { $cert['public-key-size'] = $key.size }
        $cert['signature-algorithm']  = $c.SignatureAlgorithm.FriendlyName

        $chainResult = Test-Chain $c
        $chain = [ordered]@{ validation = $(if ($chainResult.ok) { 'valid' } else { 'invalid' }) }
        if ($chainResult.fps.Count -gt 0) { $chain['certificates'] = $chainResult.fps }
        if ($chainResult.anchor) { $chain['trust-anchor'] = $chainResult.anchor }

        $status = @()
        if ($c.NotAfter -lt $now)  { $status += 'expired' }
        if ($c.NotBefore -gt $now) { $status += 'not-yet-valid' }
        if (-not $chainResult.ok)  { $status += 'chain-invalid' }

        $rec = [ordered]@{
            version       = 1
            'record-id'   = [guid]::NewGuid().ToString()
            reporter      = $Reporter
            subject       = [ordered]@{ host = $Reporter }
            location      = [ordered]@{ store = ($path -replace '^Cert:\\', ''); label = $c.Thumbprint }
            evidence      = 'observed-store'
            'observed-at' = ConvertTo-Rfc3339 $now
            'valid-for'   = $ValidFor
            certificate   = $cert
            chain         = $chain
        }
        if ($status.Count -gt 0) { $rec['status'] = $status }
        $rec
    }
}

$set  = [ordered]@{ version = 1; records = @($records) }
$json = $set | ConvertTo-Json -Depth 8

if ($OutFile) {
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $tmp = Join-Path $dir (".cor-" + [guid]::NewGuid().ToString('N') + '.tmp')
    [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
    Move-Item -Force -Path $tmp -Destination $OutFile
}

if ($PushUri) {
    $params = @{ Uri = $PushUri; Method = 'Post'; ContentType = $MediaType; Body = $json }
    if ($Token)                 { $params['Headers'] = @{ Authorization = "Bearer $Token" } }
    if ($UseDefaultCredentials) { $params['UseDefaultCredentials'] = $true }
    Invoke-RestMethod @params | Out-Null
    Write-Verbose "pushed $(@($records).Count) record(s) to $PushUri"
}

$json
