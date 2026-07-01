# Azure Trusted Signing script for Tauri signCommand
# Called by Tauri with: powershell -File sign-windows.ps1 <file-to-sign>
# Requires env vars: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$FileToSign
)

$ErrorActionPreference = "Stop"

# Skip signing if Azure credentials are not set (local dev builds)
if (-not $env:AZURE_CLIENT_ID -or -not $env:AZURE_TENANT_ID -or -not $env:AZURE_CLIENT_SECRET) {
    Write-Host "SKIP signing (no Azure credentials): $FileToSign"
    exit 0
}

# Find signtool
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    Write-Error "signtool.exe not found at $signtool"
    exit 1
}

# Find dlib (NuGet-installed in .signing/ or CI_PROJECT_DIR\.signing\)
$searchPaths = @(
    "$PSScriptRoot\..\.signing",
    "$env:CI_PROJECT_DIR\.signing",
    "C:\Program Files\ArtifactSigningClientTools"
)

$dlib = $null
foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        $found = Get-ChildItem -Path $searchPath -Recurse -Filter "Azure.CodeSigning.Dlib.dll" | 
            Where-Object { $_.DirectoryName -like "*x64*" } | 
            Select-Object -First 1 -ExpandProperty FullName
        if ($found) { $dlib = $found; break }
    }
}

if (-not $dlib) {
    Write-Error "Azure.CodeSigning.Dlib.dll not found"
    exit 1
}

# Create or reuse metadata.json
$metadataPath = "$env:TEMP\hpn-signing-metadata.json"
if (-not (Test-Path $metadataPath)) {
    $metadataContent = @"
{
  "Endpoint": "https://weu.codesigning.azure.net",
  "CodeSigningAccountName": "hmsx-signing",
  "CertificateProfileName": "hpn-release",
  "ExcludeCredentials": [
    "ManagedIdentityCredential",
    "WorkloadIdentityCredential",
    "SharedTokenCacheCredential",
    "VisualStudioCredential",
    "VisualStudioCodeCredential",
    "AzurePowerShellCredential",
    "AzureDeveloperCliCredential",
    "InteractiveBrowserCredential"
  ]
}
"@
    [System.IO.File]::WriteAllText($metadataPath, $metadataContent, [System.Text.UTF8Encoding]::new($false))
}

# Retry with exponential backoff + fallback timestamp servers.
# Microsoft's ACS timestamp server occasionally returns transient errors
# ("could not be reached or returned an invalid response") even when the
# Azure-side code signing succeeded. signtool then reports the whole
# operation as failed because the RFC3161 timestamp couldn't be attached.
# Cycling through alternate timestamp servers (DigiCert, Sectigo,
# GlobalSign) lets a single provider outage NOT take down the build.
$timestampServers = @(
    "http://timestamp.acs.microsoft.com",
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1"
)
$maxAttempts = 5
for ($i = 1; $i -le $maxAttempts; $i++) {
    $tsServer = $timestampServers[($i - 1) % $timestampServers.Length]
    Write-Host "Signing attempt $i/$maxAttempts using timestamp server: $tsServer"
    Write-Host "Signing: $FileToSign"
    & "$signtool" sign /v /fd SHA256 /tr "$tsServer" /td SHA256 /dlib "$dlib" /dmdf "$metadataPath" "$FileToSign"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Signed successfully on attempt ${i}: $FileToSign"
        exit 0
    }
    if ($i -lt $maxAttempts) {
        $backoff = [math]::Min(60, [math]::Pow(2, $i))
        Write-Host "Sign attempt $i failed (exit $LASTEXITCODE). Backing off $backoff s before retry."
        Start-Sleep -Seconds $backoff
    }
}
Write-Error "Signing failed for $FileToSign after $maxAttempts attempts across $($timestampServers.Length) timestamp servers"
exit 1
