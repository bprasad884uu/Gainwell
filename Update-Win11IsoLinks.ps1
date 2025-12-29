param(
    [switch]$DebugMode
)

# -------------------------------------------------
# Paths
# -------------------------------------------------
$LinkGenScript = ".\Win11OSLinkGenerate.ps1"
$UpgradeScript = ".\Windows11Upgrade.ps1"

if (!(Test-Path $LinkGenScript)) {
    Write-Error "Win11OSLinkGenerate.ps1 not found"
    exit 1
}

if (!(Test-Path $UpgradeScript)) {
    Write-Error "Windows11Upgrade.ps1 not found"
    exit 1
}

Write-Host "[INFO] Running link generator..." -ForegroundColor Cyan

# -------------------------------------------------
# Run generator and capture output
# -------------------------------------------------
$output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $LinkGenScript 2>&1

if ($DebugMode) {
    Write-Host "`n[DEBUG] Raw generator output:" -ForegroundColor Yellow
    $output | ForEach-Object { Write-Host $_ }
}

# -------------------------------------------------
# FIX: Join output to handle wrapped URLs
# -------------------------------------------------
$joinedOutput = ($output -join "`n")

# -------------------------------------------------
# Extract links (normalize whitespace)
# -------------------------------------------------
if ($joinedOutput -match '\$isoUrl_EN_GB\s*=\s*"([^"]+)"') {
    $enGB = ($matches[1] -replace '\s+', '')
} else {
    $enGB = ""
}

if ($joinedOutput -match '\$isoUrl_EN_US\s*=\s*"([^"]+)"') {
    $enUS = ($matches[1] -replace '\s+', '')
} else {
    $enUS = ""
}

if ($DebugMode) {
    Write-Host "`n[DEBUG] Extracted values:" -ForegroundColor Yellow
    Write-Host "EN-GB Raw: $enGB"
    Write-Host "EN-US Raw: $enUS"
}

# -------------------------------------------------
# Validation
# -------------------------------------------------
function Test-ValidHttpsUrl {
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    if ($Url -notmatch '^https://') { return $false }
    return $true
}

$enGB_Valid = Test-ValidHttpsUrl $enGB
$enUS_Valid = Test-ValidHttpsUrl $enUS

if ($DebugMode) {
    Write-Host "`n[DEBUG] Validation status:" -ForegroundColor Yellow
    Write-Host "EN-GB Valid: $enGB_Valid"
    Write-Host "EN-US Valid: $enUS_Valid"
}

# -------------------------------------------------
# Update Windows11Upgrade.ps1 (partial-safe)
# -------------------------------------------------
$updated = $false
$content = Get-Content $UpgradeScript -Raw

if ($enGB_Valid) {
    $content = $content -replace '\$isoUrl_EN_GB\s*=\s*"[^"]*"', "`$isoUrl_EN_GB  = `"$enGB`""
    Write-Host "Updating ISO link for: EN-GB"
    $updated = $true
}

if ($enUS_Valid) {
    $content = $content -replace '\$isoUrl_EN_US\s*=\s*"[^"]*"', "`$isoUrl_EN_US  = `"$enUS`""
    Write-Host "Updating ISO link for: EN-US"
    $updated = $true
}

if ($updated) {
    # IMPORTANT: prevent extra blank line / formatting drift
    $content = $content.TrimEnd("`r", "`n")

    Set-Content -Path $UpgradeScript -Value $content -Encoding UTF8
    Write-Host "Link updated successfully."
    exit 0
}

Write-Warning "No valid HTTPS ISO links detected. Update skipped."
exit 0
