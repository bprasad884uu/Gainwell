# Paths
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

# Run link generator and capture output
$output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $LinkGenScript 2>&1

# Extract links
# Extract EN-GB
$matchENGB = $output | Select-String '\$isoUrl_EN_GB\s*=\s*"([^"]+)"'
$enGB = if ($matchENGB) { $matchENGB.Matches[0].Groups[1].Value } else { "" }

# Extract EN-US
$matchENUS = $output | Select-String '\$isoUrl_EN_US\s*=\s*"([^"]+)"'
$enUS = if ($matchENUS) { $matchENUS.Matches[0].Groups[1].Value } else { "" }

# -------------------------
# Validation
# -------------------------
function Test-ValidHttpsUrl {
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    if ($Url -notmatch '^https://') { return $false }
    return $true
}

$enGB_Valid = Test-ValidHttpsUrl $enGB
$enUS_Valid = Test-ValidHttpsUrl $enUS

$updated = $false
$content = Get-Content $UpgradeScript -Raw

if ($enGB_Valid) {
    $content = $content -replace '\$isoUrl_EN_GB\s*=\s*".*"', "`$isoUrl_EN_GB  = `"$enGB`""
    Write-Host "Updating ISO link for: EN-GB"
    $updated = $true
}

if ($enUS_Valid) {
    $content = $content -replace '\$isoUrl_EN_US\s*=\s*".*"', "`$isoUrl_EN_US  = `"$enUS`""
    Write-Host "Updating ISO link for: EN-US"
    $updated = $true
}

if ($updated) {
    #IMPORTANT: remove extra trailing newlines
    $content = $content.TrimEnd("`r", "`n")

    Set-Content -Path $UpgradeScript -Value $content -Encoding UTF8
    Write-Host "Link updated successfully."
    exit 0
}

Write-Warning "No valid HTTPS ISO links detected. Update skipped."
exit 0