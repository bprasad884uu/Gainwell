# 7-Zip Version Check, Conditional Uninstall & Optional Update

$DownloadUrl     = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/7-Zip/7-Zip-x64.exe"
$InstallerPath   = "$env:TEMP\7zip_installer.exe"
$RequiredVersion = [Version]"25.00"

$InstalledVersion = $null
$UninstallString  = $null
$InstallRequired  = $false
$AllEntries       = @()

Write-Host "`nChecking 7-Zip Installation..." -ForegroundColor Cyan

# Search uninstall registry keys dynamically
$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($RegPath in $RegPaths) {
    $found = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match "7-?Zip" }

    if ($found) { $AllEntries += $found }
}

if (-not $AllEntries -or $AllEntries.Count -eq 0) {
    Write-Host "`n7-Zip not installed. Skipping install." -ForegroundColor Yellow
    return
}

# Pick first entry for version and uninstall EXE logic (your original behavior)
$item = $AllEntries | Select-Object -First 1

Write-Host "Found entry: $($item.DisplayName)"

$rawVersion      = $item.DisplayVersion
$UninstallString = $item.UninstallString

# Extract clean version number
if ($rawVersion -and $rawVersion -match '\d+(\.\d+){0,3}') {
    try { 
        $InstalledVersion = [Version]$Matches[0] 
    } catch { 
        $InstalledVersion = $null 
    }
}

if ($InstalledVersion) {
    Write-Host "`nInstalled Version: $InstalledVersion"
}

# Decide if we need to reinstall
if ($InstalledVersion -and $InstalledVersion -lt $RequiredVersion) {
    $InstallRequired = $true
    Write-Host "`nOlder version detected..." -ForegroundColor Yellow
}

# ---------------- DYNAMIC MSI GUID DETECTION ---------------- #

$MsiGuid = $null

foreach ($entry in $AllEntries) {

    # Check in UninstallString
    if ($entry.UninstallString -and $entry.UninstallString -match '\{23170F69-40C1-2702-[0-9A-F\-]+\}') {
        $MsiGuid = $Matches[0]
        break
    }

    # Check in registry key name
    if ($entry.PSChildName -and $entry.PSChildName -match '\{23170F69-40C1-2702-[0-9A-F\-]+\}') {
        $MsiGuid = $Matches[0]
        break
    }

    # Check full path
    if ($entry.PSPath -and $entry.PSPath -match '\{23170F69-40C1-2702-[0-9A-F\-]+\}') {
        $MsiGuid = $Matches[0]
        break
    }
}

# Always run MSI uninstall if GUID found
if ($MsiGuid) {
    Start-Process "msiexec.exe" -ArgumentList "/x $MsiGuid /quiet /norestart" -Wait -ErrorAction SilentlyContinue
}

# ---------------- UNINSTALL & INSTALL ONLY IF OLDER VERSION ---------------- #

if ($InstallRequired) {

    if ($UninstallString) {
        if ($UninstallString -is [array]) { $UninstallString = $UninstallString[0] }

        if ($UninstallString -match '^(\".*?\.exe\")') {
            $Exe = $Matches[1].Trim('"')
        } elseif ($UninstallString -match '^(.*?\.exe)') {
            $Exe = $Matches[1]
        } else {
            $Exe = $UninstallString
        }

        Start-Process -FilePath $Exe -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
    }

    Write-Host "`nDownloading latest 7-Zip..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -UseBasicParsing

    Write-Host "`nInstalling latest version..."
    Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait

    Write-Host "`n7-Zip updated successfully." -ForegroundColor Green
}
else {
    Write-Host "`n7-Zip is already up to date. No action required." -ForegroundColor Cyan
}
