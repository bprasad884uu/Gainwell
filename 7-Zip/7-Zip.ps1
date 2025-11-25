# 7-Zip found -> uninstall + reinstall

$DownloadUrl   = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/7-Zip/7-Zip-x64.msi"
$InstallerPath = "$env:TEMP\7zip_latest.msi"

Write-Host "`nChecking 7-Zip installation..." -ForegroundColor Cyan

$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$AllEntries = @()

foreach ($path in $RegPaths) {
    $found = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "7-?Zip" }

    if ($found) { $AllEntries += $found }
}

if ($AllEntries.Count -eq 0) {
    Write-Host "`n7-Zip not installed. Skipping..." -ForegroundColor Yellow
    return
}

# ---------- Show ALL found versions in output ----------

Write-Host ""
foreach ($entry in $AllEntries) {
    $verOut = "Unknown"

    if ($entry.DisplayVersion -and $entry.DisplayVersion -match '\d+(\.\d+){0,3}') {
        try {
            $v = [Version]$Matches[0]
            $verOut = $v.ToString()
        } catch {
            $verOut = $entry.DisplayVersion
        }
    }

    Write-Host "7-Zip Found : $($entry.DisplayName)  ->  $verOut"
}

# ---------- For uninstall, use ONLY first entry's UninstallString ----------

$first          = $AllEntries | Select-Object -First 1
$UninstallString = $first.UninstallString

# ---------------- DETECT UNINSTALL METHODS ----------------

$MsiGuids = @()
$UninstallExecutables = @()

foreach ($entry in $AllEntries) {

    # Collect uninstall EXE if available
    if ($entry.UninstallString) {
        $str = $entry.UninstallString

        # Extract EXE path if present
        if ($str -match '\"(.*?\.exe)\"') {
            $UninstallExecutables += $Matches[1]
        }
    }

    # Detect MSI GUID from UninstallString, registry key name or entry path
    foreach ($source in @($entry.UninstallString, $entry.PSChildName, $entry.PSPath)) {
        if ($source -and $source -match '\{23170F69-40C1-2702-[0-9A-F\-]+\}') {
            $guid = $Matches[0]
            if ($guid -and $MsiGuids -notcontains $guid) { $MsiGuids += $guid }
        }
    }
}

# ---------------- RUN UNINSTALL ----------------

if ($UninstallExecutables.Count -gt 0) {
    foreach ($exe in $UninstallExecutables | Select-Object -Unique) {
        Start-Process $exe -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
    }
}

if ($MsiGuids.Count -gt 0) {
    foreach ($guid in $MsiGuids) {
        Start-Process "msiexec.exe" -ArgumentList "/x $guid /quiet /norestart" -Wait
    }
}

# ---------------- INSTALL NEW VERSION ----------------

Write-Host "`nDownloading latest 7-Zip..."
Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -UseBasicParsing

Write-Host "Installing latest 7-Zip..."
Start-Process "msiexec.exe" -ArgumentList "/i `"$InstallerPath`" /quiet /norestart" -Wait

Write-Host "`n7-Zip installation completed successfully." -ForegroundColor Green
