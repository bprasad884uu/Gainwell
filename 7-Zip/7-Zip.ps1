# 7-Zip Version Check and Conditional Update Script

$DownloadUrl = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/7-Zip/7-Zip-x64.exe"
$InstallerPath = "$env:TEMP\7zip_installer.exe"
$RequiredVersion = [Version]"25.00"
$InstalledVersion = $null

Write-Host "`nChecking 7-Zip Installation..." -ForegroundColor Cyan

# Updated registry paths
$Paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip"
)

foreach ($Path in $Paths) {
    if (Test-Path $Path) {
        $installed = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue)."DisplayVersion"

        if ($installed) {
            # "21.04 beta" → "21.04"
            if ($installed -match '\d+(\.\d+){0,3}') {
                $cleanVersion = $Matches[0]

                try {
                    $InstalledVersion = [Version]$cleanVersion
                } catch {
                    Write-Host "Found 7-Zip version string '$installed' (cleaned: '$cleanVersion') but could not parse it as System.Version." -ForegroundColor Yellow
                    $InstalledVersion = $null
                }
            }
            else {
                Write-Host "Found 7-Zip version string '$installed' but no numeric version could be extracted." -ForegroundColor Yellow
                $InstalledVersion = $null
            }

            if ($InstalledVersion) { break }
        }
    }
}

if ($InstalledVersion) {
    Write-Host "7-Zip Installed Version: $InstalledVersion"

    if ($InstalledVersion -ge $RequiredVersion) {
        Write-Host "7-Zip is already up to date. Skipping installation." -ForegroundColor Green
        return
    } else {
        Write-Host "Version found but outdated. Updating..." -ForegroundColor Yellow
    }

    Write-Host "Downloading latest installer..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -UseBasicParsing

    Write-Host "Installing silently..."
    Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait

    Write-Host "Update completed successfully." -ForegroundColor Green

} else {
    Write-Host "7-Zip is NOT installed or version could not be determined. Skipping download and installation as requested." -ForegroundColor DarkYellow
}
