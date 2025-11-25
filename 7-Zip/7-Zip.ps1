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
        $Props = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        
        $installed = $Props.DisplayVersion
        $UninstallString = $Props.UninstallString
        
        if ($installed) {
            # Extract numeric version from values
            if ($installed -match '\d+(\.\d+){0,3}') {
                $CleanVersion = $Matches[0]

                try {
                    $InstalledVersion = [Version]$CleanVersion
                } catch {
                    Write-Host "Invalid version format detected: $installed" -ForegroundColor Red
                    $InstalledVersion = $null
                }
            }

            if ($InstalledVersion) { break }
        }
    }
}

if ($InstalledVersion) {

    Write-Host "Detected installed version: $InstalledVersion" -ForegroundColor Cyan

    if ($InstalledVersion -ge $RequiredVersion) {
        Write-Host "7-Zip is already up to date. No action required." -ForegroundColor Green
        return
    }

    Write-Host "Outdated version detected. Removing existing 7-Zip..." -ForegroundColor Yellow
    
    if ($UninstallString) {
        # Silent uninstall if possible
        Start-Process -FilePath $UninstallString -ArgumentList "/S" -Wait
        Write-Host "Uninstall completed." -ForegroundColor Green
    } else {
        Write-Host "Uninstall command not found. Cannot remove old version." -ForegroundColor Red
        return
    }

    Write-Host "Downloading latest version..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -UseBasicParsing

    Write-Host "Installing updated version..."
    Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait

    Write-Host "Update completed successfully." -ForegroundColor Green

} else {
    Write-Host "7-Zip not installed or version unreadable. Skipping installation as per rule." -ForegroundColor DarkYellow
}