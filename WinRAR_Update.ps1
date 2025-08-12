# Update-WinRAR.ps1
# Auto-updates WinRAR only if installed and older than latest version

[CmdletBinding()]
param (
    [string]$TempInstaller = "$env:TEMP\winrar-update.exe"
)

function Get-WinRARInfo {
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($key in $keys) {
        $inst = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "WinRAR*" }
        if ($inst) {
            $arch = if ($inst.InstallLocation -and ($inst.InstallLocation -match "Program Files \(x86\)")) {
                "x86"
            } else {
                "x64"
            }
            return [PSCustomObject]@{
                InstallLocation = $inst.InstallLocation
                DisplayVersion  = $inst.DisplayVersion
                Architecture    = $arch
            }
        }
    }
    return $null
}

function Get-LatestWinRAR {
    Write-Host "Fetching latest WinRAR version info..." -ForegroundColor Cyan
    try {
        $page = Invoke-WebRequest -Uri "https://www.win-rar.com/download.html?&L=0" -UseBasicParsing
    } catch {
        Write-Error "Failed to fetch WinRAR download page: $_"
        return $null
    }

    # Match latest version number
    $match = [regex]::Match($page.Content, "WinRAR\s+(\d+\.\d+)")
    if (-not $match.Success) {
        Write-Error "Could not find latest version number on page."
        return $null
    }
    $versionString = $match.Groups[1].Value

    # Find the first direct .exe link
    $exeLink = ($page.Links | Where-Object { $_.href -match "\.exe$" } | Select-Object -First 1).href
    if (-not $exeLink) {
        Write-Error "Could not locate .exe download link on page."
        return $null
    }

    # Fix: If relative link, prepend full domain
    if ($exeLink -notmatch "^https?://") {
        $exeLink = "https://www.win-rar.com$exeLink"
    }

    return [PSCustomObject]@{
        Version = $versionString
        Url     = $exeLink
    }
}

# --- Main script ---
Write-Host "Checking if WinRAR is installed..." -ForegroundColor Cyan
$winrar = Get-WinRARInfo

if (-not $winrar) {
    Write-Host "WinRAR is not installed. No update performed." -ForegroundColor Yellow
    return
}

Write-Host "Installed version: $($winrar.DisplayVersion)" -ForegroundColor Green
Write-Host "Architecture: $($winrar.Architecture)" -ForegroundColor Green

$latest = Get-LatestWinRAR
if (-not $latest) { return }

Write-Host "Latest version available: $($latest.Version)" -ForegroundColor Cyan

if ([version]$winrar.DisplayVersion -ge [version]$latest.Version) {
    Write-Host "WinRAR is already up-to-date (v$($winrar.DisplayVersion)). No update needed." -ForegroundColor Yellow
    return
}

Write-Host "Downloading update from: $($latest.Url)" -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $latest.Url -OutFile $TempInstaller -UseBasicParsing
} catch {
    Write-Error "Failed to download installer: $_"
    return
}

Write-Host "Installing update silently..." -ForegroundColor Cyan
$process = Start-Process -FilePath $TempInstaller -ArgumentList "/S" -Wait -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "WinRAR updated successfully to version $($latest.Version)!" -ForegroundColor Green
} else {
    Write-Error "Installer exited with code $($process.ExitCode)."
}

Remove-Item $TempInstaller -Force -ErrorAction SilentlyContinue