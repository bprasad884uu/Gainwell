<#
7-Zip version check & conditional install

- Checks 7-Zip in Uninstall registry keys.
- Reads DisplayVersion (handles values like "21.03 beta").
- If installed AND version < 25.00  -> download + silent install.
- If installed AND version >= 25.00 -> skip.
- If not installed                  -> skip (as per requirement).
#>

param(
    [string]$DownloadUrl = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/7-Zip/7-Zip-x64.exe",
    [Version]$RequiredVersion = "25.00"
)

$InstallerPath = Join-Path $env:TEMP "7-Zip-x64.exe"

Write-Host "`n=== 7-Zip Check ===" -ForegroundColor Cyan

function Get-7ZipInstalledVersion {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $rawVersion = $props.DisplayVersion

            if (-not $rawVersion) { continue }

            # Handle values like "21.03 beta" -> "21.03"
            if ($rawVersion -match '\d+(\.\d+){0,3}') {
                $numericVersion = $Matches[0]

                try {
                    return [Version]$numericVersion
                } catch {
                    Write-Host "Found 7-Zip version string '$rawVersion' but could not parse it." -ForegroundColor Yellow
                    return $null
                }
            }
        }
    }

    return $null
}

$InstalledVersion = Get-7ZipInstalledVersion

if (-not $InstalledVersion) {
    Write-Host "7-Zip not found (or version could not be read). Skipping download and installation." -ForegroundColor Yellow
    return
}

Write-Host "Detected 7-Zip version: $InstalledVersion"

if ($InstalledVersion -ge $RequiredVersion) {
    Write-Host "7-Zip already upto-date ($InstalledVersion). No installation needed." -ForegroundColor Green
    return
}

Write-Host "7-Zip is older than required ($RequiredVersion). Updating..." -ForegroundColor Yellow

# Download installer
try {
    Write-Host "Downloading installer from:`n$DownloadUrl"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -UseBasicParsing -ErrorAction Stop
    Write-Host "Download completed: $InstallerPath"
}
catch {
    Write-Host "Failed to download 7-Zip installer: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# Silent install
try {
    Write-Host "Running silent installation..."
    $proc = Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait -PassThru
    Write-Host "Installer exit code: $($proc.ExitCode)"

    Write-Host "7-Zip installation/update completed." -ForegroundColor Green
}
catch {
    Write-Host "Failed to run 7-Zip installer: $($_.Exception.Message)" -ForegroundColor Red
}
