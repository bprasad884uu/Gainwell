# Function to check if Winget is installed and perform actions
function Check-WingetAndUpgrade {
    Write-Output "Checking if Winget is installed..."
    $appInstallerPath = "C:\Program Files\WindowsApps"
    $searchPattern = "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    $installerFolder = Get-ChildItem -Path $appInstallerPath -Filter $searchPattern -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($installerFolder) {
        $wingetExePath = Join-Path -Path $installerFolder.FullName -ChildPath 'winget.exe'
        if (Test-Path $wingetExePath) {
            Write-Output "Winget found. Fetching upgradable packages..."
            try {
                $rawOutput = & $wingetExePath upgrade --accept-source-agreements 2>$null

                $headerLine = $rawOutput | Where-Object { $_ -match "\bId\b" } | Select-Object -First 1
                $idIndex = $headerLine.IndexOf("Id")

                $upgradeList = $rawOutput | Where-Object {
                    $_ -notmatch "^\s*$" -and
                    $_ -notmatch "^-+$" -and
                    $_ -notmatch "^Name" -and
                    $_ -notmatch "upgrades available" -and
                    $_ -notmatch "Copyright" -and
                    $_ -notmatch "Windows Package"
                }

                $packagesToUpgrade = foreach ($line in $upgradeList) {
                    if ($line.Length -gt $idIndex) {
                        $rest = $line.Substring($idIndex).Trim()
                        $packageId = ($rest -split '\s+')[0]
                        if ($packageId -match "\." -and $packageId -notmatch "java|jdk|jre|temurin|adoptium" -and $packageId.Length -gt 3) {
                            $packageId
                        }
                    }
                }

                if ($packagesToUpgrade) {
                    Write-Output "Upgrading $($packagesToUpgrade.Count) packages (Java excluded)..."
                    foreach ($pkg in $packagesToUpgrade) {
                        Write-Output "Upgrading: $pkg"
                        & $wingetExePath upgrade --id $pkg --accept-source-agreements --accept-package-agreements --silent
                    }
                    Write-Output "Upgrade completed successfully!"
                } else {
                    Write-Output "No packages to upgrade (or all were Java packages)."
                }

            } catch {
                Write-Output "Failed to upgrade apps. Error: $_"
            }
        } else {
            Write-Output "Winget executable not found in the folder."
            Install-Winget
        }
    } else {
        Write-Output "Winget installation folder not found."
        Install-Winget
    }
}

# Function to install Winget if not found
function Install-Winget {
    Write-Host "Winget not found. Installing Winget..." -ForegroundColor Yellow
    $progressPreference = 'SilentlyContinue'
    $downloadUrl = "https://aka.ms/getwinget"
    $outputPath = "$env:USERPROFILE\Downloads\AppInstaller.msixbundle"
    Write-Host "Downloading App Installer from $downloadUrl..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath -ErrorAction Stop
        Write-Host "Download completed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to download App Installer. Error: $_" -ForegroundColor Red
        exit
    }
    Write-Host "Installing App Installer..." -ForegroundColor Yellow
    try {
        Add-AppxPackage -Path $outputPath -ErrorAction Stop
        Write-Host "App Installer installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to install App Installer. Error: $_" -ForegroundColor Red
        exit
    }
    Write-Host "Verifying installation of Winget..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Winget is successfully installed and ready to use!" -ForegroundColor Green
    } else {
        Write-Host "Winget installation failed or is not recognized in the PATH." -ForegroundColor Red
        exit
    }
    Write-Host "Cleaning up downloaded file..." -ForegroundColor Yellow
    Remove-Item -Path $outputPath -Force -ErrorAction SilentlyContinue
    Write-Host "Retrying upgrade process now that Winget is installed..."
    Check-WingetAndUpgrade
}

# Call the function
Check-WingetAndUpgrade