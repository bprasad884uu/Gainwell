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

                # Find the header line
                $headerLineIndex = ($rawOutput | Select-String "^Name\s+Id\s+").LineNumber - 1

                if ($headerLineIndex -ge 0) {
                    $headerLine = $rawOutput[$headerLineIndex]
                    $idIndex = $headerLine.IndexOf("Id")

                    # Skip header and separator lines, get only data lines
                    $dataLines = $rawOutput | Select-Object -Skip ($headerLineIndex + 2)

                    # Build upgrade list excluding Java packages
                    $packagesToUpgrade = foreach ($line in $dataLines) {
                        if ($line -match "^\s*$" -or $line -match "upgrades available") { continue }
                        if ($line.Length -gt $idIndex) {
                            $rest = $line.Substring($idIndex).Trim()
                            $packageId = ($rest -split '\s+')[0]
                            if ($packageId -match "\." -and
                                $packageId -notmatch "java|jdk|jre|temurin|adoptium" -and
                                $packageId.Length -gt 3) {
                                $packageId
                            }
                        }
                    }

                    if ($packagesToUpgrade) {
                        # Display table with Java rows removed
                        Write-Output ""
                        Write-Output "Packages to be upgraded (Java excluded):"
                        Write-Output $rawOutput[$headerLineIndex]        # Header row
                        Write-Output $rawOutput[$headerLineIndex + 1]    # Separator row

                        foreach ($line in $dataLines) {
                            if ($line -match "^\s*$" -or $line -match "upgrades available") { continue }
                            if ($line.Length -gt $idIndex) {
                                $rest = $line.Substring($idIndex).Trim()
                                $packageId = ($rest -split '\s+')[0]
                                if ($packageId -match "\." -and
                                    $packageId -notmatch "java|jdk|jre|temurin|adoptium" -and
                                    $packageId.Length -gt 3) {
                                    Write-Output $line
                                }
                            }
                        }

                        Write-Output ""
                        Write-Output "Upgrading $($packagesToUpgrade.Count) packages..."

                        # Upgrade each package individually
                        foreach ($pkg in $packagesToUpgrade) {
                            Write-Output ""
                            Write-Output "--- Upgrading: $pkg ---"
                            & $wingetExePath upgrade --id $pkg --accept-source-agreements --accept-package-agreements --silent
                        }

                        Write-Output ""
                        Write-Output "Upgrade completed successfully!"
                    } else {
                        Write-Output "No packages to upgrade."
                    }
                } else {
                    Write-Output "Could not parse winget output."
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