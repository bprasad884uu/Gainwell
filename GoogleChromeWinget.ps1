# Function to check if Winget is installed and perform actions
function Check-WingetAndUpgrade {
    Write-Output "Checking if Winget is installed..."

    # Define the installation folder path for Winget
    $appInstallerPath = "C:\Program Files\WindowsApps"
    $searchPattern = "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    $installerFolder = Get-ChildItem -Path $appInstallerPath -Filter $searchPattern -ErrorAction SilentlyContinue

    if ($installerFolder) {
        # Winget installation folder found
        $wingetPath = $installerFolder.FullName
        # Check if winget executable exists in the folder
        $wingetExePath = Join-Path -Path $wingetPath -ChildPath 'winget.exe'
        
        if (Test-Path $wingetExePath) {
            Write-Output "Found winget.exe in $wingetExePath"
            
            # Check current installed version of Google Chrome
            $chromeVersion = & $wingetExePath show --id=Google.Chrome | Select-String -Pattern "Version" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }
            Write-Host "Installed Google Chrome version: $chromeVersion"
            
            # Execute the upgrade command with forced agreement
            Write-Output "Upgrading Google Chrome..."
            $upgradeResult = & $wingetExePath upgrade --id=Google.Chrome --force --silent 2>&1
            if ($upgradeResult -like "*No available upgrade found.*") {
                Write-Host "Google Chrome is up to date."
            } else {
                Write-Host "Google Chrome is updating..."
                # After update, check new installed version
                $updatedVersion = & $wingetExePath show --id=Google.Chrome | Select-String -Pattern "Version" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }
                Write-Host "Google Chrome is updated. Installed version is: $updatedVersion"
            }
        }
    } else {
        # If winget is not installed, proceed with the manual update method
        Write-Host "Winget not found. Proceeding with manual update..."

        # Set security protocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $updateUrl = "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1"

        # Function to check if Chrome is installed
        function Test-ChromeInstalled {
            try {
                $chromePath = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -Name '(default)' -ErrorAction SilentlyContinue
                return $chromePath
            } catch {
                return $null
            }
        }

        # Function to get the installed Chrome version
        function Get-ChromeVersion {
            try {
                $chromePath = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -Name '(default)' -ErrorAction SilentlyContinue
                if (Test-Path $chromePath) {
                    $versionInfo = (Get-Item $chromePath).VersionInfo
                    return $versionInfo.ProductVersion
                } else {
                    return $null
                }
            } catch {
                return $null
            }
        }

        # Main script execution
        try {
            # Check if Chrome is installed
            $chromePath = Test-ChromeInstalled
            if ($chromePath) {
                Write-Host "Chrome is installed at '$chromePath'"
                
                # Download data using Invoke-WebRequest
                $json = Invoke-RestMethod -Uri $updateUrl -ErrorAction Stop
                
                # Parse JSON response
                $chromeVersion = $json.version
                
                # Get current installed Chrome version
                $installedVersion = Get-ChromeVersion
                
                # Check if update is available
                if ($chromeVersion -ne $installedVersion) {
                    Write-Host "Update available: $chromeVersion"
                    
                    # Run update script if version mismatched
                    Write-Host "Current Version - $installedVersion"
                    
                    # Download installer
                    $Path = $env:TEMP
                    $Installer = "chrome_installer.exe"
                    $installerPath = "$Path\$Installer"
                    Write-Host "Downloading Google Chrome..."
                    
                    Invoke-WebRequest "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi" -OutFile $installerPath -ErrorAction Stop
                    
                    if (Test-Path $installerPath) {
                        Write-Host "Installing Google Chrome..."
                        Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Verb RunAs -Wait
                        Remove-Item $installerPath -ErrorAction SilentlyContinue
                    } else {
                        Write-Host "Failed to download installer."
                    }

                    # Registry management for updater
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
                    $googleKeys = Get-ChildItem -Path $regPath | Where-Object { $_.PSChildName -like "GoogleUpdaterInternalService*" }

                    if ($googleKeys) {
                        Write-Output "Found the following keys:"
                        foreach ($key in $googleKeys) {
                            $fullPath = $key.PSPath -replace "Microsoft.PowerShell.Core\\Registry::", ""
                            Write-Output $fullPath

                            $imagePath = (Get-ItemProperty -Path $key.PSPath).ImagePath

                            if ($imagePath) {
                                Write-Output "ImagePath: $imagePath"
                                Write-Output "Running ImagePath..."
                                Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$imagePath`"" -NoNewWindow -Wait
                            } else {
                                Write-Output "No ImagePath value found."
                            }
                        }
                    } else {
                        Write-Output "No keys found starting with 'GoogleUpdaterInternalService'."
                    }

                    # Configure automatic updates in the registry
                    $updateKey = 'HKLM:\SOFTWARE\Policies\Google\Update'
                    if (-not (Test-Path $updateKey)) {
                        New-Item -Path $updateKey -Force | Out-Null
                    }
                    Set-ItemProperty -Path $updateKey -Name "AutoUpdateCheckPeriodMinutes" -Value 1440 -Force
                    Set-ItemProperty -Path $updateKey -Name "UpdatesSuppressedStartHour" -Value 0 -Force
                    Set-ItemProperty -Path $updateKey -Name "UpdatesSuppressedDuration" -Value 0 -Force
                    Set-ItemProperty -Path $updateKey -Name "UpdateDefault" -Value 2 -Force

                    Write-Host "Automatic updates for Google Chrome have been enabled."

                    # Get the updated version
                    $installedVersion = Get-ChromeVersion
                    Write-Host "Updated Version - $installedVersion"
                } else {
                    Write-Host "Chrome is up to date. Installed version: $installedVersion."
                }
            } else {
                Write-Host "Google Chrome is not installed on this system."
            }
        } catch {
            Write-Host "Error: $($_.Exception.Message)"
        }
    }
}

# Main script execution
Check-WingetAndUpgrade
