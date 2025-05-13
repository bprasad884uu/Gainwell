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

# Function to check if chrome is installed
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
			$sourcePath = "\\10.131.76.6\Software\Google-Chrome.msi"
			$destinationPath = "$installerPath\Google-Chrome.msi"			
            #Invoke-WebRequest "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi" -OutFile $installerPath -ErrorAction Stop
            
            if (Test-Path $installerPath) {
                Write-Host "Installing Google Chrome..."
                #Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Verb RunAs -Wait
				Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$destinationPath`" /quiet /norestart" -Verb RunAs -Wait
                Remove-Item $installerPath -ErrorAction SilentlyContinue
            } else {
                Write-Host "Failed to download installer."
            }

            # Registry management
            # Define the registry path
			$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services"

			# Use Get-ChildItem to list all subkeys and filter those that start with 'GoogleUpdaterInternalService'
			$googleKeys = Get-ChildItem -Path $regPath | Where-Object { $_.PSChildName -like "GoogleUpdaterInternalService*" }

			# Output the full path of the matching keys and execute ImagePath if available
			if ($googleKeys) {
				Write-Output "Found the following keys:"
				foreach ($key in $googleKeys) {
					$fullPath = $key.PSPath -replace "Microsoft.PowerShell.Core\\Registry::", ""
					Write-Output $fullPath

					# Get the ImagePath value from the registry key
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

            # Configure automatic updates
            $updateKey = 'HKLM:\SOFTWARE\Policies\Google\Update'
            if (-not (Test-Path $updateKey)) {
                New-Item -Path $updateKey -Force | Out-Null
            }
            Set-ItemProperty -Path $updateKey -Name "AutoUpdateCheckPeriodMinutes" -Value 1440 -Force
            Set-ItemProperty -Path $updateKey -Name "UpdatesSuppressedStartHour" -Value 0 -Force
            Set-ItemProperty -Path $updateKey -Name "UpdatesSuppressedDuration" -Value 0 -Force
            Set-ItemProperty -Path $updateKey -Name "UpdateDefault" -Value 2 -Force

            Write-Host "Automatic updates for Google Chrome have been enabled."
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