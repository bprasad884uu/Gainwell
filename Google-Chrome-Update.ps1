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
            Write-Host "`nUpdate available: $chromeVersion"
            
			# Run update script if version mismatched
            Write-Host "Current Version - $installedVersion"
            # Download installer
            Write-Host "`nDownloading Google Chrome..."
            $downloadUrl = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
			$installerPath = "$env:TEMP\chrome_installer.msi"

			$downloadSuccess = $false
			# Load System.Net.Http.dll for PowerShell 5.1
			if (-not ("System.Net.Http.HttpClient" -as [type])) {
				Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
			}

			#Function Part
			function Format-Size {
				param ([long]$bytes)
				switch ($bytes) {
					{ $_ -ge 1MB } { return "{0:N2} MB" -f ($bytes / 1MB) }
					{ $_ -ge 1KB } { return "{0:N2} KB" -f ($bytes / 1KB) }
					default        { return "$bytes B" }
				}
			}

			function Format-Speed {
				param ([double]$bytesPerSecond)
				switch ($bytesPerSecond) {
					{ $_ -ge 1MB } { return "{0:N2} MB/s" -f ($bytesPerSecond / 1MB) }
					{ $_ -ge 1KB } { return "{0:N2} KB/s" -f ($bytesPerSecond / 1KB) }
					default        { return "{0:N2} B/s" -f $bytesPerSecond }
				}
			}

			# Create HttpClient Instance
			$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
			$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

			if (-not $downloadSuccess) {
				Write-Host "`nStarting download..."

				# Send GET Request
				$response = $httpClient.GetAsync($downloadUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

				# Validate Response
				if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
					Write-Host "`nHttpClient request failed: $($response.StatusCode) ($($response.ReasonPhrase))" -ForegroundColor Red
					exit
				}

				# Get Content Stream
				$stream = $response.Content.ReadAsStreamAsync().Result
				if (-not $stream) {
					Write-Host "`nFailed to retrieve response stream." -ForegroundColor Red
					exit
				}

				# Get File Size
				$totalSize = $response.Content.Headers.ContentLength
				if ($null -eq $totalSize) {
					Write-Host "`nWarning: File size unknown. Assuming large file to prevent errors." -ForegroundColor Yellow
					$totalSize = 1024 * 1024 * 1024
				}

				# Open Output File
				$fileStream = [System.IO.File]::OpenWrite($installerPath)
				
				# Set Large Buffer for Fast Download
				$bufferSize = 10MB
				$buffer = New-Object byte[] ($bufferSize)
				$downloaded = 0
				$startTime = Get-Date

				Write-Host "`nDownloading Google Chrome..."
				while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
					$fileStream.Write($buffer, 0, $bytesRead)
					$downloaded += $bytesRead
					$elapsed = (Get-Date) - $startTime
					
					# Calculate Speed
					$speed = $downloaded / $elapsed.TotalSeconds
					
					# Calculate Progress (%)
					$progress = ($downloaded / $totalSize) * 100
				
					# ETA Calculation
					$remainingBytes = $totalSize - $downloaded
					$etaSeconds = if ($speed -gt 0) { [math]::Round($remainingBytes / $speed, 2) } else { "Calculating..." }

					if ($etaSeconds -is [double]) {
						$etaHours = [math]::Floor($etaSeconds / 3600)
						$etaMinutes = [math]::Floor(($etaSeconds % 3600) / 60)
						$etaRemainingSeconds = [math]::Floor($etaSeconds % 60)

						$etaFormatted = ""
						if ($etaHours -gt 0) { $etaFormatted += "${etaHours}h " }
						if ($etaMinutes -gt 0) { $etaFormatted += "${etaMinutes}m " }
						if ($etaRemainingSeconds -gt 0 -or $etaFormatted -eq "") { $etaFormatted += "${etaRemainingSeconds}s" }
					} else {
						$etaFormatted = "Calculating..."
					}

					Write-Host "`rTotal: $(Format-Size $totalSize) | Progress: $([math]::Round($progress,2))% | Downloaded: $([math]::Round($downloaded / 1MB, 2)) MB | Speed: $(Format-Speed $speed) | ETA: $etaFormatted" -NoNewline
				}

				# Close Streams
				$fileStream.Close()
				Write-Host "`nDownload Complete: $destination"
				$downloadSuccess = $true
				$httpClient.Dispose()
			}

			if (-not $downloadSuccess) {
				Write-Host "`nAll download methods failed. Please check your internet connection." -ForegroundColor Red
				exit
			}

            if (Test-Path $installerPath) {
                Write-Host "`nInstalling Google Chrome..."
                Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Verb RunAs -Wait
                Remove-Item $installerPath -ErrorAction SilentlyContinue
            } else {
                Write-Host "`nFailed to download installer."
            }

            # Registry management
            # Define the registry path
			$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services"

			# Use Get-ChildItem to list all subkeys and filter those that start with 'GoogleUpdaterInternalService'
			$googleKeys = Get-ChildItem -Path $regPath | Where-Object { $_.PSChildName -like "GoogleUpdaterInternalService*" }

			# Output the full path of the matching keys and execute ImagePath if available
			if ($googleKeys) {
				Write-Output "`nFound the following keys:"
				foreach ($key in $googleKeys) {
					$fullPath = $key.PSPath -replace "Microsoft.PowerShell.Core\\Registry::", ""
					Write-Output $fullPath

					# Get the ImagePath value from the registry key
					$imagePath = (Get-ItemProperty -Path $key.PSPath).ImagePath

					if ($imagePath) {
						Write-Output "`nImagePath: $imagePath"
						
						Write-Output "`nRunning ImagePath..."
							Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$imagePath`"" -NoNewWindow -Wait
					} else {
						Write-Output "`nNo ImagePath value found."
					}
				}
			} else {
				Write-Output "`nNo keys found starting with 'GoogleUpdaterInternalService'."
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

            Write-Host "`nAutomatic updates for Google Chrome have been enabled."
            $installedVersion = Get-ChromeVersion
            Write-Host "`nUpdated Version - $installedVersion"
        } else {
            Write-Host "`nChrome is up to date. Installed version: $installedVersion."
        }
    } else {
        Write-Host "`nGoogle Chrome is not installed on this system."
    }
} catch {
    Write-Host "`nError: $($_.Exception.Message)"
}