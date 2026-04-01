# Set security protocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$updateUrl = "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1"

# Function to check if Chrome is installed (System-wide)
function Test-ChromeInstalled {
    try {
        $chromePath = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -Name '(default)' -ErrorAction SilentlyContinue
        return $chromePath
    } catch {
        return $null
    }
}

# Function to get Chrome version
function Get-ChromeVersion {
    try {
        $chromePath = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -Name '(default)' -ErrorAction SilentlyContinue
        if (Test-Path $chromePath) {
            return (Get-Item $chromePath).VersionInfo.ProductVersion
        } else {
            return $null
        }
    } catch {
        return $null
    }
}

# ================================
# Detect ALL User Profiles (C:\Users)
# ================================
$userChromeInstalled = $false

$profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin @("Public", "Default", "Default User", "All Users")
}

foreach ($profile in $profiles) {
    $userChromePath = "$($profile.FullName)\AppData\Local\Google\Chrome\Application\chrome.exe"

    if (Test-Path $userChromePath) {
        Write-Host "User-level Chrome detected for user: $($profile.Name)"
        $userChromeInstalled = $true

        $setupPath = "$($profile.FullName)\AppData\Local\Google\Chrome\Application\setup.exe"

        if (Test-Path $setupPath) {
            Write-Host "Uninstalling Chrome for user: $($profile.Name)..."
            Start-Process $setupPath -ArgumentList "--uninstall --force-uninstall" -Wait
            Write-Host "Removed Chrome for user: $($profile.Name)"
        } else {
            Write-Host "setup.exe not found for user: $($profile.Name)"
        }
    }
}

# ================================
# Main script execution
# ================================
try {
    $chromePath = Test-ChromeInstalled

    # If neither system nor user Chrome exists → exit
    if (-not $chromePath -and -not $userChromeInstalled) {
        Write-Host "`nGoogle Chrome is not installed on this system."
        return
    }

    if ($chromePath -or $userChromeInstalled) {

        if ($userChromeInstalled) {
            Write-Host "Proceeding with system-wide installation..."
        } else {
            Write-Host "Chrome is installed at '$chromePath'"
        }

        # Get latest version
        $json = Invoke-RestMethod -Uri $updateUrl -ErrorAction Stop
        $chromeVersion = $json.version

        $installedVersion = Get-ChromeVersion

        if ($chromeVersion -ne $installedVersion -or $userChromeInstalled) {

            Write-Host "`nUpdate available: $chromeVersion"
            Write-Host "Current Version - $installedVersion"

            # Download installer
            Write-Host "`nDownloading Google Chrome..."
            $downloadUrl = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
            $installerPath = "$env:TEMP\chrome_installer.msi"

            $downloadSuccess = $false

            if (-not ("System.Net.Http.HttpClient" -as [type])) {
                Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
            }

            function Format-Size {
                param ([long]$bytes)
                switch ($bytes) {
                    { $_ -ge 1MB } { "{0:N2} MB" -f ($bytes / 1MB) }
                    { $_ -ge 1KB } { "{0:N2} KB" -f ($bytes / 1KB) }
                    default { "$bytes B" }
                }
            }

            function Format-Speed {
                param ([double]$bytesPerSecond)
                switch ($bytesPerSecond) {
                    { $_ -ge 1MB } { "{0:N2} MB/s" -f ($bytesPerSecond / 1MB) }
                    { $_ -ge 1KB } { "{0:N2} KB/s" -f ($bytesPerSecond / 1KB) }
                    default { "{0:N2} B/s" -f $bytesPerSecond }
                }
            }

            $httpClient = New-Object System.Net.Http.HttpClient
            $response = $httpClient.GetAsync($downloadUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

            if ($response.StatusCode -ne 200) {
                Write-Host "Download failed."
                return
            }

            $stream = $response.Content.ReadAsStreamAsync().Result
            $totalSize = $response.Content.Headers.ContentLength

            $fileStream = [System.IO.File]::OpenWrite($installerPath)

            $buffer = New-Object byte[] (10MB)
            $downloaded = 0
            $startTime = Get-Date

            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fileStream.Write($buffer, 0, $bytesRead)
                $downloaded += $bytesRead

                $elapsed = (Get-Date) - $startTime
                $speed = $downloaded / $elapsed.TotalSeconds
                $progress = ($downloaded / $totalSize) * 100

                Write-Host "`rProgress: $([math]::Round($progress,2))% | Speed: $(Format-Speed $speed)" -NoNewline
            }

            $fileStream.Close()
            $httpClient.Dispose()

            Write-Host "`nDownload complete."

            if (Test-Path $installerPath) {
                Write-Host "`nInstalling Google Chrome..."
                Start-Process "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait
                Remove-Item $installerPath -Force
            }

            # Registry settings
            $updateKey = 'HKLM:\SOFTWARE\Policies\Google\Update'
            if (-not (Test-Path $updateKey)) {
                New-Item -Path $updateKey -Force | Out-Null
            }

            Set-ItemProperty -Path $updateKey -Name "AutoUpdateCheckPeriodMinutes" -Value 1440 -Force
            Set-ItemProperty -Path $updateKey -Name "UpdateDefault" -Value 2 -Force

            $installedVersion = Get-ChromeVersion
            Write-Host "`nUpdated Version - $installedVersion"
        }
        else {
            Write-Host "`nChrome is already up to date."
        }
    }

} catch {
    Write-Host "`nError: $($_.Exception.Message)"
}