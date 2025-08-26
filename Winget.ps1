# Check if any process starting with "Forti" is running
$fcProcesses = Get-Process -Name "Forti*" -ErrorAction SilentlyContinue

if ($fcProcesses) {
    Write-Host "FortiClient is running. Closing it..."
    foreach ($proc in $fcProcesses) {
        try {
            Stop-Process -Id $proc.Id -Force
        } catch {
            Write-Warning "Failed to stop process $($proc.Name) (PID: $($proc.Id))"
        }
    }
    Start-Sleep -Seconds 3  # Give it a moment to close completely
    Write-Host "FortiClient closed."
} else {
    Write-Host "FortiClient is not running."
}

# Function to check if Winget is installed and perform actions
function Check-WingetAndUpgrade {
    Write-Output "Checking if Winget is installed..."

    # Define the installation folder path for Winget
    $appInstallerPath = "C:\Program Files\WindowsApps"
    $searchPattern = "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    $installerFolder = Get-ChildItem -Path $appInstallerPath -Filter $searchPattern -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($installerFolder) {
        # Winget installation folder found
        $wingetExePath = Join-Path -Path $installerFolder.FullName -ChildPath 'winget.exe'

        if (Test-Path $wingetExePath) {
            Write-Output "Winget found. Upgrading apps..."
            try {
                & $wingetExePath upgrade --all --accept-source-agreements --accept-package-agreements --silent
                Write-Output "Upgrade completed successfully!"
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

    # Define the download URL and destination path
    $downloadUrl = "https://aka.ms/getwinget"
    $outputPath = "$env:USERPROFILE\Downloads\AppInstaller.msixbundle"

    # Download the App Installer package
    Write-Host "Downloading App Installer from $downloadUrl..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath -ErrorAction Stop
        Write-Host "Download completed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to download App Installer. Error: $_" -ForegroundColor Red
        exit
    }

    # Install the App Installer package
    Write-Host "Installing App Installer..." -ForegroundColor Yellow
    try {
        Add-AppxPackage -Path $outputPath -ErrorAction Stop
        Write-Host "App Installer installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to install App Installer. Error: $_" -ForegroundColor Red
        exit
    }

    # Verify installation
    Write-Host "Verifying installation of Winget..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Winget is successfully installed and ready to use!" -ForegroundColor Green
    } else {
        Write-Host "Winget installation failed or is not recognized in the PATH." -ForegroundColor Red
        exit
    }

    # Cleanup
    Write-Host "Cleaning up downloaded file..." -ForegroundColor Yellow
    Remove-Item -Path $outputPath -Force -ErrorAction SilentlyContinue

    # Retry upgrading apps after installation
    Write-Host "Retrying upgrade process now that Winget is installed..."
    Check-WingetAndUpgrade
}

# Call the function
Check-WingetAndUpgrade
