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
            # Get installed Google Chrome version
            Write-Output "Retrieving installed Google Chrome version..."
            $chromeVersion = (& $wingetExePath list --name "Google Chrome" | ForEach-Object {
                if ($_ -match "^Google Chrome\s+Google\.Chrome\s+(\S+)") {
                    $matches[1]
                }
            }).Trim()

            if (-not $chromeVersion) {
                Write-Output "Google Chrome is not installed or winget could not find it."
                return
            }

            Write-Output "Installed Google Chrome version: $chromeVersion"

            # Attempt to upgrade Google Chrome
            Write-Output "Checking for updates..."
            $output = & $wingetExePath upgrade --id=Google.Chrome --force --silent 2>&1

            if ($output -match "No available upgrade found.") {
                Write-Output "Google Chrome is up to date."
            } elseif ($output -match "Starting upgrade") {
                Write-Output "Google Chrome is updating..."
                
                # Wait and check updated version
                Start-Sleep -Seconds 10
                $updatedVersion = (& $wingetExePath list --name "Google Chrome" | ForEach-Object {
                    if ($_ -match "^Google Chrome\s+Google\.Chrome\s+(\S+)") {
                        $matches[1]
                    }
                }).Trim()

                Write-Output "Google Chrome is updated and Installed version is: $updatedVersion"
            } else {
                Write-Output "An error occurred during the update process:"
                Write-Output $output
            }
        } else {
            Write-Output "Winget executable not found in $wingetPath."
            Install-Winget
        }
    } else {
        Write-Output "Winget is not installed on this system."
        Install-Winget
    }
}

# Function to install Winget if not found
function Install-Winget {
    Write-Host "Winget not found. Installing Winget..."

    $ProgressPreference = 'SilentlyContinue'
    
    # Install the NuGet provider if it's not already installed
    Write-Host "Installing NuGet provider..."
    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null

    # Install the Microsoft.WinGet.Client module from PSGallery
    Write-Host "Installing WinGet PowerShell module from PSGallery..."
    Install-Module -Name Microsoft.WinGet.Client -Force -Scope CurrentUser | Out-Null

    # Use Repair-WinGetPackageManager cmdlet to bootstrap WinGet
    Write-Host "Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet..."
    Repair-WinGetPackageManager

    Write-Host "WinGet installed successfully. Now retrying the update process..."
    
    # Retry upgrading apps after installation
    Check-WingetAndUpgrade
}

# Call the function to check Winget and upgrade Google Chrome
Check-WingetAndUpgrade
