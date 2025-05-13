# Ensure the script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit
}

# Function to update graphics drivers using Windows Update
function Update-GraphicsDriver {
    Write-Output "Searching for graphics devices..."

    # Get the list of graphics devices
    $graphicsDevices = Get-WmiObject Win32_VideoController

    if ($graphicsDevices.Count -eq 0) {
        Write-Error "No graphics devices found on this system."
        return
    }

    foreach ($device in $graphicsDevices) {
        Write-Output "Graphics Device Found: $($device.Description) ($($device.DriverVersion))"
    }

    # Access Windows Update session
    Write-Output "Searching for updates via Windows Update..."
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()

    try {
        # Search only for driver updates
        $searchResult = $updateSearcher.Search("Type='Driver'")
        Write-Output "Total driver updates found: $($searchResult.Updates.Count)"

        if ($searchResult.Updates.Count -eq 0) {
            Write-Output "No driver updates found."
            return
        }

        # Filter for graphics-related updates
        $graphicsUpdates = $searchResult.Updates | Where-Object {
            $_.Title -like "*graphics*" -or $_.Title -like "*display*"
        }

        if ($graphicsUpdates.Count -eq 0) {
            Write-Output "No graphics driver updates found."
            return
        }

        Write-Output "The following graphics driver updates are available:"
        foreach ($update in $graphicsUpdates) {
            Write-Output $update.Title
        }

        # Install updates
        Write-Output "Downloading and installing graphics driver updates..."
        foreach ($update in $graphicsUpdates) {
            $updateInstaller = $updateSession.CreateUpdateInstaller()
            $updateInstaller.Updates = New-Object -ComObject Microsoft.Update.UpdateColl
            $updateInstaller.Updates.Add($update)
            $installationResult = $updateInstaller.Install()

            if ($installationResult.ResultCode -eq 2) {
                Write-Output "Successfully installed: $($update.Title)"
            } else {
                Write-Error "Failed to install: $($update.Title)"
            }
        }

        Write-Output "Graphics driver update completed. A restart may be required."

    } catch {
        Write-Error "An error occurred while searching for updates: $_"
    }
}

# Call the function
Update-GraphicsDriver
