try {
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Set-ExecutionPolicy Bypass -Scope Process -Force
} catch {
    # Do nothing; suppress the error
}

# Automatically set the folder to the same location as the script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$driverFolder = $scriptDir

# Function to list all devices with missing drivers
Function Get-MissingDrivers {
    Write-Host "Listing devices with missing drivers..." -ForegroundColor Yellow
    # Using PnPUtil to get device information
    $devices = Get-PnpDevice | Where-Object { $_.Status -eq 'Error' }

    if ($devices) {
        Write-Host "`nMissing drivers found for the following devices:`n" -ForegroundColor Cyan
        $devices | Format-Table -Property Name, DeviceID, Status, Class
    } else {
        Write-Host "No missing drivers found!" -ForegroundColor Green
    }

    return $devices
}

# Function to install drivers for missing devices from the folder
Function Install-MissingDrivers {
    param (
        [string]$DriverPath,
        [array]$MissingDevices
    )
    Write-Host "`nInstalling missing drivers from: $DriverPath" -ForegroundColor Yellow

    # Get all INF files in the driver folder
    $infFiles = Get-ChildItem -Path $DriverPath -Recurse -Include *.inf

    if ($infFiles) {
        foreach ($device in $MissingDevices) {
            $deviceName = $device.Name
            $deviceId = $device.DeviceID

            # Check for a driver file that matches the device
            $matchingDriver = $infFiles | Where-Object { $_.FullName -like "*$deviceId*" }

            if ($matchingDriver) {
                foreach ($driver in $matchingDriver) {
                    Write-Host "`nInstalling driver for: $deviceName" -ForegroundColor Cyan
                    # Use PnPUtil to add drivers to the driver store and install
                    pnputil /add-driver $driver.FullName /install | Out-Null
                    
                    # Custom message indicating the driver was installed
                    if ($deviceName -like "*Wi-Fi*") {
                        Write-Host "Driver installed: Wi-Fi" -ForegroundColor Green
                    } elseif ($deviceName -like "*Display*" -or $device.Class -eq "Display") {
                        Write-Host "Driver installed: Display" -ForegroundColor Green
                    } else {
                        Write-Host "Driver installed: $deviceName" -ForegroundColor Green
                    }
                }
            } else {
                Write-Host "No matching driver found for: $deviceName ($deviceId)" -ForegroundColor Red
            }
        }
        Write-Host "`nDriver installation completed!" -ForegroundColor Green
    } else {
        Write-Host "No drivers found in the specified folder!" -ForegroundColor Red
    }
}

# Main logic
$missingDevices = Get-MissingDrivers

if ($missingDevices) {
    Install-MissingDrivers -DriverPath $driverFolder -MissingDevices $missingDevices
} else {
    Write-Host "`nNo missing drivers to install." -ForegroundColor Green
}
