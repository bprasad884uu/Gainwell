# Update-WindowsApps.ps1
# Script to update all installed Windows apps for all users, ignoring errors for missing AppxManifest.xml

# Function to update all installed Windows apps
function Update-AllWindowsApps {
    try {
        # Get all installed app packages
        $appPackages = Get-AppxPackage -AllUsers

        # Check if there are any packages to update
        if ($appPackages) {
            foreach ($package in $appPackages) {
                # Ensure InstallLocation is not null or empty
                if (![string]::IsNullOrEmpty($package.InstallLocation)) {
                    # Define the path to the AppxManifest.xml
                    $appxManifestPath = Join-Path -Path $package.InstallLocation -ChildPath 'AppxManifest.xml'
                    
                    # Check if the AppxManifest.xml exists
                    if (Test-Path $appxManifestPath) {
                        try {
                            Write-Host "Updating app: $($package.Name)"
                            Add-AppxPackage -DisableDevelopmentMode -Register $appxManifestPath -ErrorAction Stop
                        } catch {
                            Write-Host "Error updating $($package.Name): $_"
                        }
                    } else {
                        Write-Host "Warning: AppxManifest.xml not found for $($package.Name) at $appxManifestPath. Skipping..."
                    }
                } else {
                    Write-Host "Warning: InstallLocation is null or empty for $($package.Name). Skipping..."
                }
            }
            Write-Host "All apps have been processed."
        } else {
            Write-Host "No installed apps found."
        }
    } catch {
        Write-Host "An error occurred: $_"
    }
}

# Call the function to update all Windows apps
Update-AllWindowsApps
