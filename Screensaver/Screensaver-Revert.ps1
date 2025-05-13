# Specify the registry path
$registryPath = "Registry::HKEY_USERS"

# Get all keys under the specified path
$keys = Get-ChildItem -Path $registryPath

# Filter to include only users and exclude _Classes
$filteredKeys = $keys | Where-Object { $_.PSChildName -notlike "*_Classes" }

# Get user profiles to map SID to Username
$UserProfiles = Get-WmiObject Win32_UserProfile | Select-Object LocalPath, SID

foreach ($key in $filteredKeys) {
    $SID_Value = $key.PSChildName
    $subKey = "Registry::HKEY_USERS\$SID_Value"

    # Get corresponding username from user profile
    $UserProfile = $UserProfiles | Where-Object { $_.SID -eq $SID_Value }
    $UserName = if ($UserProfile) {
        ($UserProfile.LocalPath -split "\\")[-1] 
    } else { 
        "Unknown" 
    }

    # Check if registry path exists
    if (Test-Path $subKey) {
        try {
            # Define registry paths
            $photoViewerPath = "$subKey\Software\Microsoft\Windows Photo Viewer\Slideshow\Screensaver"
            $desktopPath = "$subKey\Control Panel\Desktop"
            $policyPath = "$subKey\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
            $policy = "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System"

            # Remove registry values
            Remove-ItemProperty -Path $desktopPath -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $desktopPath -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $desktopPath -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $desktopPath -Name "SCRNSAVE.EXE" -ErrorAction SilentlyContinue

            # Remove registry keys if they exist
            foreach ($path in @($photoViewerPath, $policyPath, $policy)) {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force
                    Write-Output "✅ Removed registry key: $path"
                } else {
                    Write-Output "ℹ️ Registry key not found: $path"
                }
            }

            Write-Output "✅ Registry settings reverted for user: $UserName"

        } catch {
            Write-Output "❌ Failed to revert settings for user: $UserName - Error: $_"
        }
    }
}

# Apply changes to user settings
RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters ,1 ,True

# Apply Group Policy
gpupdate /force 

Write-Output "✅ Screensaver settings reverted successfully for all users!"
