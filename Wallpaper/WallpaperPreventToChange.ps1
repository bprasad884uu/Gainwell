# Set the path to the wallpaper image
$wallpaper = "C:\Windows\Web\Wallpaper\Windows\Wallpaper.jpg"
$binaryValue = [System.Text.Encoding]::Unicode.GetBytes($wallpaper)
# Get all user profiles using CIMInstance
$userProfiles = Get-CimInstance Win32_UserProfile

# Function to create registry key if it doesn't exist
function Ensure-RegistryKey {
    param (
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force
    }
}

# Set wallpaper for each user profile that exists
foreach ($profile in $userProfiles) {
    $subKey = "Registry::\HKEY_USERS\$($profile.SID)"

    # Check if the registry path exists before setting values
    if (Test-Path $subKey) {
        $desktopPath = "$subKey\Control Panel\Desktop"
        
        # Check if the Wallpaper value exists in the registry
        $wallpaperExists = Get-ItemProperty -Path $desktopPath -Name Wallpaper -ErrorAction SilentlyContinue

        if ($null -eq $wallpaperExists) {
            # Ensure registry keys exist
            Ensure-RegistryKey -Path "$desktopPath"
            Ensure-RegistryKey -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            Ensure-RegistryKey -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"

            # Set wallpaper values
            Set-ItemProperty -Path "$desktopPath" -Name Wallpaper -Value $wallpaper -Force
            Set-ItemProperty -Path "$desktopPath" -Name WallpaperStyle -Value 2 -Force
            Set-ItemProperty -Path "$desktopPath" -Name TileWallpaper -Value 0 -Force
			Set-ItemProperty -Path "$desktopPath" -Name TranscodedImageCount -Value 1 -Force
			Set-ItemProperty -Path "$desktopPath" -Name TranscodedImageCache -Value $binaryValue -Type Binary -Force
            Set-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name Wallpaper -Value $wallpaper -Force
            Set-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name WallpaperStyle -Value 2 -Force
            Set-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name NoDispBackgroundPage -Value 1 -Force
            Set-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name NoChangingWallPaper -Value 1 -Force
        }
    }
}

# Prevent users from changing the wallpaper for the current user
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'TranscodedImageCache' -Value $binaryValue -Type Binary -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $wallpaper -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -Value 2 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -Value 0 -Force

# Prevent users from changing the wallpaper for All User
Ensure-RegistryKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
Ensure-RegistryKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name Wallpaper -Value $wallpaper -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name WallpaperStyle -Value 2 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name NoDispBackgroundPage -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name NoChangingWallPaper -Value 1 -Force

# Create registry path if it doesn't exist
Ensure-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"

# Set wallpaper for all users on the machine
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name Wallpaper -Value $wallpaper -Force


