# Set the path to the wallpaper image
$wallpaper = "C:\Windows\web\Wallpaper\Windows\wallpaper.jpg"

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

# Set the wallpaper for each user profile that exists
foreach ($profile in $userProfiles) {
    $subKey = "Registry::\HKEY_USERS\$($profile.SID)"

    # Check if the registry path exists before setting values
    if (Test-Path $subKey) {
        # Ensure registry keys exist
        $null = Ensure-RegistryKey -Path "$subKey\Control Panel\Desktop"
        $null = Ensure-RegistryKey -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $null = Ensure-RegistryKey -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"

        # Set wallpaper values
        Set-ItemProperty -Path "$subKey\Control Panel\Desktop" -Name Wallpaper -Value $wallpaper -Force
        Set-ItemProperty -Path "$subKey\Control Panel\Desktop" -Name WallpaperStyle -Value 2 -Force
        Set-ItemProperty -Path "$subKey\Control Panel\Desktop" -Name TileWallpaper -Value 0 -Force
        Set-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name Wallpaper -Value $wallpaper -Force
        Set-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name WallpaperStyle -Value 2 -Force
        Set-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name NoDispBackgroundPage -Value 1 -Force
        Set-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name NoChangingWallPaper -Value 1 -Force
    }
}

# Prevent users from changing the wallpaper for the current user
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $wallpaper -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -Value 2 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -Value 0 -Force

# Prevent users from changing the wallpaper for All User
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name Wallpaper -Value $wallpaper -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name WallpaperStyle -Value 2 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name NoDispBackgroundPage -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name NoChangingWallPaper -Value 1 -Force

# Create registry path if it doesn't exist
$null = Ensure-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"

# Set wallpaper for all users on the machine
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name Wallpaper -Value $wallpaper -Force


# Define the SystemParametersInfo constants
$SPI_SETDESKWALLPAPER = 0x0014
$SPIF_UPDATEINIFILE = 0x01
$SPIF_SENDCHANGE = 0x02

# Load the Wallpaper class with SystemParametersInfo
Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class Wallpaper {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    }
"@

# Function to set the wallpaper for a user profile
function Set-WallpaperForUser {
    param (
        [string]$userSID,
        [string]$wallpaper
    )

    # Set the wallpaper for the user profile
    [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $wallpaper, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
}

# Get all user profiles on the system
$userProfiles = Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false }

# Set the wallpaper for each user profile
foreach ($profile in $userProfiles) {
    $userSID = $profile.LocalPath.Split("\")[-1]
    $null = Set-WallpaperForUser -userSID $userSID -wallpaperPath $wallpaper
}
