# Set the path to the Windows and lockscreen default wallpaper
$wallpaper= "C:\Windows\Web\Wallpaper\Windows\img0.jpg"

# Revert Wallpaper changes for User Profiles
$userProfiles = Get-CimInstance Win32_UserProfile

foreach ($profile in $userProfiles) {
    $subKey = "Registry::\HKEY_USERS\$($profile.SID)"
    
    if (Test-Path $subKey) {
        $desktopPath = "$subKey\Control Panel\Desktop"
        
        # Reset registry values
			Set-ItemProperty -Path "$desktopPath" -Name Wallpaper -Value $wallpaper -Force
            Remove-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name Wallpaper -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name WallpaperStyle -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name NoDispBackgroundPage -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name NoChangingWallPaper -ErrorAction SilentlyContinue
    }
}

# Revert changes for All Users
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Recurse -ErrorAction SilentlyContinue

# Revert Lock Screen policy changes
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force -ErrorAction SilentlyContinue

# Delete task schedulers
$taskName = "Wallpaper Update Schedule"
$taskNamePolicy = "Wallpaper Policy"

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskNamePolicy -Confirm:$false -ErrorAction SilentlyContinue

# Delete files from system32 directory
$WallpaperPolicy = Join-Path $env:SystemRoot "System32\WallpaperPolicy.vbs"
$SetWallpaper = Join-Path $env:SystemRoot "System32\SetWallpaper.vbs"

Remove-Item -Path $WallpaperPolicy -Force -ErrorAction SilentlyContinue
Remove-Item -Path $SetWallpaper -Force -ErrorAction SilentlyContinue

# Refresh the group policy
gpupdate /force

# Refresh the desktop to apply changes
# Check if the type 'Wallpaper' already exists
if (-not ([System.Management.Automation.PSTypeName]'Wallpaper').Type) {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class Wallpaper {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    }
"@
}

# Default wallpaper path
$SPI_SETDESKWALLPAPER = 0x0014
$UpdateIniFile = 0x01
$SendChangeEvent = 0x02

# Set the desktop wallpaper
$null = [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $wallpaper, $UpdateIniFile -bor $SendChangeEvent)

Write-Host "Wallpaper Policy removed from all user profiles and set default wallpaper and lockscreen."