$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# CONFIG
# ============================================================

$wallpaper = "C:\Windows\Web\Wallpaper\Windows\img19.jpg"

$TaskUpdateName   = "Wallpaper Update Schedule"
$TaskPolicyName   = "Wallpaper Policy"

$BaseDir          = "C:\ProgramData\Acceleron\Wallpaper"
$WallpaperPolicy  = Join-Path $env:SystemRoot "System32\WallpaperPolicy.vbs"
$SetWallpaper     = Join-Path $env:SystemRoot "System32\SetWallpaper.vbs"

# ============================================================
# REVERT WALLPAPER SETTINGS FOR ALL USER PROFILES
# ============================================================

$userProfiles = Get-CimInstance Win32_UserProfile

foreach ($profile in $userProfiles) {

    $UserHive = "Registry::HKEY_USERS\$($profile.SID)"

    if (-not (Test-Path $UserHive)) {
        continue
    }

    $DesktopKey  = "$UserHive\Control Panel\Desktop"
    $PolicyKey   = "$UserHive\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $ActiveDesk  = "$UserHive\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"

    # Reset wallpaper
    if (Test-Path $DesktopKey) {
        Set-ItemProperty -Path $DesktopKey -Name Wallpaper -Value $wallpaper -Force
    }

    # Remove enforced policies
    Remove-ItemProperty -Path $PolicyKey  -Name Wallpaper              -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $PolicyKey  -Name WallpaperStyle         -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $PolicyKey  -Name NoDispBackgroundPage   -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $ActiveDesk -Name NoChangingWallPaper    -ErrorAction SilentlyContinue
}

# ============================================================
# REMOVE MACHINE-LEVEL WALLPAPER / LOCKSCREEN POLICIES
# ============================================================

Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" `
    -Recurse -Force -ErrorAction SilentlyContinue

Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
    -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================
# REMOVE SCHEDULED TASKS
# ============================================================

Unregister-ScheduledTask -TaskName $TaskUpdateName  -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskPolicyName  -Confirm:$false -ErrorAction SilentlyContinue

# ============================================================
# REMOVE DEPLOYED FILES
# ============================================================

Remove-Item -Path $WallpaperPolicy -Force -ErrorAction SilentlyContinue
Remove-Item -Path $SetWallpaper -Force -ErrorAction SilentlyContinue
Remove-Item $BaseDir -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================
# REFRESH GROUP POLICY
# ============================================================

gpupdate /force | Out-Null

# ============================================================
# FORCE DESKTOP REFRESH (CURRENT SESSION)
# ============================================================

$SPI_SETDESKWALLPAPER = 0x0014
$SPIF_UPDATEINIFILE  = 0x01
$SPIF_SENDCHANGE     = 0x02

if (-not ([System.Management.Automation.PSTypeName]'Wallpaper').Type) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(
        int uAction,
        int uParam,
        string lpvParam,
        int fuWinIni
    );
}
"@
}

[Wallpaper]::SystemParametersInfo(
    $SPI_SETDESKWALLPAPER,
    0,
    $wallpaper,
    $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE
) | Out-Null

Write-Host "Wallpaper policy removed and default wallpaper restored successfully."
