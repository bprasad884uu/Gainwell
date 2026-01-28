$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# CONFIG
# ============================================================

$DefaultWallpaper = "C:\Windows\Web\Wallpaper\Windows\img19.jpg"
$SpotlightAssets  = "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\DesktopSpotlight\Assets\Images"

$IsWindows11 = ([Environment]::OSVersion.Version.Build -ge 22000)

# EXE (same directory as script)
$ScriptDir = "C:\ProgramData\Acceleron\Wallpaper"
$ExePath   = Join-Path $ScriptDir "WallpaperUpdate.exe"

# ============================================================
# PROCESS ALL USER PROFILES (HKU SAFE)
# ============================================================

$userProfiles = Get-CimInstance Win32_UserProfile

foreach ($profile in $userProfiles) {

    $UserHive = "Registry::HKEY_USERS\$($profile.SID)"
    if (-not (Test-Path $UserHive)) { continue }

    $DesktopKey = "$UserHive\Control Panel\Desktop"
    if (-not (Test-Path $DesktopKey)) { continue }

    # --------------------------------------------------------
    # REMOVE USER WALLPAPER POLICIES
    # --------------------------------------------------------
    Remove-ItemProperty "$UserHive\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name Wallpaper,WallpaperStyle,NoDispBackgroundPage `
        -ErrorAction SilentlyContinue

    Remove-ItemProperty "$UserHive\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" `
        -Name NoChangingWallPaper `
        -ErrorAction SilentlyContinue

    $cdmKey = "$UserHive\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

    # ========================================================
    # WINDOWS 10 (NO CDM)
    # ========================================================
    if (-not (Test-Path $cdmKey)) {

        Set-ItemProperty `
            -Path  $DesktopKey `
            -Name  Wallpaper `
            -Value $DefaultWallpaper `
            -Force

        continue
    }

    # ========================================================
    # WINDOWS 11 (CDM PRESENT)
    # ========================================================

    # Enable Desktop Spotlight
    $spotKey = "$UserHive\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings"
    if (-not (Test-Path $spotKey)) {
        New-Item -Path $spotKey -Force | Out-Null
    }
    Set-ItemProperty $spotKey -Name EnabledState -Type DWord -Value 1

    # CDM – values only
    Set-ItemProperty $cdmKey -Name ContentDeliveryAllowed          -Type DWord -Value 1
    Set-ItemProperty $cdmKey -Name RotatingLockScreenEnabled        -Type DWord -Value 1
    Set-ItemProperty $cdmKey -Name RotatingLockScreenOverlayEnabled -Type DWord -Value 1
    Set-ItemProperty $cdmKey -Name SubscribedContent-338389Enabled  -Type DWord -Value 1

    # Spotlight seed image (instant fallback)
    $SpotlightImage = Get-ChildItem $SpotlightAssets -Filter *.jpg -ErrorAction SilentlyContinue |
                      Select-Object -First 1

    if ($SpotlightImage) {
        Set-ItemProperty `
            -Path  $DesktopKey `
            -Name  Wallpaper `
            -Value $SpotlightImage.FullName `
            -Force
    }
    else {
        Set-ItemProperty `
            -Path  $DesktopKey `
            -Name  Wallpaper `
            -Value $DefaultWallpaper `
            -Force
    }
}

# ============================================================
# MACHINE LEVEL CLEANUP
# ============================================================

Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" `
    -Recurse -Force -ErrorAction SilentlyContinue

Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
    -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================
# REFRESH (CURRENT LOGGED-IN USER IF ANY)
# ============================================================

gpupdate /force | Out-Null
rundll32.exe user32.dll,UpdatePerUserSystemParameters

# ============================================================
# RUN WallpaperUpdate.exe AND DELETE IT
# ============================================================

if (Test-Path $ExePath) {

    try {
        Start-Process -FilePath $ExePath -Wait -WindowStyle Hidden
        Start-Sleep -Seconds 2
        Remove-Item -Path $ScriptDir -Recurse -Force
    }
    catch {
        # Silent by design
    }
}

Write-Host "Wallpaper policy removed and default wallpaper restored successfully."
