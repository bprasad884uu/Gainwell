try {
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Set-ExecutionPolicy Bypass -Scope Process -Force
} catch {
    # Do nothing; suppress the error
}

# Add This PC to the desktop
#$null = New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0

# Add User's Profile to the desktop
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" -Value 0

# Apply IconSize for ALL users
$UserSIDs = Get-ChildItem "Registry::HKEY_USERS" |
    Where-Object { $_.Name -match "S-1-5-21-" }  # filters real user profiles

foreach ($sid in $UserSIDs) {
    $registryPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\Shell\Bags\1\Desktop"

    # Create key if not exists
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Set small icon size
    Set-ItemProperty -Path $registryPath -Name "IconSize" -Value 32
}

# Restart explorer.exe to apply the changes
Stop-Process -Name explorer -Force
