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

# Set desktop icons to display as small icons
#$null = New-Item -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -Force
# Set the path to the registry key
$registryPath = "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop"

# Set the name of the property
$propertyName = "IconSize"

# Set the value for small icons
$propertyValue = 32

# Set the property value
Set-ItemProperty -Path $registryPath -Name $propertyName -Value $propertyValue

# Restart explorer.exe to apply the changes
Stop-Process -Name explorer -Force
