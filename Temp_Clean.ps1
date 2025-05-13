# This script will remove some of the unwanted files and folders from Windows 10
# It will also disable some of the tracking and advertising settings
# Use it at your own risk and discretion

# Define the cleanup settings
$StateKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
$CleanupKeys = Get-ChildItem -Path $StateKey

# Enable all cleanup options
foreach ($Key in $CleanupKeys) {
    Set-ItemProperty -Path "$StateKey\$($Key.PSChildName)" -Name "StateFlags" -Value 1
}

# Run the cleanup with the configured settings
Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1"

# Disable the telemetry and diagnostic data collection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

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

foreach ($profile in $userProfiles) {
$subKey = "Registry::HKEY_USERS\$($profile.SID)"

    if (Test-Path $subKey) {
		# Disable the targeted ads and app launch tracking
		Ensure-RegistryKey -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
		Set-ItemProperty -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0
		Ensure-RegistryKey -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
		Set-ItemProperty -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0

		# Disable the Bing search and Cortana in Windows search
		#Ensure-RegistryKey -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
		#Set-ItemProperty -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
		#Set-ItemProperty -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0

		# Disable the tips, tricks, suggestions and ads in various places
		Ensure-RegistryKey -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
		Set-ItemProperty -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
		Set-ItemProperty -Path "$subKey\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0
		}
}