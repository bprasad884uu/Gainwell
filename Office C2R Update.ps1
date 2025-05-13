# Define the path to the OfficeC2RClient.exe
$OfficeC2RClient = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"

# Check if the file exists
if (Test-Path $OfficeC2RClient) {
    # Get the current version
    $office = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*Microsoft Office*" }
    Write-Output "Current Office Version: $($office.DisplayVersion)"

    # Start the update silently
    Start-Process -FilePath $OfficeC2RClient -ArgumentList "/update user updatetoversion=16.0.11901.20218 displaylevel=False" -NoNewWindow

    # Get the updated version
    $office = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*Microsoft Office*" }
    Write-Output "Updated Office Version: $($office.DisplayVersion)"
} else {
    Write-Output "OfficeC2RClient.exe not found. Please check the path."
}
