$regPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk", 
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk"
)
$valueName = "DisplayIcon"
$folderName = "InstallLocation"
$AnyDeskInstalled = $false

foreach ($regPath in $regPaths) {
    # Check if the registry key exists
    if (Test-Path $regPath) {
        # Get the value of DisplayIcon
        $installationDirectory = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName
        $anydeskFolder = Get-ItemProperty -Path $regPath -Name $folderName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $folderName
        
        if ($installationDirectory) {
            $AnyDeskInstalled = $true
            Write-Output "AnyDesk is installed at: $installationDirectory"
            Write-Output "AnyDesk folder location: $anydeskFolder"

            # Run AnyDesk silent removal
            Write-Host "Removing AnyDesk...."
            Start-Process "$installationDirectory" -ArgumentList "--silent --remove" -Wait

            # Add a delay to allow uninstallation to complete
            Start-Sleep -Seconds 5

            break # Exit the loop if found
        }
    }
}

# Define possible AnyDesk installation folder paths
$possibleFolders = @("C:\Program Files (x86)\AnyDesk", "C:\Program Files\AnyDesk")
$removedFolders = @() # Array to track removed folders

# Check and remove the folders if they exist
foreach ($folder in $possibleFolders) {
    if (Test-Path $folder) {
        # Remove the folder and add it to the removedFolders array
        Remove-Item -Recurse -Force -Path $folder
        $removedFolders += $folder
    }
}

# Display the result only once per folder
if ($removedFolders.Count -gt 0) {
    foreach ($removed in $removedFolders) {
        Write-Host "AnyDesk uninstalled and folder removed at: $removed"
    }
} else {
    Write-Host "AnyDesk is not installed."
}