# Define the base path for the Microsoft Desktop App Installer
$basePath = "C:\Program Files\WindowsApps"

# Get the latest version of the Microsoft.DesktopAppInstaller folder with the specified suffix
$latestFolder = Get-ChildItem $basePath | Where-Object { $_.Name -like "Microsoft.DesktopAppInstaller_*x64__8wekyb3d8bbwe" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Check if a folder was found
if ($latestFolder) {
    # Change to the latest folder
    Set-Location $latestFolder.FullName
    Write-Host "Changed directory to: $($latestFolder.FullName)"
    
    # Update using Winget, automatically accepting all prompts
    Write-Host "Updating using Winget..."
    .\winget upgrade --all --accept-source-agreements --accept-package-agreements
} else {
    Write-Host "No Microsoft.DesktopAppInstaller folder with the specified suffix found."
}
