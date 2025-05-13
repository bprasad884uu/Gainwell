# Define the registry path for Google Chrome
$chromeRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"

# Get the installed version of Google Chrome
if (Test-Path $chromeRegPath) {
    # Get the executable path from the registry
    $chromeExePath = (Get-ItemProperty -Path $chromeRegPath).'(default)'

    # Get the version information
    $chromeVersion = (Get-Item -Path $chromeExePath).VersionInfo.ProductVersion
    Write-Output "Google Chrome Version: $chromeVersion"
} else {
    Write-Output "Google Chrome is not installed."
}
