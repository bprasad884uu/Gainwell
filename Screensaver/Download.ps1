$url = "https://github.com/bprasad884uu/Gainwell/raw/e191d9db492538af6c02930d832d6890e2ef12e6/Screensaver/Company_Screensaver.ps1"
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
