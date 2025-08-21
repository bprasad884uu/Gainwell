[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$url = <Script_URL>
$output = "$env:Temp\Script.ps1"

# Remove if it already exists
if (Test-Path $output) {
    Remove-Item $output -Force
}

# Download the script
Invoke-WebRequest -Uri $url -OutFile $output

# Execute the script
& $output

# Delete after execution
if (Test-Path $output) { Remove-Item $output -Force -Recurse }

