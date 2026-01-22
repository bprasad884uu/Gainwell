# Set variables
$fidoUrl = "https://github.com/pbatard/Fido/raw/refs/heads/master/Fido.ps1"
$fidoPath = "$env:TEMP\Fido.ps1"

# Download Fido.ps1 using HttpClient
Add-Type -AssemblyName System.Net.Http
$client = [System.Net.Http.HttpClient]::new()
$response = $client.GetAsync($fidoUrl).Result
if ($response.IsSuccessStatusCode) {
    [System.IO.File]::WriteAllText($fidoPath, $response.Content.ReadAsStringAsync().Result)
    Write-Host "Fido.ps1 downloaded successfully to $fidoPath"
} else {
    Write-Host "Failed to download Fido.ps1. Status Code: $($response.StatusCode)" -ForegroundColor Red
    exit 1
}

# ---------------------------------
# Header
# ---------------------------------
$version = "25H2"

Write-Host "Windows 11, $version Download Link:"
Write-Host "--------------------------------------------------------------"

# -------------------------------
# English US
# -------------------------------
$output = powershell.exe -NoProfile -Command `
    "& '$fidoPath' -Win 11 -Rel Latest -Ed Pro -Arch x64 -GetUrl -Lang English" |
    Where-Object { $_ -match '^https?://' }

$url = $output | Select-Object -First 1
if (-not $url) { $url = "" }

Write-Host "`$isoUrl_EN_US  = `"$url`""

# -------------------------------
# English UK (International)
# -------------------------------
$output = powershell.exe -NoProfile -Command `
    "& '$fidoPath' -Win 11 -Rel Latest -Ed Pro -Arch x64 -GetUrl -Lang 'English International'" |
    Where-Object { $_ -match '^https?://' }

$url = $output | Select-Object -First 1
if (-not $url) { $url = "" }

Write-Host "`$isoUrl_EN_GB  = `"$url`""