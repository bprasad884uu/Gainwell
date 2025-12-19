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

# Define common download options
$commonArgs = @(
    "-Win", "11",
    "-Rel", "Latest",
    "-Ed", "Pro",
    "-Arch", "x64",
    "-GetUrl"
)

# Define both language variants
$languages = @("English International" , "English")

# ---------------------------------
# Header
# ---------------------------------
$version = "25H2"

Write-Host "Windows 11, $version Download Link:"
Write-Host "--------------------------------------------------------------"

# ---------------------------------
# Loop with REQUIRED output
# ---------------------------------
foreach ($lang in $languages) {

    Write-Host ""
    Write-Host "Download Link for language: $lang"

    $argsWithLang = $commonArgs + ("-Lang", $lang)

    $output = powershell.exe `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File $fidoPath `
        @argsWithLang

    $url = $output | Where-Object { $_ -match '^https?://' } | Select-Object -First 1

    if ($lang -eq "English International") {
        Write-Host "`$isoUrl_EN_GB  = `"$url`""
    }
    else {
        Write-Host "`$isoUrl_EN_US  = `"$url`""
    }
}