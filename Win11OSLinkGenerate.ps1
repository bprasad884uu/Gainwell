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

# Loop through both languages
foreach ($lang in $languages) {
    Write-Host "`nDownload Link for language: $lang" -ForegroundColor Cyan
    $argsWithLang = $commonArgs + ("-Lang", $lang)
    
    $downloadOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fidoPath @argsWithLang

    if ($downloadOutput) {
        Write-Host "`n$lang ISO Info:"
        $downloadOutput | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "Failed to retrieve download info for $lang." -ForegroundColor Red
    }
}
