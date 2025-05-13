# Input image and output script path
$imagePath = "D:\Bishnu_Data\Downloads\Screensaver\GCPL-EN_compressed.jpg"
$outputScript = "D:\Bishnu_Data\Downloads\Screensaver\GeneratedScript.ps1"
$finalOutputFile = "D:\Bishnu_Data\Downloads\Screensaver\GCPL-EN_compressed.txt"

# Read and encode image
$imageBytes = [System.IO.File]::ReadAllBytes($imagePath)
$base64String = [Convert]::ToBase64String($imageBytes)

# Chunking
$chunkSize = 1000
$scriptLines = @()
$chunkCount = [math]::Ceiling($base64String.Length / $chunkSize)

# Generate chunk variables as lines of script
for ($i = 0; $i -lt $chunkCount; $i++) {
    $startIndex = $i * $chunkSize
    $length = [Math]::Min($chunkSize, $base64String.Length - $startIndex)
    $chunk = $base64String.Substring($startIndex, $length)
    $line = '$chunk' + ($i + 1) + ' = "' + $chunk + '"'
    $scriptLines += $line
}

# Add merge logic
$scriptLines += "`n# Merge chunks"
$scriptLines += '$finalString = ""'
for ($i = 1; $i -le $chunkCount; $i++) {
    $scriptLines += '$finalString += $chunk' + $i
}

# Write to file
$scriptLines += "`n# Write to file"
$scriptLines += '[System.IO.File]::WriteAllText("' + $finalOutputFile + '", $finalString)'

# Save the generated script
Set-Content -Path $outputScript -Value $scriptLines -Encoding UTF8

Write-Host "PowerShell script with chunked base64 data generated at:`n$outputScript"
