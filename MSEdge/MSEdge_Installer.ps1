# Download and Update Microsoft Edge Silently
# Author: Bishnu's Helper

# MSI download URL and output path
$url = "https://github.com/bprasad884uu/Gainwell/releases/download/Edge/MicrosoftEdgeEnterpriseX64.msi"
$output = "$env:TEMP\MicrosoftEdgeEnterpriseX64.msi"

try {
    Write-Host "Downloading Microsoft Edge..." -ForegroundColor Cyan
    # --- Functions ---
function Format-Size {
    param ([long]$bytes)
    switch ($bytes) {
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($bytes / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($bytes / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($bytes / 1KB) }
        default        { return "$bytes B" }
    }
}

function Format-Speed {
    param ([double]$bytesPerSecond)
    switch ($bytesPerSecond) {
        { $_ -ge 1GB } { return "{0:N2} GB/s" -f ($bytesPerSecond / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB/s" -f ($bytesPerSecond / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB/s" -f ($bytesPerSecond / 1KB) }
        default        { return "{0:N2} B/s" -f $bytesPerSecond }
    }
}

# --- Download File ---
if (-not ("System.Net.Http.HttpClient" -as [type])) {
    Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
}

$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

if (-not $downloadSuccess) {
    Write-Host "`nStarting download..."

    $response = $httpClient.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

    if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
        Write-Host "`nHttpClient request failed: $($response.StatusCode) ($($response.ReasonPhrase))" -ForegroundColor Red
        exit
    }

    $stream = $response.Content.ReadAsStreamAsync().Result
    if (-not $stream) {
        Write-Host "`nFailed to retrieve response stream." -ForegroundColor Red
        exit
    }

    $totalSize = $response.Content.Headers.ContentLength
    if ($null -eq $totalSize) {
        Write-Host "`nWarning: Server did not return file size." -ForegroundColor Yellow
    }

    $fileStream = [System.IO.File]::OpenWrite($output)
    $bufferSize = 10MB
    $buffer = New-Object byte[] ($bufferSize)
    $downloaded = 0
    $startTime = Get-Date

    Write-Host "`nDownloading Edge Setup..."
    while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $fileStream.Write($buffer, 0, $bytesRead)
        $downloaded += $bytesRead
        $elapsed = (Get-Date) - $startTime
        $speed = $downloaded / $elapsed.TotalSeconds
        $progress = ($downloaded / $totalSize) * 100

        $remainingBytes = $totalSize - $downloaded
        $etaSeconds = if ($speed -gt 0) { [math]::Round($remainingBytes / $speed, 2) } else { "Calculating..." }

        if ($etaSeconds -is [double]) {
            $etaHours = [math]::Floor($etaSeconds / 3600)
            $etaMinutes = [math]::Floor(($etaSeconds % 3600) / 60)
            $etaRemainingSeconds = [math]::Floor($etaSeconds % 60)

            $etaFormatted = ""
            if ($etaHours -gt 0) { $etaFormatted += "${etaHours}h " }
            if ($etaMinutes -gt 0) { $etaFormatted += "${etaMinutes}m " }
            if ($etaRemainingSeconds -gt 0 -or $etaFormatted -eq "") { $etaFormatted += "${etaRemainingSeconds}s" }
        } else {
            $etaFormatted = "Calculating..."
        }

        Write-Host "`rTotal: $(Format-Size $totalSize) | Progress: $([math]::Round($progress,2))% | Downloaded: $(Format-Size $downloaded) | Speed: $(Format-Speed $speed) | ETA: $etaFormatted" -NoNewline
    }

    $fileStream.Close()
    Write-Host "`nDownload Complete: $output"
    $downloadSuccess = $true
    $httpClient.Dispose()
}

if (-not $downloadSuccess) {
    Write-Host "`nAll download methods failed. Please check your internet connection." -ForegroundColor Red
    exit
}

    if (Test-Path $output) {
        Write-Host "Download completed. Starting update..." -ForegroundColor Green
        
        # Run installer silently (no UI, quiet upgrade if already installed)
        Start-Process "msiexec.exe" -ArgumentList "/i `"$output`" /quiet /norestart" -Wait
        
        Write-Host "Microsoft Edge update completed successfully." -ForegroundColor Green
    }
    else {
        Write-Host "Download failed: File not found at $output" -ForegroundColor Red
    }
}
catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # Cleanup downloaded file
    if (Test-Path $output) {
        Remove-Item $output -Force
    }
}
