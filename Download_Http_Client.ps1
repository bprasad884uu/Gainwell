powershell
# Ensure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define URL and output path
$url    = "https://raw.githubusercontent.com/bprasad884uu/Gainwell/refs/heads/main/Screensaver/Company_Screensaver.ps1"
$output = Join-Path $env:TEMP "Script.ps1"

# Remove if it already exists
if (Test-Path $output) {
    Remove-Item $output -Force -ErrorAction SilentlyContinue
}

# Load HttpClient assembly (needed in Windows PowerShell 5.1)
Add-Type -AssemblyName "System.Net.Http"

function Format-Size {
    param([double]$bytes)
    if ($bytes -lt 1KB) { return ("{0} B" -f [math]::Round($bytes,0)) }
    if ($bytes -lt 1MB) { return ("{0:N2} KB" -f ($bytes/1KB)) }
    if ($bytes -lt 1GB) { return ("{0:N2} MB" -f ($bytes/1MB)) }
    return ("{0:N2} GB" -f ($bytes/1GB))
}

function Format-Speed {
    param([double]$bps)
    if ($bps -lt 1KB) { return ("{0} B/s" -f [math]::Round($bps,0)) }
    if ($bps -lt 1MB) { return ("{0:N2} KB/s" -f ($bps/1KB)) }
    return ("{0:N2} MB/s" -f ($bps/1MB))
}

function Format-Remaining {
    param([double]$seconds)
    if ($seconds -lt 0 -or [double]::IsInfinity($seconds) -or [double]::IsNaN($seconds)) { return "Unknown" }
    $ts = [TimeSpan]::FromSeconds([math]::Round($seconds))
    if ($ts.TotalHours -ge 1) {
        return ("{0}h {1}m {2}s" -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds)
    } elseif ($ts.TotalMinutes -ge 1) {
        return ("{0}m {1}s" -f $ts.Minutes, $ts.Seconds)
    } else {
        return ("{0}s" -f $ts.Seconds)
    }
}

$httpClient = [System.Net.Http.HttpClient]::new()
try {
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $url)
    $response = $httpClient.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

    if (-not $response.IsSuccessStatusCode) {
        throw "Download failed with status code: $($response.StatusCode)"
    }

    $totalBytes = $response.Content.Headers.ContentLength
    $stream = $response.Content.ReadAsStreamAsync().Result
    $fileStream = [System.IO.File]::OpenWrite($output)
    $fileStream.SetLength(0)

    $bufferSize = 81920
    $buffer = New-Object byte[] $bufferSize
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $totalRead = 0L

    while ($true) {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { break }

        $fileStream.Write($buffer, 0, $read)
        $totalRead += $read

        # Speed & ETA
        $elapsed = $sw.Elapsed.TotalSeconds
        if ($elapsed -le 0) { $elapsed = 0.0001 }
        $speed = $totalRead / $elapsed

        if ($totalBytes) {
            $remainingBytes = $totalBytes - $totalRead
            $etaSeconds = if ($speed -gt 0) { $remainingBytes / $speed } else { -1 }
            $percent = [math]::Floor(($totalRead * 100) / $totalBytes)
        } else {
            $etaSeconds = -1
            $percent = 0
        }

        # Format output
        $totalStr = if ($totalBytes) { Format-Size $totalBytes } else { "Unknown" }
        $downloadedStr = Format-Size $totalRead
        $speedStr = Format-Speed $speed
        $etaStr = Format-Remaining $etaSeconds

        $line = "Total Size: $totalStr | Download: $downloadedStr | Speed: $speedStr | ETA: $etaStr | Percentage: $percent%"

        Write-Host -NoNewline "`r$line"
    }

    Write-Host "`nDownload complete. Saved to: $output`n"
    $sw.Stop()

    $fileStream.Close()
    $stream.Close()

    # Run the script
    Invoke-Expression (Get-Content -Path $output -Raw)

} catch {
    Write-Error "Failed: $_"
} finally {
    if ($fileStream) { $fileStream.Dispose() }
    if ($stream) { $stream.Dispose() }
    if ($response) { $response.Dispose() }
    $httpClient.Dispose()
    if (Test-Path $output) { Remove-Item $output -Force -Recurse -ErrorAction SilentlyContinue }
}
