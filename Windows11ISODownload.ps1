# Download both Win11 24H2 ISOs (EN-GB and EN-US) into D:\WINOS
# Run as Administrator for Mount-DiskImage verification.

# Ensure destination folder exists
$targetFolder = "F:\OS\RAW"
if (-not (Test-Path $targetFolder)) {
    New-Item -ItemType Directory -Path $targetFolder | Out-Null
}

# List of ISOs to download
$isos = @(
    @{
        Locale = "en-GB"
        Url    = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_EnglishInternational_x64.iso?t=6a1a0fe6-3811-4547-90d6-eb8b9f480fb0&P1=1759599900&P2=601&P3=2&P4=KP9R2Hki4lvfivX3WTulRZbMaBCCXNHbzgfHvP87pcoRzcf2Er7Z9A3%2fZzXE%2bO1m0S5oaPVM4I%2bhgU1z5ImwHNS%2bWXiyEVEL36kmt3S6UoHXvl6j%2f5VlUHMeFa3KN92b66Jj9sXrJDC0D6xvtS1mPYmV6KuqB70XR6%2be%2fKKXv87cKpQx1zYzqxJJrP2CQ3OrNKDxLZv9XI1DscOLl8qCFjpFUni1YlNbJPTXk42mAjmLwqhMy2auEyy6s1t1YBApf5Bj1WtIox6QFCCs7B2PxcV0yhLU3RuZConeLSPEacB5bDqTqXvP%2fc%2bgom1GJ2FFuw8bGNLDSac3GgdyQQSJwQ%3d%3d"
        File   = Join-Path $targetFolder "Win11_25H2_ENGB.iso"
    },
    @{
        Locale = "en-US"
        Url    = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_English_x64.iso?t=49bc1e21-229a-4d13-938f-ce1228bd0221&P1=1759599910&P2=601&P3=2&P4=ZM1EGR90ndsJZfuuMiywYiGiXTCvHy3%2bMkgs60YFUzCFjU9KVsGUiKqn9wPzew8VqIrwCClHlCbUsX4kS2r4ENoeR1nowxq08LHheK4YCVJDhYL5wsonsylK3%2bpQ9aNAZgigZ3WRtOW1M%2bw8S4ZHVrDF0tGb4BAH6QNIx4Sal8Q8a%2fjHktvntqkCQ%2fb4cl3DNp9e6TkWtqMGsJ3fuRafgzSJTWpBaTJxTVs2AFk5tIYCjbOgSQmw%2fy45BRlIlkOIRSRnnFfXsRmAnshrGBNd1XvZvIvlZsmZZUZ2S6n%2bYuwYf55FVZeWRnrlwCb6KM39sxotRB9V4%2btn5JD1%2f7wbJQ%3d%3d"
        File   = Join-Path $targetFolder "Win11_25H2_ENUS.iso"
    }
)

# Helper functions
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

# Ensure HttpClient assembly available
if (-not ("System.Net.Http.HttpClient" -as [type])) {
    Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
}

# Main loop: process each ISO entry
foreach ($iso in $isos) {
    $locale = $iso.Locale
    $isoUrl = $iso.Url
    $destination = $iso.File

    Write-Host "`n===== Processing $locale -> $destination =====`n"

    $downloadSuccess = $false
    $fileStream = $null

    # If file exists, try mounting it to confirm integrity
    if (Test-Path $destination) {
        Write-Host "File already exists: $destination"
        Write-Host "Attempting to mount to verify integrity..."

        try {
            $mount = Mount-DiskImage -ImagePath $destination -ErrorAction Stop
            Start-Sleep -Seconds 1
            $null = Dismount-DiskImage -ImagePath $destination -ErrorAction SilentlyContinue
            Write-Host "Mount successful. Skipping download for $locale."
            $downloadSuccess = $true
        } catch {
            Write-Warning "Existing ISO failed to mount or is corrupted. Removing and re-downloading..."
            try { Remove-Item -Path $destination -Force -ErrorAction Stop } catch { Write-Warning "Failed to remove existing file: $_" }
        }
    }

    if (-not $downloadSuccess) {
        Write-Host "Starting download for $locale..."

        $httpClientHandler = New-Object System.Net.Http.HttpClientHandler
        $httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

        try {
            $response = $httpClient.GetAsync($isoUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                Write-Host "HttpClient request failed: $($response.StatusCode) ($($response.ReasonPhrase))" -ForegroundColor Red
                continue
            }

            $stream = $response.Content.ReadAsStreamAsync().Result
            if (-not $stream) {
                Write-Host "Failed to retrieve response stream." -ForegroundColor Red
                continue
            }

            # Use Int64 to store size safely
            $totalSizeObj = $response.Content.Headers.ContentLength
            if ($null -eq $totalSizeObj) {
                Write-Host "Warning: Content-Length unknown. Progress will be approximate." -ForegroundColor Yellow
                # set big number for progress math so percentage won't divide by zero
                $totalSize = [int64](1024 * 1024 * 1024)
            } else {
                $totalSize = [int64]$totalSizeObj
            }

            # Create/overwrite file
            $fileStream = [System.IO.File]::Create($destination)

            $bufferSize = 10 * 1024 * 1024   # 10 MB buffer
            $buffer = New-Object byte[] ($bufferSize)
            $downloaded = [int64]0
            $startTime = Get-Date

            Write-Host "Downloading Windows 11 ISO ($locale)..."
            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fileStream.Write($buffer, 0, $bytesRead)
                $downloaded += [int64]$bytesRead
                $elapsed = (Get-Date) - $startTime
                $speed = if ($elapsed.TotalSeconds -gt 0) { $downloaded / $elapsed.TotalSeconds } else { 0.0 }
                $progress = if ($totalSize -gt 0) { ($downloaded / $totalSize) * 100 } else { 0.0 }

                # safe remaining bytes calculation using Int64
                $remainingBytes = $totalSize - $downloaded
                if ($remainingBytes -lt 0) { $remainingBytes = 0 }

                $etaSeconds = if ($speed -gt 0) { [math]::Round($remainingBytes / $speed, 2) } else { $null }

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

                Write-Host ("`rTotal: {0} | Progress: {1:N2}% | Downloaded: {2} | Speed: {3} | ETA: {4}" -f `
                    (Format-Size $totalSize), $progress, (Format-Size $downloaded), (Format-Speed $speed), $etaFormatted) -NoNewline
            }

            $fileStream.Close()
            $stream.Close()

            Write-Host "`nDownload complete: $destination"

            # Verify by attempting to mount
            try {
                $null = Mount-DiskImage -ImagePath $destination -ErrorAction Stop
                Start-Sleep -Seconds 1
                $null = Dismount-DiskImage -ImagePath $destination -ErrorAction SilentlyContinue
                Write-Host "Post-download mount verification succeeded for $locale."
                $downloadSuccess = $true
            } catch {
                Write-Warning "Downloaded file failed to mount. It may be corrupted. Deleting file."
                try { Remove-Item -Path $destination -Force -ErrorAction Stop } catch { Write-Warning "Could not delete corrupted file: $_" }
                $downloadSuccess = $false
            }
        } catch {
            # Avoid $locale:$_ parsing issue by formatting message explicitly
            Write-Error ("Error downloading {0}: {1}" -f $locale, $_.ToString())
        } finally {
            if ($httpClient) { $httpClient.Dispose() }
            if ($fileStream -ne $null) {
                try { $fileStream.Dispose() } catch {}
            }
        }
    }

    if (-not $downloadSuccess) {
        Write-Host ("Failed to obtain a valid ISO for {0}." -f $locale) -ForegroundColor Red
    }
}

Write-Host "`nAll tasks complete."
