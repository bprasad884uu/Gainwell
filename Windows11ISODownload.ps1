# Download both Win11 24H2 ISOs (EN-GB and EN-US) into D:\WINOS
# Run as Administrator for Mount-DiskImage verification.

# Ensure destination folder exists
$targetFolder = "D:\WINOS"
if (-not (Test-Path $targetFolder)) {
    New-Item -ItemType Directory -Path $targetFolder | Out-Null
}

# List of ISOs to download
$isos = @(
    @{
        Locale = "en-GB"
        Url    = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_EnglishInternational_x64.iso?t=949f3b52-4fec-4e79-948d-dc867ec0e0b2&P1=1757396282&P2=601&P3=2&P4=hbln8pdQLqN%2b2wY9vR494xAbrK9NlMmNhAK8ECgHyKVSxOa9RQ3CSMFFM4jUtw%2fqx16PH4lv5kS2%2ft1KBFIxcALLLqDDiUnd3Fd200vdkRVWZygwTl39KclN7PUrR26kvuoVYuo%2bTmlkQ03pne%2ftMYM1hMNxfoVtj6%2byTY7pXn%2fjIRC%2bZ9Bu2SSazrbolhWO%2f4Mv9X8UPtttCOs8raDP%2fq2ula9KrfrN%2fkYlVw8e7PX7XZB7mk0gjReMfj7r4nUOXmEUY3Y3FuySmAHOYQ05yaK6REFaGTTKlrn9n1irZqiwyk4a%2fAU4pCYUtkER1n8cRUlFL4ald9qXjMbo5V9Ajg%3d%3d"
        File   = Join-Path $targetFolder "Win11_24H2_ENGB.iso"
    },
    @{
        Locale = "en-US"
        Url    = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_English_x64.iso?t=fc01eb3d-8381-4320-a964-e4d64ad4bb5a&P1=1757396303&P2=601&P3=2&P4=dT9HnICUdIvrOyUtME7dKbpLUiNX5ADOkYvtWLWgDFMwlo1KKVOTbpoCg92r7IjmRFxQftUGvDJEqIiK8klJLZ1ononhNnp1c4F7fABTXTgFsqsS5B0chsTI45ldj0DYN17mKCO0l4BxKO7n4jeaXz3FzK67X1kltJBuwJDThhXFjAvhnKMbwVhnEiGwxWrdMms2w%2fRGeJOKqO28bZp03c%2bg6VCv86czoyElRP%2bCWohpquCSgI6ucg02QoMOawjGs7dVyZN1L9f%2bctE1AX5Bihwy0%2brdjE6MP1MDJ1vbSAddO4pfk7uqnUvhVrDuptcGcOnO%2bQFr%2fJbCnoh%2b%2fFBpww%3d%3d"
        File   = Join-Path $targetFolder "Win11_24H2_ENUS.iso"
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
            Dismount-DiskImage -ImagePath $destination -ErrorAction SilentlyContinue
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
                Dismount-DiskImage -ImagePath $destination -ErrorAction SilentlyContinue
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
