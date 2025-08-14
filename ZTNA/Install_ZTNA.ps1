# Install_ZTNA.ps1
# Install ZTNA
# Author: Bishnu's Helper

$DidUninstall = $false
$DidInstall   = $false

Write-Host "`n=== Checking and Installing ZTNA (Zscaler) ==="

$destination = "$env:TEMP\Zscaler-windows-installer-x64.msi"

$ZTNA_setup = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/ZTNA/Zscaler-windows-4.7.0.61-installer-x64.msi"

$downloadSuccess = $false
# --- Try HttpClient (Fastest) ---
if (-not ("System.Net.Http.HttpClient" -as [type])) {
    Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
}

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

$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

if (-not $downloadSuccess) {
    Write-Host "`nStarting download..."

    $response = $httpClient.GetAsync($ZTNA_setup, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

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
        Write-Host "`nWarning: File size unknown. Assuming large file to prevent errors." -ForegroundColor Yellow
        $totalSize = 1024 * 1024 * 1024
    }

    $fileStream = [System.IO.File]::OpenWrite($destination)

    $bufferSize = 10MB
    $buffer = New-Object byte[] ($bufferSize)
    $downloaded = 0
    $startTime = Get-Date

    Write-Host "`nDownloading ZTNA Setup..."
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
    Write-Host "`nDownload Complete: $destination"
    $downloadSuccess = $true
    $httpClient.Dispose()
}

if (-not $downloadSuccess) {
    Write-Host "`nAll download methods failed. Please check your internet connection." -ForegroundColor Red
    exit
}

# Check if ZTNA already installed
$ZTNAInstalled = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
    Where-Object { $_.DisplayName -like "*Zscaler*" }

$ZTNAInstalled += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
    Where-Object { $_.DisplayName -like "*Zscaler*" }

if ($ZTNAInstalled.Count -gt 0) {
    Write-Host "`nZTNA (Zscaler) is already installed. Skipping installation."
} elseif (Test-Path $destination) {
    Write-Host "`nInstalling ZTNA from: $destination"
    Start-Process "msiexec.exe" -ArgumentList "/i `"$destination`" /qn /norestart" -Wait
    Write-Host "`nZTNA installation completed."
    $DidInstall = $true
} else {
    Write-Host "ERROR: Installer not found at $destination"
}

if ($DidInstall) {
    Write-Host "`n✔ ZTNA (Zscaler) was installed."
	Write-Host "`nStopping ZTNA processes..."
    $ProcessesToKill = @("ZSAService", "ZSATray", "ZSATrayManager")
    foreach ($proc in $ProcessesToKill) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force
    }
    Write-Host "`nZTNA processes stopped. They will start on next system boot or user login."
	# Clean up installer
    Remove-Item $destination -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "`nℹ No ZTNA installation performed."
}

Write-Host "`n=== Script Finished ==="
