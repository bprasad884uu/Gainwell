# Install_ZTNA.ps1
# Install ZTNA
# Author: Bishnu's Helper

$DidInstall      = $false
$downloadSuccess = $false

Write-Host "`n=== Checking and Installing ZTNA (Zscaler) ==="

$destination = "$env:TEMP\Zscaler-windows-installer-x64.msi"
$ZTNA_setup  = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/ZTNA/Zscaler-windows-4.7.0.61-installer-x64.msi"

# -------- Functions --------
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
function Test-ZTNAInstalled {
    $entries = @()
    $entries += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Where-Object { $_.DisplayName -like "*Zscaler*" }
    $entries += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Where-Object { $_.DisplayName -like "*Zscaler*" }
    $entries += Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Where-Object { $_.DisplayName -like "*Zscaler*" }
    return ($entries -and $entries.Count -gt 0)
}

# -------- 1) Check first --------
if (Test-ZTNAInstalled) {
    Write-Host "`nZTNA (Zscaler) is already installed. Skipping download and installation."
    # Optional: remove leftover installer if present
    if (Test-Path $destination) {
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
        Write-Host "Cleaned up leftover installer: $destination"
    }
    Write-Host "`n=== Script Finished ==="
    return
}

# -------- 2) Download only if not installed --------
# Ensure TLS 1.2 for older hosts
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

if (Test-Path $destination) {
    # Clean any previous partial file
    Remove-Item $destination -Force -ErrorAction SilentlyContinue
}

# --- Download File ---
# Load HttpClient only now (needed)
if (-not ("System.Net.Http.HttpClient" -as [type])) {
    Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
}

$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

Write-Host "`nStarting download..."
try {
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
        Write-Host "`nWarning: Server did not return file size." -ForegroundColor Yellow
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
catch {
    try { $httpClient.Dispose() } catch {}
    Write-Host "`nERROR: Failed to download ZTNA installer. $_" -ForegroundColor Red
    exit 1
}

if (-not $downloadSuccess) {
    Write-Host "`nAll download methods failed. Please check your internet connection." -ForegroundColor Red
    exit 1
}

# -------- 3) Install silently --------
Write-Host "`nInstalling ZTNA from: $destination"
$proc = Start-Process "msiexec.exe" -ArgumentList "/i `"$destination`" /qn /norestart" -Wait -PassThru
if ($proc.ExitCode -eq 0) {
    Write-Host "`nZTNA installation completed."
    $DidInstall = $true
} else {
    Write-Host "`nERROR: MSI installation failed with exit code $($proc.ExitCode)." -ForegroundColor Red
}

# -------- 4) Post-install --------
if ($DidInstall) {
    Write-Host "`nZTNA (Zscaler) was installed."
	Write-Host "`nStopping ZTNA processes..."
    $ProcessesToKill = @("ZSAService", "ZSATray", "ZSATrayManager")
    foreach ($proc in $ProcessesToKill) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force
    }
    Write-Host "`nZTNA processes stopped. They will start on next system boot or user login."
	} else {
    Write-Host "`nNo ZTNA installation performed."
}

# -------- 5) Always Cleanup --------
if (Test-Path $destination) {
    Remove-Item $destination -Force -ErrorAction SilentlyContinue
    Write-Host "`nInstaller removed: $destination"
}

Write-Host "`n=== Script Finished ==="
