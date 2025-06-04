# Ensure script is running as Administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator."
    Exit
}

# Step 1: Check if system is Dell
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
if ($manufacturer -notlike "*Dell*") {
    Write-Output "❌ This system is not a Dell device. Exiting."
    exit
}

Write-Output "✅ Dell system detected. Proceeding with Dell Command | Configure installation..."

# Step 2: Set download URL and destination
$downloadUrl = "https://dl.dell.com/FOLDER12902766M/1/Dell-Command-Configure-Application_MD8CJ_WIN64_5.2.0.9_A00.EXE"
$installerPath = "$env:TEMP\DellCommandConfigure.exe"

# Step 3: Download Dell Command | Configure
Write-Output "📥 Downloading Dell Command | Configure..."

$downloadSuccess = $false

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

# Create HttpClient with custom User-Agent
$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)
$httpClient.DefaultRequestHeaders.UserAgent.ParseAdd('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36')
$httpClient.DefaultRequestHeaders.Add("Accept", "*/*")

if (-not $downloadSuccess) {
    Write-Host "`nStarting download..."

    $response = $httpClient.GetAsync($downloadUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

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

    $fileStream = [System.IO.File]::OpenWrite($installerPath)

    $bufferSize = 10MB
    $buffer = New-Object byte[] ($bufferSize)
    $downloaded = 0
    $startTime = Get-Date

    Write-Host "`nDownloading Windows 11 ISO ($locale)..."
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
    Write-Host "`nDownload Complete: $installerPath"
    $downloadSuccess = $true
    $httpClient.Dispose()
}

if (-not $downloadSuccess) {
    Write-Host "`nDoownload failed. Please check your internet connection." -ForegroundColor Red
    exit
}

# Step 4: Install silently
Write-Output "`n📦 Installing Dell Command | Configure silently..."
Start-Process -FilePath $installerPath -ArgumentList "/s" -Wait

# Step 5: Define CCTK path
$cctkPath = "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe"
if (-Not (Test-Path $cctkPath)) {
    Write-Error "❌ CCTK not found at expected path: $cctkPath"
    exit
}

# Step 6: Check TPM and Secure Boot
Write-Output "`n🔍 Checking TPM status..."
$tpmStatus = & $cctkPath --tpm
Write-Output $tpmStatus

Write-Output "`n🔍 Checking Secure Boot status..."
$secureBootStatus = & $cctkPath --secureboot
Write-Output $secureBootStatus

# Step 7: Enable TPM and Secure Boot if needed
if ($tpmStatus -match "Disabled") {
    Write-Output "🔧 Enabling TPM..."
    & $cctkPath --tpm=on
}

if ($secureBootStatus -match "Disabled") {
    Write-Output "🔧 Enabling Secure Boot..."
    & $cctkPath --secureboot=enable
}

Write-Output "`n✅ Operation complete. A reboot may be required for changes to take effect."
