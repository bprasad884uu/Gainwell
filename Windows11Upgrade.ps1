<## Ensure PowerShell Runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}#>

# Check Registry (Original Install Language)
$locale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''

switch ($locale) {
    "en-GB" { $languageName = "English (UK)" }
    "en-US" { $languageName = "English (US)" }
    default { $languageName = $locale }
}
Write-Host "Detected Language: $languageName - Downloading ISO..."

# --- Choose Temp location: prefer C: if it has >= 20 GB, otherwise find another drive ---
function Select-TempRoot {
    param(
        [long]$MinimumBytes = (20 * 1024 * 1024 * 1024)  # 20 GB
    )

    # Try current $env:TEMP drive first
    try {
        $envTempRoot = [System.IO.Path]::GetPathRoot($env:TEMP)
        if ($envTempRoot) {
            $deviceId = $envTempRoot.TrimEnd('\')
            $logical = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID = '$deviceId'" -ErrorAction SilentlyContinue
            if ($logical -and $logical.FreeSpace -ge $MinimumBytes) {
                # Return cleaned temp path (no trailing backslash)
                return $env:TEMP.TrimEnd('\')
            }
        }
    } catch {
        # ignore and continue scanning other drives
    }

    # Scan other local fixed drives for free space
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Sort-Object -Property DeviceID
    foreach ($d in $drives) {
        if ($d.FreeSpace -ge $MinimumBytes) {
            $root = "$($d.DeviceID)\"
            $candidateTemp = Join-Path -Path $root -ChildPath "Temp"
            try {
                if (-not (Test-Path $candidateTemp)) {
                    New-Item -Path $candidateTemp -ItemType Directory -Force | Out-Null
                }
                # quick write test
                $testFile = Join-Path $candidateTemp ".__writetest.tmp"
                Set-Content -Path $testFile -Value "ok" -ErrorAction Stop
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                return $candidateTemp.TrimEnd('\')
            } catch {
                # If can't create/write, skip this drive
                continue
            }
        }
    }

    # Fallback to $env:TEMP if nothing matches
    return $env:TEMP.TrimEnd('\')
}

$TempRoot = Select-TempRoot -MinimumBytes (20 * 1024 * 1024 * 1024)
# If returned root is a drive root like "C:", normalize to a Temp subfolder
if ($TempRoot -match "^[A-Za-z]:$") {
    $TempRoot = Join-Path $TempRoot "Temp"
    if (-not (Test-Path $TempRoot)) { New-Item -Path $TempRoot -ItemType Directory -Force | Out-Null }
}

Write-Host "Using temp root: $TempRoot"

# Set Download URL & Destination Based on Locale (destination now inside $TempRoot)
if ($locale -eq "en-GB") {
    $isoUrl = "h"
    $destination = Join-Path -Path $TempRoot -ChildPath "Win11_24H2_ENGB.iso"
} elseif ($locale -eq "en-US") {
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_English_x64.iso?t=bed7282e-df3b-4302-9ed2-f03ff13d2e30&P1=1758720782&P2=601&P3=2&P4=vRBkWtUkcInyMlMm2IdJt7UzNR5GR2lB31%2b9YJVavRrncRPx3tEWzNSd5ziMXBnlnVbNIUDQ%2baFA%2bH2%2fJtkKBn4iJLWfZvJ5Q3besbAKw5d7AK3DijoCWictnlO7rCCuU7UTHyMgGtc5bCArkcACA4YAnsMFNBL0YSjhdbEGfmIaDjgtz2CA7nyxsxjBaEZ0KphNOpPtuXOigIUMkCWAkGMnIuL%2fYP4nFemK55EqIzpiu1AIJMonxtYWDi9Gt1NNATs6lNl1IYm2iGhbsvLkLhiVj3SuWpXpBaQ9Eo6y7HCqO2MHKxuwc%2fHS%2fuKhf4Kct4bcryQndA7%2fZgbnmqz7Pw%3d%3d"
    $destination = Join-Path -Path $TempRoot -ChildPath "Win11_24H2_ENUS.iso"
} else {
    Write-Host "Unsupported Language. No ISO available." -ForegroundColor Red
    exit
}

# --- Step 0: Check if file exists and verify integrity ---
$downloadSuccess = $false

if (Test-Path $destination) {
    Write-Host "`nFile already exists: $destination"
    Write-Host "`nChecking file integrity by attempting to mount..."

    try {
        $null = Mount-DiskImage -ImagePath $destination -ErrorAction Stop
        Write-Host "`nISO mounted successfully. File integrity confirmed."
        $null = Dismount-DiskImage -ImagePath $destination
        $downloadSuccess = $true
    } catch {
        Write-Warning "`nFailed to mount ISO. File may be corrupted. Re-downloading..."
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
    }
}

# --- Step 1: Try HttpClient (Fastest) ---
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

    $response = $httpClient.GetAsync($isoUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

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
    Write-Host "`nDownload Complete: $destination"
    $downloadSuccess = $true
    $httpClient.Dispose()
}

if (-not $downloadSuccess) {
    Write-Host "`nAll download methods failed. Please check your internet connection." -ForegroundColor Red
    exit
}

# --- Step 2: Mount ISO ---
Write-Host "`nUnmounting existing ISOs..."
# Get all volumes that are mounted from ISO files
$volumes = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }

foreach ($volume in $volumes) {
    try {
        $devicePath = "\\.\$($volume.DriveLetter):"
        Write-Host "`nAttempting to dismount image mounted at: $devicePath"
        $null = Dismount-DiskImage -DevicePath $devicePath -ErrorAction Stop
        Write-Host "`nSuccessfully dismounted: $devicePath"
    } catch {
        Write-Warning "`nFailed to dismount: $devicePath. Error: $_"
    }
}

# Find Downloaded ISO File in chosen temp root
$isoPath = Get-ChildItem -Path ($TempRoot + '\') -Filter "Win11*.iso" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
if (-not $isoPath -and (Test-Path $destination)) { $isoPath = $destination }

if (-not $isoPath) {
    Write-Host "`nNo ISO file found in Temp Folder ($TempRoot)." -ForegroundColor Red
    exit
}

Write-Host "`nISO found: $isoPath"

# Mount ISO
Write-Host "`nMounting ISO..."
try {
    $null = Mount-DiskImage -ImagePath $isoPath -ErrorAction Stop
    Write-Host "`nISO Mounted Successfully." -ForegroundColor Green
} catch {
    Write-Host "`nFailed to mount ISO: $_" -ForegroundColor Red
    exit
}

# Get Drive Letter of Mounted ISO
Start-Sleep -Seconds 2 # Allow mounting
$driveLetter = (Get-DiskImage -ImagePath $isoPath | Get-Volume).DriveLetter
$setupPath = "$driveLetter`:\setup.exe"

if (-not (Test-Path $setupPath)) {
    Write-Warning "`nSetup file not found. Exiting..." -ForegroundColor Red
    exit
}

# --- Step 3: Windows 11 upgrade (Silent Install)
# Get Manufacturer
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
Write-Host "`nDetected System Manufacturer: $manufacturer"

# Windows 11 CPU Compatibility Check Script with Bypass
$intelListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsIntel.txt"
$amdListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsAMD.txt"
$qualcommListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsQualcomm.txt"

# Get raw CPU name
$cpu = Get-CimInstance -ClassName Win32_Processor
$rawCpuName = $cpu.Name.Trim()

# Extract clean CPU model string
if ($rawCpuName -match "Core\(TM\)\s+i[3579]-\S+") {
    $cleanCpuName = $matches[0]
} elseif ($rawCpuName -match "Core\s+i[3579]-\S+") {
    $cleanCpuName = $matches[0] -replace "Core", "Core(TM)"
} elseif ($rawCpuName -match "AMD\s+Ryzen\s+\d+\s+\d{4}") {
    $cleanCpuName = $matches[0] -replace "^AMD\s+", ""
} elseif ($rawCpuName -match "AMD\s+Ryzen\s+\S+") {
    $cleanCpuName = $matches[0]
} elseif ($rawCpuName -match "Qualcomm\s+\S+") {
    $cleanCpuName = $matches[0]
} elseif ($rawCpuName -match "Xeon\(R\)\s+CPU\s+([A-Za-z0-9\-]+)") {
    $cleanCpuName = "Xeon " + $matches[1]
} else {
    $cleanCpuName = ""
}

# Fallback if match fails
if (-not $cleanCpuName) {
    Write-Host "`nCould not extract a matching CPU model from '$rawCpuName'" -ForegroundColor Yellow
    $cleanCpuName = $rawCpuName  # Proceed with raw name
}

# Load System.Net.Http.dll for PowerShell 5.1 if needed
if (-not ("System.Net.Http.HttpClient" -as [type])) {
    Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
}

# Use HttpClient instead of Invoke-WebRequest
$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

# Download CPU lists
try {
    $intelList = $httpClient.GetStringAsync($intelListUrl).Result
    $amdList = $httpClient.GetStringAsync($amdListUrl).Result
    $qualcommList = $httpClient.GetStringAsync($qualcommListUrl).Result
} catch {
    Write-Host "`nFailed to download processor support lists." -ForegroundColor Yellow
    return
}

# Split lists into lines
$intelList = $intelList -split "`n" | ForEach-Object { $_.Trim() }
$amdList = $amdList -split "`n" | ForEach-Object { $_.Trim() }
$qualcommList = $qualcommList -split "`n" | ForEach-Object { $_.Trim() }

# Determine manufacturer and check support
$cpuSupported = $false
switch -Regex ($cpu.Manufacturer) {
    "Intel"    { $cpuSupported = $intelList -contains $cleanCpuName }
    "AMD"      { $cpuSupported = $amdList -contains $cleanCpuName }
    "Qualcomm" { $cpuSupported = $qualcommList -contains $cleanCpuName }
    default    { Write-Host "`nUnknown manufacturer: $($cpu.Manufacturer)" }
}

# Function to check TPM 2.0
function Check-TPM {
    $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
    return $tpm.SpecVersion -match "2.0"
}

# Check if the processor is 64-bit
$architecture = $cpu.AddressWidth
$cpu64Bit = $architecture -eq 64

# Check CPU Speed (Minimum 1 GHz)
$cpuSpeedGHz = $cpu.MaxClockSpeed / 1000
$cpuSpeedCompatible = $cpuSpeedGHz -ge 1

# Get Secure Boot status
function Get-SecureBootStatus {
    try {
        if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
            $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
            return [bool]$secureBoot
        } else {
            throw "`nNot 64-bit"
        }
    } catch {
        try {
            $msinfo = Get-CimInstance -Namespace root\WMI -Class MS_SystemInformation -ErrorAction Stop
            if ($msinfo.SecureBoot -ne $null) {
                return [bool]$msinfo.SecureBoot
            }
        } catch {}
        try {
            $cs = Get-CimInstance -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($cs.SecureBootState -ne $null) {
                return [bool]$cs.SecureBootState
            }
        } catch {}
        return $false
    }
}

# Get Secure Boot Status
$secureBootEnabled = Get-SecureBootStatus

# Check TPM 2.0 Support
$tpmCompatible = Check-TPM

# Display results
Write-Host "`nWindows 11 Compatibility Check" -ForegroundColor Cyan
Write-Host "-----------------------------------"
Write-Host "`nProcessor: $rawCpuName"

# Architecture Check
if ($cpu64Bit) {
    Write-Host "`n64-bit CPU: Compatible" -ForegroundColor Green
} else {
    Write-Host "`n64-bit CPU: Not Compatible" -ForegroundColor Red
}

# CPU Speed Check
if ($cpuSpeedCompatible) {
    Write-Host "`nCPU Speed: $cpuSpeedGHz GHz (Compatible)" -ForegroundColor Green
} else {
    Write-Host "`nCPU Speed: $cpuSpeedGHz GHz (Not Compatible)" -ForegroundColor Red
}

# Secure Boot Check
if ($secureBootEnabled) {
    Write-Host "`nSecure Boot Enabled: Yes" -ForegroundColor Green
} else {
    Write-Host "`nSecure Boot Enabled: No" -ForegroundColor Red
}

# TPM 2.0 Check
if ($tpmCompatible) {
    Write-Host "`nTPM 2.0 Support: Yes" -ForegroundColor Green
} else {
    Write-Host "`nTPM 2.0 Support: No" -ForegroundColor Red
}

# CPU Support Check
if ($cpuSupported) {
    Write-Host "`nCPU Compatibility: $rawCpuName is supported" -ForegroundColor Green
} else {
    Write-Host "`nCPU Compatibility: $rawCpuName is NOT supported" -ForegroundColor Red
}

# Store failed checks
# Incompatibility reasons
$incompatibilityReasons = @()
if (-not $cpu64Bit) { $incompatibilityReasons += "CPU is not 64-bit" }
if (-not $cpuSpeedCompatible) { $incompatibilityReasons += "CPU speed is less than 1 GHz" }
if (-not $secureBootEnabled) { $incompatibilityReasons += "Secure Boot is not enabled" }
if (-not $tpmCompatible) { $incompatibilityReasons += "TPM 2.0 is not supported or not enabled" }
if (-not $cpuSupported) { $incompatibilityReasons += "Unsupported processor: $rawCpuName" }

# Final verdict
if ($incompatibilityReasons.Count -gt 0) {
    Write-Host "`nThis system does not meet below Windows 11 requirements:" -ForegroundColor Yellow
    foreach ($reason in $incompatibilityReasons) {
        Write-Host " - $reason" -ForegroundColor Red
    }

    Write-Host "`nRegistry Tweaks will be applied to bypass the checks..." -ForegroundColor Yellow
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassStorageCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f
    Write-Host "`nBypass Applied Successfully. Now Proceed for installation..." -ForegroundColor Green
    $installArgs = "/product server /auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable /noreboot"
} else {
    Write-Host "`nThis system meets all Windows 11 hardware requirements." -ForegroundColor Green
    $installArgs = "/auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable /noreboot"
}

# Start Windows 11 Upgrade
Write-Host "`nStarting Windows 11 upgrade..."
$null = Start-Process -FilePath $setupPath -ArgumentList $installArgs -PassThru

# Path to the setup log file
$logPath = 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log'
$setupFolder = 'C:\$WINDOWS.~BT'

# Delete the log file if it exists
if (Test-Path $logPath) {
    $null = Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
}

function Is-SetupRunning {
    Get-Process -Name 'setupprep','SetupHost' -ErrorAction SilentlyContinue | Where-Object { $_ } | ForEach-Object { return $true }
    return $false
}

while ($true) {
    $folderExists = Test-Path $setupFolder
    $logExists = Test-Path $logPath
    $setupRunning = Is-SetupRunning

    if ($logExists -or (-not $folderExists -and -not $setupRunning)) {
        if (-not $folderExists -and -not $setupRunning) {
            Write-Host "`nNeither setup folder nor upgrade process found. Exiting..." -ForegroundColor Yellow
        }
        break
    }
    Start-Sleep -Seconds 1
}

# Start monitoring loop
Write-Host "`nYour PC will restart several times. This might take a while." -ForegroundColor Green
$lastPercent = -1

# Spinner characters
$spinner = '\|/--\|/--'.ToCharArray()
$spinnerIndex = 0
$lastPercent = -1
$currentPercent = 0

# Initial display
#Write-Host -NoNewline "`r$($spinner[$spinnerIndex]) 0% complete     " -ForegroundColor Cyan

while ($true) {
    Start-Sleep -Milliseconds 200

    if (Test-Path $logPath) {
        $content = Get-Content $logPath -Tail 200
        $progressLines = $content | Where-Object { $_ -match "Overall progress: \[(\d+)%\]" }

        if ($progressLines) {
            $lastLine = $progressLines[-1]
            if ($lastLine -match "Overall progress: \[(\d+)%\]") {
                $currentPercent = [int]$matches[1]
            }
        }

        # Update spinner and progress
        $spinnerChar = $spinner[$spinnerIndex % $spinner.Length]
        Write-Host -NoNewline "`r$spinnerChar $currentPercent% complete     " -ForegroundColor Cyan
        $spinnerIndex++

        if ($currentPercent -ge 100) {
            Write-Host "`r" + (' ' * 60) + "`r" -NoNewline
            Write-Host "Upgrade completed! Your PC will restart in a few moments" -ForegroundColor Green
            break
        }
    } else {
        Write-Host -NoNewline "`rWindows 11 installation failed. Please restart the installation or try again after restarting your PC." -ForegroundColor Red
        break
    }
}

# Unmount ISO
Write-Host "`nUnmounting ISO..."

# Unmount the ISO after installation
try {
    Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Failed to dismount ISO: $_"
}
Write-Host "`nWindows 11 upgrade process complete."

Write-Host "`nRebooting System..."
#Restart-Computer -Force











