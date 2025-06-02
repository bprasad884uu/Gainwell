# Define system locale
$systemLocale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''

# Define network path and destination folder
$sourceFolder = "\\10.131.45.121\Basic Softwares"
$destinationFolder = "$env:Temp"
$MountDrive = "Y"

# Ensure destination folder exists
if (-not (Test-Path $destinationFolder)) {
    New-Item -Path $destinationFolder -ItemType Directory | Out-Null
}

# Define source ISO based on system locale
switch ($systemLocale) {
    "en-US" { $sourceISO = Join-Path $sourceFolder "Win11_24H2_ENUS.iso" }
    "en-GB" { $sourceISO = Join-Path $sourceFolder "Win11_24H2_ENGB.iso" }
    default {
        Write-Output "`nNo matching ISO found for system locale: $systemLocale"
        exit 1
    }
}

$destinationISO = Join-Path $destinationFolder (Split-Path $sourceISO -Leaf)

# --- Step 2: Check if file exists and verify integrity ---
$downloadSuccess = $false

if (Test-Path $destinationISO) {
    Write-Host "`nFile already exists: $destinationISO"
    Write-Host "`nChecking file integrity by attempting to mount..."

    try {
        Mount-DiskImage -ImagePath $destinationISO -ErrorAction Stop
        Write-Host "`nISO mounted successfully. File integrity confirmed."
        Dismount-DiskImage -ImagePath $destinationISO
        $downloadSuccess = $true
    } catch {
        Write-Warning "`nFailed to mount ISO. File may be corrupted. Re-copying..."
        Remove-Item $destinationISO -Force
    }
}

# --- Step 3: Copy with progress ---
if (-not $downloadSuccess) {
    if (-not (Test-Path $sourceISO)) {
        Write-Host "`nSource ISO not found: $sourceISO"
        exit 1
    }

    $fileInfo = Get-Item "$sourceISO"
    $totalSize = $fileInfo.Length

    function Format-Size($bytes) {
        if ($bytes -ge 1GB) { return ("{0:N2} GB" -f ($bytes / 1GB)) }
        elseif ($bytes -ge 1MB) { return ("{0:N2} MB" -f ($bytes / 1MB)) }
        elseif ($bytes -ge 1KB) { return ("{0:N2} KB" -f ($bytes / 1KB)) }
        else { return ("{0} B" -f $bytes) }
    }

    Write-Host "`nCopying ISO (Total Size: $(Format-Size $totalSize)) from network share...`n"

    $blockSize = 10MB
    $copiedBytes = 0
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $sourceStream = [System.IO.File]::OpenRead($sourceISO)
    $destStream = [System.IO.File]::Create($destinationISO)

    $buffer = New-Object byte[] $blockSize
    while (($readBytes = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $destStream.Write($buffer, 0, $readBytes)
        $copiedBytes += $readBytes

        $elapsedTime = $stopwatch.Elapsed.TotalSeconds
        $speedBytesPerSec = if ($elapsedTime -gt 0) { $copiedBytes / $elapsedTime } else { 0 }

        function Format-Speed($bytesPerSec) {
            if ($bytesPerSec -ge 1GB) { return ("{0:N2} GB/s" -f ($bytesPerSec / 1GB)) }
            elseif ($bytesPerSec -ge 1MB) { return ("{0:N2} MB/s" -f ($bytesPerSec / 1MB)) }
            elseif ($bytesPerSec -ge 1KB) { return ("{0:N2} KB/s" -f ($bytesPerSec / 1KB)) }
            else { return ("{0} B/s" -f $bytesPerSec) }
        }

        $percentComplete = [math]::Round(($copiedBytes / $totalSize) * 100, 2)
        $remainingBytes = $totalSize - $copiedBytes
        $etaSeconds = if ($speedBytesPerSec -gt 0) { [math]::Round($remainingBytes / $speedBytesPerSec, 2) } else { "Calculating..." }

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

        Write-Progress -Activity "Copying File..." -Status "$percentComplete% Complete - ETA: $etaFormatted" -PercentComplete $percentComplete
        Write-Host "`rTotal: $(Format-Size $totalSize) | Copied: $(Format-Size $copiedBytes) | Speed: $(Format-Speed $speedBytesPerSec) | ETA: $etaFormatted" -NoNewline
    }

    $sourceStream.Close()
    $destStream.Close()
    $sourceStream.Dispose()
    $destStream.Dispose()

    Write-Host "`nFile copy completed successfully!"
}

# --- Step 4: Find Copied ISO File ---
# --- Install Windows 11 ---
Write-Host "`nUnmounting existing ISOs..."
# Get all volumes that are mounted from ISO files
$volumes = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }

foreach ($volume in $volumes) {
    try {
        $devicePath = "\\.\$($volume.DriveLetter):"
        $image = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_DiskDrive | Where-Object {
            $_.DeviceID -like "*$($volume.DriveLetter)*"
        }

        # Try to dismount using the drive letter
        Write-Host "`nAttempting to dismount image mounted at: $devicePath"
        Dismount-DiskImage -DevicePath $devicePath -ErrorAction Stop
        Write-Host "`nSuccessfully dismounted: $devicePath"
    } catch {
        Write-Warning "`nFailed to dismount: $devicePath. Error: $_"
    }
}

# Find Copied ISO File
$isoPath = Get-ChildItem -Path "$env:Temp\" -Filter "Win11*.iso" -File | Select-Object -ExpandProperty FullName -First 1

if (-not $isoPath) {
    Write-Host "`nNo ISO file found in Temp Folder." -ForegroundColor Red
    exit
}

Write-Host "`nISO found: $isoPath"

# Mount ISO
Write-Host "`nMounting ISO..."
try {
    Mount-DiskImage -ImagePath $isoPath -ErrorAction Stop
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
    Write-Host "`nSetup file not found. Exiting..." -ForegroundColor Red
    exit
}

# --- Step 5: Windows 11 upgrade (Silent Install) ---
# Get Manufacturer
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
Write-Host "`nDetected System Manufacturer: $manufacturer"

# Windows 11 CPU Compatibility Check Script with Bypass
# GitHub CPU lists
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
    $cleanCpuName = $rawCpuName  # Proceed with raw name
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
        # Confirm-SecureBootUEFI works only in 64-bit PowerShell and UEFI systems
        if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
            $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
            return [bool]$secureBoot
        } else {
            #Write-Verbose "Confirm-SecureBootUEFI requires 64-bit PowerShell. Falling back..."
            throw "`nNot 64-bit"
        }
    } catch {
        Write-Verbose "`nPrimary method failed: $_. Trying WMI fallback..."

        try {
            # Fallback 1: MS_SystemInformation
            $msinfo = Get-CimInstance -Namespace root\WMI -Class MS_SystemInformation -ErrorAction Stop
            if ($msinfo.SecureBoot -ne $null) {
                return [bool]$msinfo.SecureBoot
            }
        } catch {
            #Write-Verbose "MS_SystemInformation failed: $_"
        }

        try {
            # Fallback 2: Win32_ComputerSystem (less reliable, but sometimes works)
            $cs = Get-CimInstance -Class Win32_ComputerSystem
            if ($cs.SecureBootState -ne $null) {
                return [bool]$cs.SecureBootState
            }
        } catch {
            #Write-Verbose "Win32_ComputerSystem fallback failed: $_"
        }

        #Write-Warning "Unable to determine Secure Boot status."
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
    Write-Host "`nCPU Compatibility: $cleanCpuName is supported" -ForegroundColor Green
} else {
    Write-Host "`nCPU Compatibility: $cleanCpuName is NOT supported" -ForegroundColor Red
}

# Store failed checks
# Incompatibility reasons
$incompatibilityReasons = @()
if (-not $cpu64Bit) { $incompatibilityReasons += "CPU is not 64-bit" }
if (-not $cpuSpeedCompatible) { $incompatibilityReasons += "CPU speed is less than 1 GHz" }
if (-not $secureBootEnabled) { $incompatibilityReasons += "Secure Boot is not enabled" }
if (-not $tpmCompatible) { $incompatibilityReasons += "TPM 2.0 is not supported or not enabled" }
if (-not $cpuSupported) { $incompatibilityReasons += "Unsupported processor: $cleanCpuName" }

# Final verdict
if ($incompatibilityReasons.Count -gt 0) {
    Write-Host "`nThis system does not meet below Windows 11 requirements:" -ForegroundColor Yellow
    foreach ($reason in $incompatibilityReasons) {
        Write-Host " - $reason" -ForegroundColor Red
    }
    Write-Host "`n⚙ Registry Tweaks will be applied to bypass the checks..." -ForegroundColor Yellow
	$null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassStorageCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f
    Write-Host "`nBypass Applied Successfully. Now Proceed for installation..." -ForegroundColor Green
	$installArgs = "/product server /auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable"
} else {
    Write-Host "`nThis system meets all Windows 11 hardware requirements." -ForegroundColor Green
	$installArgs = "/auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable"
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

# Initial output
Write-Host -NoNewline "`r0% complete     " -ForegroundColor Cyan

while ($true) {
    Start-Sleep -Seconds 1

    if (Test-Path $logPath) {
        # Read last 200 lines to find progress updates
        $content = Get-Content $logPath -Tail 200

        # Find latest progress line with Overall progress percentage
        $progressLines = $content | Where-Object { $_ -match "Overall progress: \[(\d+)%\]" }
        if ($progressLines) {
            $lastLine = $progressLines[-1]
            if ($lastLine -match "Overall progress: \[(\d+)%\]") {
                $currentPercent = [int]$matches[1]

                if ($currentPercent -ne $lastPercent) {
                    Write-Host -NoNewline "`r$currentPercent% complete     " -ForegroundColor Cyan
                    $lastPercent = $currentPercent
                }

                if ($currentPercent -ge 100) {
                    Write-Host "`r" + (' ' * 60) + "`r" -NoNewline
                    Write-Host "Upgrade completed! Your PC will restart in a few moments" -ForegroundColor Green
                    break
                }
            }
        }
    } else {
        Write-Host -NoNewline "`rWindows 11 installation failed. Please restart the installation or try again after restarting your PC." -ForegroundColor Red
        break
    }
}

# Unmount ISO
Write-Host "`nUnmounting ISO..."

# Unmount the ISO after installation
Dismount-DiskImage -ImagePath $isoPath
Write-Host "`nWindows 11 upgrade process complete."

Write-Host "`nRebooting System..."
#Restart-Computer -Force