# Define system locale
$systemLocale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''

# Define network path and destination folder
$sourceFolder = "\\10.131.126.12\Softwares"
$destinationFolder = "$env:Temp"
$MountDrive = "Y"

# Remove existing drive mapping if exists
if (Test-Path "$MountDrive`:") {
    Remove-PSDrive -Name $MountDrive -Force
    Start-Sleep -Seconds 2  # Wait to ensure removal is completed
}

# Map network drive temporarily
try {
    New-PSDrive -Name $MountDrive -PSProvider FileSystem -Root $sourceFolder -Persist -ErrorAction Stop
} catch {
    Write-Output "Failed to map network drive. Check connectivity."
    exit 1
}

# Ensure destination folder exists
if (-not (Test-Path $destinationFolder)) {
    New-Item -Path $destinationFolder -ItemType Directory | Out-Null
    Write-Output "Created folder: $destinationFolder"
}

#Check Registry (Original Install Language)
$locale = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language').InstallLanguage

# Define source ISO based on system locale
switch ($systemLocale) {
    "en-US" { $sourceISO = "$MountDrive`:Win11_24H2_ENUS.iso" }
    "en-GB" { $sourceISO = "$MountDrive`:Win11_24H2_ENGB.iso" }
    default { 
        Write-Output "No matching ISO found for system locale: $systemLocale"
        Remove-PSDrive -Name $MountDrive -Force
        exit 1 
    }
}

# Check if source ISO exists
if (-not (Test-Path $sourceISO)) {
    Write-Output "Source ISO not found: $sourceISO"
    Remove-PSDrive -Name $MountDrive -Force
    exit 1
}

# Define destination path
$destinationISO = Join-Path $destinationFolder (Split-Path $sourceISO -Leaf)

# Get file size
$fileInfo = Get-Item "$sourceISO"
$totalSize = $fileInfo.Length
$totalMB = [math]::Round($totalSize / 1MB, 2)

Write-Output "File Size: $totalMB MB"

# If the file is small, use normal Copy-Item
if ($totalMB -lt 1) {
    Copy-Item -Path $sourceISO -Destination $destinationISO -Force
    Write-Output "File copied successfully (small file, fast copy)."
    Remove-PSDrive -Name $MountDrive -Force
    exit 0
}

# Initialize progress
$blockSize = 10MB  # Adjusted for performance
$copiedBytes = 0
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Create file streams
$sourceStream = [System.IO.File]::OpenRead($sourceISO)
$destStream = [System.IO.File]::Create($destinationISO)

try {
    $buffer = New-Object byte[] $blockSize
    while (($readBytes = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $destStream.Write($buffer, 0, $readBytes)
        $copiedBytes += $readBytes

        # Progress Calculation
        $elapsedTime = $stopwatch.Elapsed.TotalSeconds
        $speed = if ($elapsedTime -gt 0) { [math]::Round($copiedBytes / $elapsedTime / 1MB, 2) } else { 0 }
        $percentComplete = [math]::Round(($copiedBytes / $totalSize) * 100, 2)
        
        # ETA Calculation
        $remainingBytes = $totalSize - $copiedBytes
        $etaSeconds = if ($speed -gt 0) { [math]::Round($remainingBytes / ( $speed * 1MB ), 2) } else { "Calculating..." }

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
        Write-Host "Total: $totalMB MB | Copied: $([math]::Round($copiedBytes / 1MB, 2)) MB | Speed: $speed MB/s | ETA: $etaFormatted" -NoNewline
    }
} catch {
    Write-Output "Error occurred during file copy: $_"
} finally {
    # Close and dispose of file streams
    $sourceStream.Close()
    $destStream.Close()
    $sourceStream.Dispose()
    $destStream.Dispose()
    Remove-PSDrive -Name $MountDrive -Force
}

Write-Output "File copy completed successfully!"

# --- Install Windows 11 ---
# Find Downloaded ISO File
$isoPath = Get-ChildItem -Path "$env:Temp\" -Filter "Win11*.iso" -File | Select-Object -ExpandProperty FullName -First 1

if (-not $isoPath) {
    Write-Host "No ISO file found in Temp Folder." -ForegroundColor Red
    exit
}

Write-Host "ISO found: $isoPath"

# Mount ISO
Write-Host "Mounting ISO..."
try {
    Mount-DiskImage -ImagePath $isoPath -ErrorAction Stop
    Write-Host "ISO Mounted Successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to mount ISO: $_" -ForegroundColor Red
    exit
}

# Get Drive Letter of Mounted ISO
$driveLetter = (Get-DiskImage -ImagePath $isoPath | Get-Volume).DriveLetter
$setupPath = "$driveLetter`:\setup.exe"

if (-not (Test-Path $setupPath)) {
    Write-Host "Setup file not found on mounted ISO. Exiting..." -ForegroundColor Red
    exit
}

# --- Step 5: Windows 11 upgrade (Silent Install)
# Get Manufacturer
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
Write-Host "Detected System Manufacturer: $manufacturer"

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
} else {
    $cleanCpuName = ""
}

# Fallback if match fails
if (-not $cleanCpuName) {
    Write-Host "⚠️ Could not extract a matching CPU model from '$rawCpuName'" -ForegroundColor Yellow
    return
}

# Load System.Net.Http.dll for PowerShell 5.1
if (-not ("System.Net.Http.HttpClient" -as [type])) {
    Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
}

# Use HttpClient instead of Invoke-WebRequest
Add-Type -AssemblyName "System.Net.Http"
$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

# Download CPU lists
try {
    $intelList = $httpClient.GetStringAsync($intelListUrl).Result
    $amdList = $httpClient.GetStringAsync($amdListUrl).Result
    $qualcommList = $httpClient.GetStringAsync($qualcommListUrl).Result
} catch {
    Write-Host "⚠️ Failed to download processor support lists." -ForegroundColor Yellow
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
    default    { Write-Host "❓ Unknown manufacturer: $($cpu.Manufacturer)" }
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
$secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
$secureBootEnabled = $secureBoot -eq $true

# Check TPM 2.0 Support
$tpmCompatible = Check-TPM

# Display results
Write-Host "`nWindows 11 Compatibility Check" -ForegroundColor Cyan
Write-Host "-----------------------------------"
Write-Host "Processor: $rawCpuName"

# Architecture Check
if ($cpu64Bit) {
    Write-Host "64-bit CPU: ✔ Compatible" -ForegroundColor Green
} else {
    Write-Host "64-bit CPU: ❌ Not Compatible" -ForegroundColor Red
}

# CPU Speed Check
if ($cpuSpeedCompatible) {
    Write-Host "CPU Speed: $cpuSpeedGHz GHz (✔ Compatible)" -ForegroundColor Green
} else {
    Write-Host "CPU Speed: $cpuSpeedGHz GHz (❌ Not Compatible)" -ForegroundColor Red
}

# Secure Boot Check
if ($secureBootEnabled) {
    Write-Host "Secure Boot Enabled: ✔ Yes" -ForegroundColor Green
} else {
    Write-Host "Secure Boot Enabled: ❌ No" -ForegroundColor Red
}

# TPM 2.0 Check
if ($tpmCompatible) {
    Write-Host "TPM 2.0 Support: ✔ Yes" -ForegroundColor Green
} else {
    Write-Host "TPM 2.0 Support: ❌ No" -ForegroundColor Red
}

# CPU Support Check
if ($cpuSupported) {
    Write-Host "CPU Compatibility: ✔ $cleanCpuName is supported" -ForegroundColor Green
} else {
    Write-Host "CPU Compatibility: ❌ $cleanCpuName is NOT supported" -ForegroundColor Red
}

# Store failed checks
$incompatibilityReasons = @()

if (-not $cpu64Bit) {
    $incompatibilityReasons += "CPU is not 64-bit"
}
if (-not $cpuSpeedCompatible) {
    $incompatibilityReasons += "CPU speed is less than 1 GHz"
}
if (-not $secureBootEnabled) {
    $incompatibilityReasons += "Secure Boot is not enabled"
}
if (-not $tpmCompatible) {
    $incompatibilityReasons += "TPM 2.0 is not supported or not enabled"
}
if (-not $cpuSupported) {
    $incompatibilityReasons += "Unsupported processor: $cleanCpuName"
}

# Final verdict
if ($incompatibilityReasons.Count -gt 0) {
    Write-Host "`n❌ Your System is NOT fully compatible with Windows 11 due to:" -ForegroundColor Yellow
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
    Write-Host "✅ Bypass Applied Successfully. Now Proceed for installation..." -ForegroundColor Green
	$installArgs = "/product server /auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable"
} else {
    Write-Host "`n✅ Your System is fully compatible with Windows 11! Proceed with normal installation." -ForegroundColor Green
	$installArgs = "/auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable"
}

# Start Windows 11 Upgrade
Write-Host "`nStarting Windows 11 upgrade..."
$null = Start-Process -FilePath $setupPath -ArgumentList $installArgs -PassThru

# Path to the setup log file
$logPath = 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log'

# Delete the log file if it exists
if (Test-Path $logPath) {
        $null = Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
}

# Start monitoring loop
Write-Host "Your PC will restart several times. This might take a while." -ForegroundColor Green
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
Write-Host "Unmounting ISO..."

# Unmount the ISO after installation
Dismount-DiskImage -ImagePath $isoPath
Write-Host "✅ Windows 11 upgrade process complete."

Write-Host "Rebooting System..."
#Restart-Computer -Force