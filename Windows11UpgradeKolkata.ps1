# --- Step 0: Detect System Locale ---
$systemLocale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''

# Define network path (source) and mount drive
$sourceFolder = "\\10.131.31.77\Softwares"

# Define source ISO based on system locale (sourceISO defined early to avoid null errors later)
switch ($systemLocale) {
    "en-US" { $sourceISO = Join-Path $sourceFolder "Win11_25H2_ENUS.iso" }
    "en-GB" { $sourceISO = Join-Path $sourceFolder "Win11_25H2_ENGB.iso" }
    default {
        Write-Output "`nNo matching ISO found for system locale: $systemLocale"
        exit 1
    }
}

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

# Define destination folder
$destinationFolder = $TempRoot
$MountDrive = "Y"

# Ensure destination folder exists
if (-not (Test-Path $destinationFolder)) {
    New-Item -Path $destinationFolder -ItemType Directory | Out-Null
}

$destinationISO = Join-Path $destinationFolder (Split-Path $sourceISO -Leaf)

# --- Step 2: Check if file exists and verify integrity ---
$downloadSuccess = $false

if (Test-Path $destinationISO) {
    Write-Host "`nFile already exists: $destinationISO"
    Write-Host "`nChecking file integrity by attempting to mount..."

    try {
        $null = Mount-DiskImage -ImagePath $destinationISO -ErrorAction Stop
        Write-Host "`nISO mounted successfully. File integrity confirmed."
        $null = Dismount-DiskImage -ImagePath $destinationISO
        $downloadSuccess = $true
    } catch {
        Write-Warning "`nFailed to mount ISO. File may be corrupted. Re-copying..."
        Remove-Item $destinationISO -Force -ErrorAction SilentlyContinue
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
        Write-Host "`nAttempting to dismount image mounted at: $devicePath"
        $null = Dismount-DiskImage -DevicePath $devicePath -ErrorAction Stop
        Write-Host "`nSuccessfully dismounted: $devicePath"
    } catch {
        Write-Warning "`nFailed to dismount: $devicePath. Error: $_"
    }
}

# Find Copied ISO File
$isoPath = Get-ChildItem -Path ($TempRoot + '\') -Filter "Win11*.iso" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
if (-not $isoPath -and (Test-Path $destinationISO)) { $isoPath = $destinationISO }

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
    Write-Host "`nSetup file not found. Exiting..." -ForegroundColor Red
    exit
}

# --- Step 5: Windows 11 upgrade (Silent Install) ---
# Get Manufacturer
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
Write-Host "`nDetected System Manufacturer: $manufacturer"

# CPU lists (WhyNotWin11)
$intelListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsIntel.txt"
$amdListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsAMD.txt"
$qualcommListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsQualcomm.txt"

# Get raw CPU name
$cpu = Get-CimInstance -ClassName Win32_Processor
$rawCpuName = $cpu.Name.Trim()

# Extract clean CPU model string (keep original extraction logic)
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
if (-not $cleanCpuName) {
    Write-Host "`nCould not extract a matching CPU model from '$rawCpuName'" -ForegroundColor Yellow
    $cleanCpuName = $rawCpuName
}

# Load System.Net.Http.dll for PowerShell 5.1 if needed
if (-not ("System.Net.Http.HttpClient" -as [type])) { Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue }

# Download CPU lists
try {
    $hc = New-Object System.Net.Http.HttpClient
    $intelList = ($hc.GetStringAsync($intelListUrl).Result -split "`n") | ForEach-Object { $_.Trim() }
    $amdList = ($hc.GetStringAsync($amdListUrl).Result -split "`n") | ForEach-Object { $_.Trim() }
    $qualList = ($hc.GetStringAsync($qualcommListUrl).Result -split "`n") | ForEach-Object { $_.Trim() }
    $hc.Dispose()
} catch {
    Write-Warning "Failed to download processor support lists. Proceeding without list-based CPU check."
    $intelList = @(); $amdList = @(); $qualList = @()
}

# Determine manufacturer and check support
$cpuSupported = $false
switch -Regex ($cpu.Manufacturer) {
    "Intel"    { $cpuSupported = $intelList -contains $cleanCpuName }
    "AMD"      { $cpuSupported = $amdList -contains $cleanCpuName }
    "Qualcomm" { $cpuSupported = $qualList -contains $cleanCpuName }
    default    { Write-Host "`nUnknown manufacturer: $($cpu.Manufacturer)" }
}

# Function to check TPM 2.0
function Check-TPM {
    try {
        $tpm = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
        if ($tpm -and $tpm.SpecVersion) { return $tpm.SpecVersion -match "2.0" }
    } catch {}
    return $false
}

# Check architecture and speed
$cpu64Bit = ($cpu.AddressWidth -eq 64)
$cpuSpeedGHz = [math]::Round(($cpu.MaxClockSpeed / 1000), 2)
$cpuSpeedCompatible = $cpuSpeedGHz -ge 1

# Secure Boot status
function Get-SecureBootStatus {
    try {
        if (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            return [bool](Confirm-SecureBootUEFI)
        } else {
            $msinfo = Get-CimInstance -Namespace root\WMI -Class MS_SystemInformation -ErrorAction SilentlyContinue
            if ($msinfo -and $msinfo.SecureBoot -ne $null) { return [bool]$msinfo.SecureBoot }
            $cs = Get-CimInstance -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($cs -and $cs.SecureBootState -ne $null) { return [bool]$cs.SecureBootState }
        }
    } catch {}
    return $false
}
$secureBootEnabled = Get-SecureBootStatus
$tpmCompatible = Check-TPM

# Display results
Write-Host "`nWindows 11 Compatibility Check" -ForegroundColor Cyan
Write-Host "-----------------------------------"
Write-Host "`nProcessor: $rawCpuName"
Write-Host "`n64-bit CPU: " + (if ($cpu64Bit) { "Yes" } else { "No" })
Write-Host "CPU Speed: $cpuSpeedGHz GHz"
Write-Host "Secure Boot Enabled: " + (if ($secureBootEnabled) { "Yes" } else { "No" })
Write-Host "TPM 2.0 Support: " + (if ($tpmCompatible) { "Yes" } else { "No" })
Write-Host "CPU Support (known-list): " + (if ($cpuSupported) { "Yes" } else { "No" })

# Collect incompatibilities
$incompatibilityReasons = @()
if (-not $cpu64Bit) { $incompatibilityReasons += "CPU is not 64-bit" }
if (-not $cpuSpeedCompatible) { $incompatibilityReasons += "CPU speed is less than 1 GHz" }
if (-not $secureBootEnabled) { $incompatibilityReasons += "Secure Boot is not enabled" }
if (-not $tpmCompatible) { $incompatibilityReasons += "TPM 2.0 is not supported or not enabled" }
if (-not $cpuSupported) { $incompatibilityReasons += "Unsupported processor: $rawCpuName" }

# Define full bypass key set
$allBypassKeys = @(
    @{Path="HKLM:\SYSTEM\Setup\MoSetup"; Name="AllowUpgradesWithUnsupportedTPMOrCPU"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassTPMCheck"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassSecureBootCheck"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassRAMCheck"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassStorageCheck"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassCPUCheck"; Value=1}
)

# Decide which bypasses are required (conservative)
$requiredBypasses = @()
if (-not $tpmCompatible) {
    $requiredBypasses += $allBypassKeys | Where-Object { $_.Name -in @("AllowUpgradesWithUnsupportedTPMOrCPU","BypassTPMCheck") }
}
if (-not $secureBootEnabled) {
    $requiredBypasses += $allBypassKeys | Where-Object { $_.Name -eq "BypassSecureBootCheck" }
}
if (-not $cpu64Bit -or -not $cpuSpeedCompatible -or -not $tpmCompatible) {
    $requiredBypasses += $allBypassKeys | Where-Object { $_.Name -in @("BypassCPUCheck","AllowUpgradesWithUnsupportedTPMOrCPU") }
}
if ($incompatibilityReasons.Count -gt 0) {
    $requiredBypasses += $allBypassKeys | Where-Object { $_.Name -in @("BypassRAMCheck","BypassStorageCheck") }
}
$requiredBypasses = $requiredBypasses | Select-Object -Unique

# Apply required bypasses and track which applied
$appliedBypasses = @()
if ($requiredBypasses.Count -gt 0) {
    Write-Host "`nApplying required registry bypasses..." -ForegroundColor Yellow
    foreach ($b in $requiredBypasses) {
        try {
            New-Item -Path $b.Path -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $b.Path -Name $b.Name -Type DWord -Value $b.Value -Force
            $appliedBypasses += $b.Name
            Write-Host " - Applied $($b.Name) at $($b.Path)"
        } catch {
            Write-Warning "Failed to apply $($b.Name): $_"
        }
    }
} else {
    Write-Host "`nNo bypasses required; system looks compatible." -ForegroundColor Green
}

# Decide whether to use /product server only if ALL bypass keys were applied
$allNames = $allBypassKeys | ForEach-Object { $_.Name } | Sort-Object
$appliedNow = $appliedBypasses | Sort-Object
$useProductServer = $false
if ($allNames -and ($allNames -eq $appliedNow)) {
    $useProductServer = $true
    Write-Host "`nAll bypass keys applied. /product server will be used." -ForegroundColor Cyan
} else {
    Write-Host "`nNot all bypass keys were applied. /product server will NOT be used." -ForegroundColor Cyan
}

# Build installer args conditionally
if ($useProductServer) {
    $installArgs = "/product server /auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable /noreboot"
} else {
    $installArgs = "/auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable /noreboot"
}

# Start Windows 11 Upgrade
Write-Host "`nStarting Windows 11 upgrade..."
try {
    $proc = Start-Process -FilePath $setupPath -ArgumentList $installArgs -PassThru
    Write-Host "Setup started (PID: $($proc.Id))."
} catch {
    Write-Error "Failed to start setup: $_"; exit 1
}

# Path to the setup log file and monitoring
$logPath = 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log'
$setupFolder = 'C:\$WINDOWS.~BT'

if (Test-Path $logPath) { Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue }

function Is-SetupRunning {
    $names = @('setupprep','setuphost','setup')
    foreach ($n in $names) { if (Get-Process -Name $n -ErrorAction SilentlyContinue) { return $true } }
    return $false
}

Write-Host "`nYour PC will restart several times. This might take a while." -ForegroundColor Green
$spinner = ('\','|','/','-'); $spinnerIndex = 0; $currentPercent = 0

while ($true) {
    Start-Sleep -Milliseconds 500
    $setupRunning = Is-SetupRunning
    $folderExists = Test-Path $setupFolder
    $logExists = Test-Path $logPath

    if (-not $logExists -and -not $folderExists -and -not $setupRunning) {
        Write-Host "`nNo setup activity detected. Exiting monitor." -ForegroundColor Yellow
        break
    }

    if ($logExists) {
        try {
            $content = Get-Content $logPath -Tail 300 -ErrorAction SilentlyContinue
            $progressLines = $content | Where-Object { $_ -match "Overall progress: \[(\d+)%\]" }
            if ($progressLines) {
                $lastLine = $progressLines[-1]
                if ($lastLine -match "Overall progress: \[(\d+)%\]") { $currentPercent = [int]$Matches[1] }
            }
        } catch {}
    }

    $spinnerChar = $spinner[$spinnerIndex % $spinner.Length]
    Write-Host -NoNewline "`r$spinnerChar $currentPercent% complete    "
    $spinnerIndex++

    if ($currentPercent -ge 100) {
        Write-Host "`nUpgrade completed! Your PC will restart in a few moments." -ForegroundColor Green
        break
    }
}

# Cleanup: unmount ISO
Write-Host "`nUnmounting ISO..."
try { $null = Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue } catch { Write-Warning "Failed to dismount ISO: $_" }

Write-Host "`nWindows 11 upgrade process finished..."
#Write-Host "`nRebooting System..."
# Restart-Computer -Force
