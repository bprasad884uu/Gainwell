# Detect Installed Language
$locale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''

# Set ISO URL and Destination
switch ($locale) {
    "en-GB" {
        $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_EnglishInternational_x64.iso?t=d83a3101-5fe5-4633-910c-36d7a9ac5ff1&P1=1748769023&P2=601&P3=2&P4=AjySopROujziXyzlYQzBFIz97IffedPBjrK8w6HXehPbck0SjEL2BGW6m9kQCIzbf82wtbx6ZZ9m3MzPTQefYkgwsrsnU7Iy%2b46TjSw48IPKA8C%2fgobB1z7Cp22XalTZ9jTDj8cIMvEqcNVtqGuQSDL38x0pKKNP2tNTVzBzev2VelGtfn7M1D5Gf6ozix212cZJjIVe3I1zF%2bKk%2f8MbtNWXniYnXyBxCMbOW9pgOEl4Pj6ZYTdSj7mBx6NFqCiMjRE3e5FV86%2f1wGRRfLRwgzGaeTlyVkJT%2b%2f6PKbO8b6Axrekc2tsZ8r3%2fh3pt5dEJ3Cbm07UDSinjzZF92ef8sw%3d%3d"
        $destination = "$env:TEMP\Win11_24H2_ENGB.iso"
        $languageName = "English (UK)"
    }
    "en-US" {
        $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_English_x64.iso?t=32d1e7b6-bf5a-4161-85af-201330b7de0c&P1=1748769000&P2=601&P3=2&P4=J7yyv9HMTd7QbpsEDEj5il8Jc1gyxN5ITJ0eLVGq%2fPn36SDjSis0f9khPRZmIkdua1c9PrmX%2bpi4hiTZRY7UTx5B%2f734hjNOf9X6Y%2bibgCixtXbDALYLafgLRjc%2bYjq%2fxIP468S4DJnulD9hxlpY53GwdDV%2banm%2fNhUTl8ROwIj2gOTjFvGP%2bulAPp8U1MNUO%2br1Ah51Dl3YkHTk7AQrP3NCSQZkjPxXZrY1zV8slixQycwf1M4MWhHHYlCa8CEY%2bktTanOqW5aMb7SvVajueFi%2b%2bsWcOJNA9UyUfx5Q6vHuiIiVlRF8iKzZKUVC9esSCWOq5z3H04XJ7%2fLaWMp2AQ%3d%3d"
        $destination = "$env:TEMP\Win11_24H2_ENUS.iso"
        $languageName = "English (US)"
    }
    default {
        Write-Host "Unsupported Language: $locale. No ISO available." -ForegroundColor Red
        exit
    }
}

Write-Host "Detected Language: $languageName - Downloading ISO..."

# Start Download with Progress
$downloadSuccess = $false
$webRequest = [System.Net.HttpWebRequest]::Create($isoUrl)
$webRequest.Method = "GET"
$response = $webRequest.GetResponse()
$totalBytes = $response.ContentLength

# Convert total file size to readable format
$totalSizeMB = $totalBytes / 1MB
$totalSizeGB = $totalSizeMB / 1024
$isoSizeFormatted = if ($totalSizeGB -ge 1) { "{0:N2} GB" -f $totalSizeGB } else { "{0:N2} MB" -f $totalSizeMB }

$readStream = $response.GetResponseStream()
$writeStream = [System.IO.File]::OpenWrite($destination)

$buffer = New-Object byte[] 8192
$totalRead = 0
$startTime = Get-Date

do {
    $read = $readStream.Read($buffer, 0, $buffer.Length)
    if ($read -gt 0) {
        $writeStream.Write($buffer, 0, $read)
        $totalRead += $read

        # Calculate download speed
        $elapsed = (Get-Date) - $startTime
        $elapsedSeconds = [Math]::Max($elapsed.TotalSeconds, 1)
        $speed = $totalRead / 1MB / $elapsedSeconds
        $percent = ($totalRead / $totalBytes) * 100
        if ($totalRead -ge 1TB) {
			$downloadedFormatted = "{0:N2} TB" -f ($totalRead / 1TB)
		} elseif ($totalRead -ge 1GB) {
			$downloadedFormatted = "{0:N2} GB" -f ($totalRead / 1GB)
		} elseif ($totalRead -ge 1MB) {
			$downloadedFormatted = "{0:N2} MB" -f ($totalRead / 1MB)
		} else {
			$downloadedFormatted = "{0:N2} KB" -f ($totalRead / 1KB)
		}

        # Dynamically adjust speed display
        if ($speed -ge 1024) {
            $speedFormatted = "{0:N2} GB/s" -f ($speed / 1024)
        } elseif ($speed -ge 1) {
            $speedFormatted = "{0:N2} MB/s" -f $speed
        } else {
            $speedFormatted = "{0:N2} KB/s" -f ($speed * 1024)
        }

        # ETA Calculation
        $remainingBytes = $totalBytes - $totalRead
        $etaSeconds = if ($speed -gt 0) { [math]::Round($remainingBytes / ($speed * 1MB), 2) } else { "Calculating..." }

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

        Write-Host ("`rFile Size: {0} | Downloaded: {1} | Speed: {2} | ETA: {3}" -f $isoSizeFormatted, $downloadedFormatted, $speedFormatted, $etaFormatted) -NoNewline
    }
} while ($read -gt 0)

$writeStream.Close()
$readStream.Close()
$response.Close()

Write-Host "`nDownload complete! File saved to: $destination"
$downloadSuccess = $true

if (-not $downloadSuccess) {
    Write-Host "❌ ISO download failed." -ForegroundColor Red
}

# --- Step 2: Mount ISO ---
Write-Host "Unmounting existing ISOs..."
# Get all volumes that are mounted from ISO files
$volumes = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }

foreach ($volume in $volumes) {
    try {
        $devicePath = "\\.\$($volume.DriveLetter):"
        $image = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_DiskDrive | Where-Object {
            $_.DeviceID -like "*$($volume.DriveLetter)*"
        }

        # Try to dismount using the drive letter
        Write-Host "Attempting to dismount image mounted at: $devicePath"
        Dismount-DiskImage -DevicePath $devicePath -ErrorAction Stop
        Write-Host "Successfully dismounted: $devicePath"
    } catch {
        Write-Warning "Failed to dismount: $devicePath. Error: $_"
    }
}

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
    Mount-DiskImage -ImagePath $destination -ErrorAction Stop
    Write-Host "ISO Mounted Successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to mount ISO: $_" -ForegroundColor Red
    exit
}

# Get Drive Letter of Mounted ISO
Start-Sleep -Seconds 2 # Allow mounting
$driveLetter = (Get-DiskImage -ImagePath $destination | Get-Volume).DriveLetter
$setupPath = "$driveLetter`:\setup.exe"

if (-not (Test-Path $setupPath)) {
    Write-Host "Setup file not found. Exiting..." -ForegroundColor Red
    exit
}

# --- Step 3: Windows 11 upgrade (Silent Install)
# Get Manufacturer
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
Write-Host "Detected System Manufacturer: $manufacturer"

# CPU Compatibility List URLs
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

if (-not $cleanCpuName) {
    Write-Host "Warning: Could not extract a matching CPU model from '$rawCpuName'" -ForegroundColor Yellow
    return
}

# Load System.Net.Http.dll for PowerShell 5.1
if (-not ("System.Net.Http.HttpClient" -as [type])) {
    Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
}
Add-Type -AssemblyName "System.Net.Http"

$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

# Download CPU lists
try {
    $intelList = $httpClient.GetStringAsync($intelListUrl).Result
    $amdList = $httpClient.GetStringAsync($amdListUrl).Result
    $qualcommList = $httpClient.GetStringAsync($qualcommListUrl).Result
} catch {
    Write-Host "Warning: Failed to download processor support lists."
    return
}

$intelList = $intelList -split "`n" | ForEach-Object { $_.Trim() }
$amdList = $amdList -split "`n" | ForEach-Object { $_.Trim() }
$qualcommList = $qualcommList -split "`n" | ForEach-Object { $_.Trim() }

# Determine manufacturer and check support
$cpuSupported = $false
switch -Regex ($cpu.Manufacturer) {
    "Intel"    { $cpuSupported = $intelList -contains $cleanCpuName }
    "AMD"      { $cpuSupported = $amdList -contains $cleanCpuName }
    "Qualcomm" { $cpuSupported = $qualcommList -contains $cleanCpuName }
    default    { Write-Host "Unknown manufacturer: $($cpu.Manufacturer)" }
}

# Function to check TPM 2.0
function Check-TPM {
    $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
    return $tpm.SpecVersion -match "2.0"
}

# Check CPU Architecture
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
Write-Host "`nWindows 11 Compatibility Check"
Write-Host "-----------------------------------"
Write-Host "Processor: $rawCpuName"

if ($cpu64Bit) {
    Write-Host "64-bit CPU: Compatible" -ForegroundColor Green
} else {
    Write-Host "64-bit CPU: Not Compatible" -ForegroundColor Red
}

if ($cpuSpeedCompatible) {
    Write-Host "CPU Speed: $cpuSpeedGHz GHz (Compatible)" -ForegroundColor Green
} else {
    Write-Host "CPU Speed: $cpuSpeedGHz GHz (Not Compatible)" -ForegroundColor Red
}

if ($secureBootEnabled) {
    Write-Host "Secure Boot Enabled: Yes" -ForegroundColor Green
} else {
    Write-Host "Secure Boot Enabled: No" -ForegroundColor Red
}

if ($tpmCompatible) {
    Write-Host "TPM 2.0 Support: Yes" -ForegroundColor Green
} else {
    Write-Host "TPM 2.0 Support: No" -ForegroundColor Red
}

if ($cpuSupported) {
    Write-Host "CPU Compatibility: $cleanCpuName is supported" -ForegroundColor Green
} else {
    Write-Host "CPU Compatibility: $cleanCpuName is NOT supported" -ForegroundColor Red
}

# Incompatibility reasons
$incompatibilityReasons = @()
if (-not $cpu64Bit) { $incompatibilityReasons += "CPU is not 64-bit" }
if (-not $cpuSpeedCompatible) { $incompatibilityReasons += "CPU speed is less than 1 GHz" }
if (-not $secureBootEnabled) { $incompatibilityReasons += "Secure Boot is not enabled" }
if (-not $tpmCompatible) { $incompatibilityReasons += "TPM 2.0 is not supported or not enabled" }
if (-not $cpuSupported) { $incompatibilityReasons += "Unsupported processor: $cleanCpuName" }

if ($incompatibilityReasons.Count -gt 0) {
    Write-Host "`nSystem is NOT fully compatible with Windows 11 due to:" -ForegroundColor Yellow
    foreach ($reason in $incompatibilityReasons) {
        Write-Host " - $reason" -ForegroundColor Red
    }

    Write-Host "`nApplying registry bypass for compatibility..."
    $null = reg add "HKLM\SYSTEM\Setup\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 1 /f
    $null = reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassStorageCheck /t REG_DWORD /d 1 /f
    $null = reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f
    $installArgs = "/product server /auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable"
	Write-Host "Bypass Applied Successfully. Now Proceed for installation..." -ForegroundColor Green
} else {
    Write-Host "`nSystem is fully compatible with Windows 11." -ForegroundColor Green
    $installArgs = "/auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable"
}

# Start Windows 11 Upgrade
Write-Host "`nStarting Windows 11 upgrade..."
$null = Start-Process -FilePath $setupPath -ArgumentList $installArgs -PassThru

# Setup log monitoring
$logPath = 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log'
$setupFolder = 'C:\$WINDOWS.~BT'

if (Test-Path $logPath) {
    $null = Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
}

function Is-SetupRunning {
    return (Get-Process -Name 'setupprep','SetupHost' -ErrorAction SilentlyContinue).Count -gt 0
}

while ($true) {
    $folderExists = Test-Path $setupFolder
    $logExists = Test-Path $logPath
    $setupRunning = Is-SetupRunning

    if ($logExists -or (-not $folderExists -and -not $setupRunning)) {
        if (-not $folderExists -and -not $setupRunning) {
            Write-Host "No setup folder or upgrade process found. Exiting..." -ForegroundColor Yellow
        }
        break
    }
    Start-Sleep -Seconds 1
}

Write-Host "Your PC will restart several times. This might take a while." -ForegroundColor Green

$lastPercent = -1
Write-Host -NoNewline "`r0% complete     " -ForegroundColor Cyan

while ($true) {
    Start-Sleep -Seconds 1
    if (Test-Path $logPath) {
        $content = Get-Content $logPath -Tail 200
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
                    Write-Host "`r`nUpgrade completed! Your PC will restart in a few moments" -ForegroundColor Green
                    break
                }
            }
        }
    } else {
        Write-Host "`rWindows 11 installation failed. Try restarting the upgrade." -ForegroundColor Red
        break
    }
}

# Unmount ISO
Write-Host "Unmounting ISO..."

# Unmount the ISO after installation
Dismount-DiskImage -ImagePath $isoPath
Write-Host "✅ Windows 11 upgrade process complete."
