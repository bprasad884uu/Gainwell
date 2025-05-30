<## Ensure PowerShell Runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}#>

#Check Registry (Original Install Language)
$locale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''

# Set destination filename
$destination = "$env:TEMP\Win11_24H2_${locale}.iso"
Write-Host "Detected Language: $locale - Downloading ISO..."

# Set Download URL & Destination Based on Locale
if ($locale -eq "en-GB") { #en-GB 0809
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_EnglishInternational_x64.iso?t=e9713b42-b188-4e21-bbab-15f2984ea13c&P1=1748679776&P2=601&P3=2&P4=HIOojbxnysdmUAJrgV6GntXJMwx4De%2bkcDnouTEoAY%2fUG9NZsMNsQ7qagf1XmWCllHyGMD7TDxVijSkoi4NjQ1FaRogKzij4sMT3cVh6P%2b2pdzVAfnGlh4OKjxWMSPYsGo6KYe3i9UeGHrgIf3HtmO%2b%2b%2fyqROEZR8v4EZuszI8GcQwjuk4MopPyw9%2bddVLva3AmI0gs1Jn%2bq0AvzSyC1zMvpsF1MG6%2bBMq1ufgCogVZi36wTuEfDNM%2f7MlZBxganFbCLXVgSTC%2fHy%2fmEIC%2fXwyQyc4ChZez8lFqy9I0owrDTkKd02elNNo5ieuTjQ%2fzre%2fDFZlMvH6ozbTWfAopGUg%3d%3d"
    Write-Host "Detected Language: English (UK) - Downloading ISO..."
    $destination = "$env:Temp\Win11_24H2_ENGB.iso"
} elseif ($locale -eq "en-US") { #en-US 0409
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_English_x64.iso?t=458e6475-663d-49b0-b8ad-3e780082f098&P1=1748679754&P2=601&P3=2&P4=skb9535EwOB%2fjOMSpqClCbZDs5Ac4UJwHrIaDAsJQ3X%2focq55c1jdyIFyrZrZCxMt%2fSBtwBTmdItdiuh47yLgbytwY%2bpJMiq%2fIbQcgV9rWSRMD10XXud%2bWEiCBAIQul9Jmu088NbIG7iAe2wmsu5FaN5GQK%2fjeEUO%2fHQIcNl8vcfOeXmX2gL3CHtVBr63a90KrRed2uI7dCVqeT7Rm5bkFIpS67PDCbGIS7ZflgjGxiMHMSOoeYpSGY2aAxKITvzL5npjsRy0BAax3K9O0LDncmhAI0mVdyWGKJ0X25dgpBbtezI6Q%2fhAWsrtgR9UHxjes5%2fK7X4P%2f3oW2OshOtefQ%3d%3d"
    $destination = "$env:Temp\Win11_24H2_ENUS.iso"
    Write-Host "Detected Language: English (US) - Downloading ISO..."
} else {
    Write-Host "Unsupported Language. No ISO available." -ForegroundColor Red
    exit
}

<# Assign language based on locale
if ($Locale -eq "0809") {
    $Language = "en-GB"
} elseif ($Locale -eq "0409") {
    $Language = "en-US"
} else {
    $Language = "Unknown"
}#>

# --- Step 1: Try HttpClient (Fastest) ---
$downloadSuccess = $false
# Load System.Net.Http.dll for PowerShell 5.1
if (-not ("System.Net.Http.HttpClient" -as [type])) {
    Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
}

# Create HttpClient Instance
$httpClientHandler = New-Object System.Net.Http.HttpClientHandler
$httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

try {
    Write-Host "🚀 Starting download using HttpClient..."

    # Send GET Request
    $response = $httpClient.GetAsync($isoUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

    # Validate Response
    if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
        Write-Host "❌ HttpClient request failed: $($response.StatusCode) ($($response.ReasonPhrase))" -ForegroundColor Red
        exit
    }

    # Get Content Stream
    $stream = $response.Content.ReadAsStreamAsync().Result
    if (-not $stream) {
        Write-Host "❌ Failed to retrieve response stream." -ForegroundColor Red
        exit
    }

    # Get File Size
    $totalSize = $response.Content.Headers.ContentLength
    if (-not $totalSize) {
        Write-Host "⚠ Warning: File size unknown. Assuming large file to prevent errors." -ForegroundColor Yellow
        $totalSize = 1GB
    }

    # Open Output File
    $fileStream = [System.IO.File]::OpenWrite($destination)

    # Set Large Buffer for Fast Download
    $bufferSize = 10MB
    $buffer = New-Object byte[] ($bufferSize)
    $downloaded = 0
    $startTime = Get-Date

    Write-Host "📥 Downloading Windows 11 ISO ($locale)..."
    while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $fileStream.Write($buffer, 0, $bytesRead)
        $downloaded += $bytesRead
        $elapsed = (Get-Date) - $startTime

        # Calculate Speed (MB/s)
        $speed = ($downloaded / $elapsed.TotalSeconds) / 1MB

        # Calculate Progress (%)
        $progress = ($downloaded / $totalSize) * 100

        # ETA Calculation
		$remainingBytes = $totalSize - $downloaded
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

		Write-Host "`r📊 Progress: $([math]::Round($progress,2))% | Downloaded: $([math]::Round($downloaded / 1MB, 2)) MB | ⚡ Speed: $([math]::Round($speed,2)) MB/s | ⏳ ETA: $etaFormatted" -NoNewline

    }

    # Close Streams
    $fileStream.Close()
	$downloadSuccess = $true
    Write-Host "`n✅ Download Complete: $destination"
} catch {
    Write-Host "❌ HttpClient download failed: $_" -ForegroundColor Red
    exit
}

# --- Step 2: Try BITS Transfer ---
if (-not $downloadSuccess) {
    Write-Host "Checking BITS service..."
    $bitsService = Get-Service -Name BITS -ErrorAction SilentlyContinue

    if (-not $bitsService) {
        Write-Host "BITS service is not installed. Using Invoke-WebRequest instead." -ForegroundColor Yellow
    } else {
        if ($bitsService.Status -ne 'Running') {
            Write-Host "Starting BITS service..."
            Start-Service -Name BITS
            Start-Sleep -Seconds 2
            $bitsService = Get-Service -Name BITS
        }

        if ($bitsService.Status -eq 'Running') {
            try {
                Write-Host "📥 Downloading using BITS Transfer..."
                Start-BitsTransfer -Source $isoUrl -Destination $destination -Priority Foreground
                Write-Host "✅ Download completed: $destination" -ForegroundColor Green
                $downloadSuccess = $true
            } catch {
                Write-Host "❌ BITS Transfer failed. Falling back to Invoke-WebRequest..." -ForegroundColor Yellow
            }
        }
    }
}

# --- Step 3: Fallback to Invoke-WebRequest ---
if (-not $downloadSuccess) {
    $maxAttempts = 3
    $attempts = 0
    do {
        try {
            Write-Host "📡 Attempting download via Invoke-WebRequest... (Attempt $($attempts+1)/$maxAttempts)"
            Invoke-WebRequest -Uri $isoUrl -OutFile $destination -ErrorAction Stop
            Write-Host "✅ Download completed: $destination" -ForegroundColor Green
            $downloadSuccess = $true
            break
        } catch {
            Write-Host "❌ Download failed. Retrying..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            $attempts++
        }
    } while ($attempts -lt $maxAttempts)
}

if (-not $downloadSuccess) {
    Write-Host "❌ All download methods failed. Please check your internet connection." -ForegroundColor Red
    exit
}

# --- Step 4: Mount ISO ---
Write-Host "Unmounting existing ISOs..."
# Get all mounted ISO disk images
$mountedISOs = Get-DiskImage | Where-Object { $_.ImagePath -like "*.iso" -and $_.DevicePath }

# Unmount each mounted ISO
foreach ($iso in $mountedISOs) {
    try {
        Dismount-DiskImage -ImagePath $iso.ImagePath
        Write-Output "✅ Unmounted: $($iso.ImagePath)"
    } catch {
        Write-Warning "❌ Failed to unmount: $($iso.ImagePath) - $_"
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
    Write-Host "✅ ISO Mounted Successfully." -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to mount ISO: $_" -ForegroundColor Red
    exit
}

# Get Drive Letter of Mounted ISO
Start-Sleep -Seconds 2 # Allow mounting
$driveLetter = (Get-DiskImage -ImagePath $destination | Get-Volume).DriveLetter
$setupPath = "$driveLetter`:\setup.exe"

if (-not (Test-Path $setupPath)) {
    Write-Host "❌ Setup file not found. Exiting..." -ForegroundColor Red
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

# Extract clean CPU model string (e.g., "Core(TM) i5-1135G7")
$cleanCpuName = if ($rawCpuName -match "Core\(TM\)\s+i[3579]-\S+") {
    $matches[0]
} elseif ($rawCpuName -match "Core\s+i[3579]-\S+") {
    $matches[0] -replace "Core", "Core(TM)" # Normalize format if needed
} else {
    ""
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

# Function to draw a progress bar
function Show-ProgressBar {
    param (
        [int]$Percent
    )
    $width = 50
    $filled = [math]::Round($Percent * $width / 100)
    $empty = $width - $filled
    $bar = ('#' * $filled) + ('-' * $empty)
    Write-Host -NoNewline "`r[$bar] $Percent%" -ForegroundColor Cyan
}

# Wait for the log file to be created (timeout: 2 minutes)
$maxWaitSeconds = 120
$waited = 0
while (-not (Test-Path $logPath) -and $waited -lt $maxWaitSeconds) {
    Start-Sleep -Seconds 1
    $waited++
}
if (-not (Test-Path $logPath)) {
    Write-Host "Log file not found after waiting $maxWaitSeconds seconds: $logPath" -ForegroundColor Red
    exit 1
}

# Start monitoring loop
Write-Host "Your PC will restart several times. This might take a while." -ForegroundColor Green
$lastPercent = -1

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
                    Show-ProgressBar -Percent $currentPercent
                    $lastPercent = $currentPercent
                }

                if ($currentPercent -ge 100) {
                    # Clear progress bar line and write completion message
                    Write-Host "`r" + (' ' * 60) + "`r" -NoNewline
                    Write-Host "Upgrade completed! Your PC will restart in a few moments" -ForegroundColor Green
                    break
                }
            }
        }
    } else {
        Write-Host "Log file not found: $logPath" -ForegroundColor Red
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