<## Ensure PowerShell Runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}#>

#Check Registry (Original Install Language)
$locale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''

# Set variables
$fidoUrl = "https://github.com/pbatard/Fido/raw/refs/heads/master/Fido.ps1"
$fidoPath = "$env:TEMP\Fido.ps1"

# Download Fido.ps1 using HttpClient
Add-Type -AssemblyName System.Net.Http
$client = [System.Net.Http.HttpClient]::new()
$response = $client.GetAsync($fidoUrl).Result
if ($response.IsSuccessStatusCode) {
    [System.IO.File]::WriteAllText($fidoPath, $response.Content.ReadAsStringAsync().Result)
    Write-Host "✅ Fido.ps1 downloaded successfully to $fidoPath"
} else {
    Write-Host "❌ Failed to download Fido.ps1. Status Code: $($response.StatusCode)" -ForegroundColor Red
    exit 1
}

# Set locale (manually define for demo or detect dynamically)
#$locale = (Get-Culture).Name

# Map PowerShell DISM language to Fido language codes
switch ($locale) {
    "en-GB" { $fidoLang = "English International" }
    "en-US" { $fidoLang = "English" }
    default {
        Write-Host "Unsupported language: $locale" -ForegroundColor Red
        exit
    }
}

# Build Fido arguments (e.g., Windows 11, version 24H2, English/International, x64)
$fidoArgs = @(
    "-Win", "11",
    "-Rel", "24H2",
    "-Ed", "Pro",
    "-Lang", $fidoLang,
    "-Arch", "x64",
    "-GetUrl"
)

# Run Fido.ps1 and capture output
$isoUrl = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fidoPath @fidoArgs
#$isoUrl = ($downloadOutput | Where-Object { $_ -match '^https:\/\/' }) -split '\s+' | Select-Object -First 1

if (-not $isoUrl) {
    Write-Host "❌ Could not extract download URL from Fido output." -ForegroundColor Red
    exit
}

# Set destination filename
$destination = "$env:TEMP\Win11_24H2_${locale}.iso"
Write-Host "Detected Language: $locale - Downloading ISO..."

<## Set Download URL & Destination Based on Locale
if ($locale -eq "en-GB") { #en-GB 0809
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_EnglishInternational_x64.iso?t=700a06e6-bd9f-4630-a7c2-3020772b9bb2&P1=1746613911&P2=601&P3=2&P4=wuRVz9S73l2SP8KpWuuTpk551hgJVt8z%2fM8jhfCTjuaZbCyDKLYK%2fo9Rq0v9VkQFOk3zaua94Q7Yu1WSRS%2bxxnC737Gs2Tuu585o9IqdSx9vXQeEL6nNemwPZY9pngDY4MNg8S4r1zKAjft82b7rMvuS5TiaWfEiJkSIfWku5EWFWi8bS5ZChYhGZmj5PpUjhwg%2fgAUlAlcXgOXplj2ecRc%2fX6MdsA29iV3%2fMvJiq9i2yW0FOuDRyttHLwsvAibpo9wdfNvIWH3TBZmaWRcYpWl6jBVDRSbB8DB5LvWJR%2bD%2f4tm5avxBOKPUg2v3rowsxK9ql%2bqT1aHQZ4wNllj7rQ%3d%3d"
    Write-Host "Detected Language: English (UK) - Downloading ISO..."
    $destination = "$env:Temp\Win11_24H2_ENGB.iso"
} elseif ($locale -eq "en-US") { #en-US 0409
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_English_x64.iso?t=f3788109-99f8-4851-9bb5-dacbc341f158&P1=1746613933&P2=601&P3=2&P4=Lr0Z2%2bo27MI1YHPK5LIkoapVHp28RSax9Pa5%2bVZOIFsppcC4d%2bQOeKsfqQgv8EYrd7CsQNGol4HXdsAnFHM5G17kVczQ69bubweLgZNS3yUkUZs9%2fWrPnQ8h2z4KETxW6kGx3lroy7mhgz1X9mrhsoUAtl4nVSgb1MActT3AtAnACNHs421CNhN9Zbr0CEfs4XN2S2x%2fSqW8nR9G5V5a17QyZOkMvWt1hb1FF2dJs85z9o35NtFAWY6xda5HDDZLHasfzwteJazvxBpmFuQ3dX8cE0GaMSaChN2pMJFgw8TaGUSZisf9R1hjk8Nzfg7MMlNlWpQ65g5nTLqK4Vb6mw%3d%3d"
    $destination = "$env:Temp\Win11_24H2_ENUS.iso"
    Write-Host "Detected Language: English (US) - Downloading ISO..."
} else {
    Write-Host "Unsupported Language. No ISO available." -ForegroundColor Red
    exit
}#>

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
Get-DiskImage | Where-Object { $_.Mounted } | ForEach-Object { Dismount-DiskImage -ImagePath $_.ImagePath }

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
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassStorageCheck /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f
    Write-Host "✅ Bypass Applied Successfully. Now Proceed for installation..." -ForegroundColor Green
	$installArgs = "/product server /auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable /noreboot"
} else {
    Write-Host "`n✅ Your System is fully compatible with Windows 11! Proceed with normal installation." -ForegroundColor Green
	$installArgs = "/auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable /noreboot"
}

# Start Windows 11 Upgrade
Write-Host "Starting Windows 11 upgrade..."
Start-Process -FilePath $setupPath -ArgumentList $installArgs -Wait

# Unmount ISO
Write-Host "Unmounting ISO..."

# Unmount the ISO after installation
Dismount-DiskImage -ImagePath $isoPath
Write-Host "✅ Windows 11 upgrade process complete."

Write-Host "Rebooting System..."
#Restart-Computer -Force