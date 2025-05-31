<## Ensure PowerShell Runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}#>

#Check Registry (Original Install Language)
$locale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''

# Set destination filename
$destination = "$env:TEMP\Win11_24H2_${locale}.iso"
switch ($locale) {
    "en-GB" { $languageName = "English (UK)" }
    "en-US" { $languageName = "English (US)" }
    default { $languageName = $locale }
}
Write-Host "Detected Language: $languageName - Downloading ISO..."

# Set Download URL & Destination Based on Locale
if ($locale -eq "en-GB") {
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_EnglishInternational_x64.iso?t=d83a3101-5fe5-4633-910c-36d7a9ac5ff1&P1=1748769023&P2=601&P3=2&P4=AjySopROujziXyzlYQzBFIz97IffedPBjrK8w6HXehPbck0SjEL2BGW6m9kQCIzbf82wtbx6ZZ9m3MzPTQefYkgwsrsnU7Iy%2b46TjSw48IPKA8C%2fgobB1z7Cp22XalTZ9jTDj8cIMvEqcNVtqGuQSDL38x0pKKNP2tNTVzBzev2VelGtfn7M1D5Gf6ozix212cZJjIVe3I1zF%2bKk%2f8MbtNWXniYnXyBxCMbOW9pgOEl4Pj6ZYTdSj7mBx6NFqCiMjRE3e5FV86%2f1wGRRfLRwgzGaeTlyVkJT%2b%2f6PKbO8b6Axrekc2tsZ8r3%2fh3pt5dEJ3Cbm07UDSinjzZF92ef8sw%3d%3d"
    $destination = "$env:Temp\Win11_24H2_ENGB.iso"
} elseif ($locale -eq "en-US") {
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_English_x64.iso?t=32d1e7b6-bf5a-4161-85af-201330b7de0c&P1=1748769000&P2=601&P3=2&P4=J7yyv9HMTd7QbpsEDEj5il8Jc1gyxN5ITJ0eLVGq%2fPn36SDjSis0f9khPRZmIkdua1c9PrmX%2bpi4hiTZRY7UTx5B%2f734hjNOf9X6Y%2bibgCixtXbDALYLafgLRjc%2bYjq%2fxIP468S4DJnulD9hxlpY53GwdDV%2banm%2fNhUTl8ROwIj2gOTjFvGP%2bulAPp8U1MNUO%2br1Ah51Dl3YkHTk7AQrP3NCSQZkjPxXZrY1zV8slixQycwf1M4MWhHHYlCa8CEY%2bktTanOqW5aMb7SvVajueFi%2b%2bsWcOJNA9UyUfx5Q6vHuiIiVlRF8iKzZKUVC9esSCWOq5z3H04XJ7%2fLaWMp2AQ%3d%3d"
    $destination = "$env:Temp\Win11_24H2_ENUS.iso"
} else {
    Write-Host "Unsupported Language. No ISO available." -ForegroundColor Red
    exit
}

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
    if ($null -eq $totalSize) {
        Write-Host "⚠ Warning: File size unknown. Assuming large file to prevent errors." -ForegroundColor Yellow
        $totalSize = 1024 * 1024 * 1024
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
	Write-Host "`n✅ Download Complete: $destination"
	$downloadSuccess = $true
    } catch {
    Write-Host "❌ HttpClient download failed: $_" -ForegroundColor Red
	exit
	}

    finally {
        $httpClient.Dispose()
    }
	
	if (-not $downloadSuccess) {
    Write-Host "❌ All download methods failed. Please check your internet connection." -ForegroundColor Red
    exit
}

# --- Step 2: Mount ISO ---
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

# --- Step 3: Windows 11 upgrade (Silent Install)
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
    Write-Host "`n❌ This system does not meet below Windows 11 requirements:" -ForegroundColor Yellow
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
    Write-Host "`n✅ This system meets all Windows 11 hardware requirements." -ForegroundColor Green
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
        Write-Host "Neither setup folder nor upgrade process found. Exiting..." -ForegroundColor Yellow
		}
    break
	}
    Start-Sleep -Seconds 1
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