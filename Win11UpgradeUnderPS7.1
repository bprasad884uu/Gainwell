# --- PART 1: Check if PowerShell 7.1 is installed ---

# Desired version
$requiredVersion = "7.1.0"
$pwshexePath = "C:\Program Files\PowerShell\$requiredVersion\pwsh.exe"

function Install-PowerShell71 {
    $version = $requiredVersion
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
    $msiName = "PowerShell-$version-win-$arch.msi"
    $downloadUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$version/$msiName"
    $tempPath = "$env:TEMP\$msiName"

    Write-Host "PowerShell 7.1 not found. Installing..."

    # Download using HttpClient
    try {
        if (-not ("System.Net.Http.HttpClient" -as [type])) {
            Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
        }
        $client = [System.Net.Http.HttpClient]::new()
        $response = $client.GetAsync($downloadUrl).Result
        if (-not $response.IsSuccessStatusCode) {
            Write-Host "❌ Failed to download PowerShell MSI." -ForegroundColor Red
            exit 1
        }
        $fs = [System.IO.File]::OpenWrite($tempPath)
        $response.Content.ReadAsStreamAsync().Result.CopyTo($fs)
        $fs.Close()
        $client.Dispose()
        Write-Host "✅ Downloaded PowerShell $version MSI to $tempPath"
    } catch {
        Write-Host "❌ Error during download: $_" -ForegroundColor Red
        exit 1
    }

    # Install silently
    try {
        Write-Host "🛠 Installing PowerShell $version..."
        Start-Process msiexec.exe -Wait -ArgumentList "/i `"$tempPath`" /qn /norestart ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 REGISTER_MANIFEST=1"
        Write-Host "✅ Installation complete."
    } catch {
        Write-Host "❌ Installation failed: $_" -ForegroundColor Red
        exit 1
    }

    # Add pwsh to system PATH if needed
    $pwshDir = [System.IO.Path]::GetDirectoryName($pwshexePath)
    $currentPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    if ($currentPath -notlike "*$pwshDir*") {
        $newPath = "$currentPath;$pwshDir"
        [Environment]::SetEnvironmentVariable("Path", $newPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Host "🔧 Added pwsh to system PATH"
    }

    # Create shim so 'powershell' runs pwsh 7.1
    try {
        $shimPath = "$env:SystemRoot\System32\powershell.cmd"
        Set-Content -Path $shimPath -Value "@echo off`n`"$pwshexePath`" %*" -Force -Encoding ASCII
        Write-Host "🔁 Shim created: 'powershell' now launches pwsh 7.1"
    } catch {
        Write-Host "❌ Failed to create shim: $_" -ForegroundColor Red
    }

    # Cleanup
    Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
    Write-Host "🧹 Deleted MSI installer"

    Write-Host "`n🎉 PowerShell 7.1 installed successfully!"
}

# Check if PowerShell 7.1 exists
if (-not (Test-Path $pwshexePath)) {
    Install-PowerShell71
    Write-Host "Restarting script with PowerShell 7.1..."
    # Relaunch the full script inside pwsh 7.1
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process -FilePath $pwshexePath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Wait
    exit
} else {
    # Check version of existing pwsh to confirm it's 7.1.x
    $versionInfo = & $pwshexePath -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
    if ($versionInfo -notlike "7.1*") {
        Write-Host "PowerShell version is $versionInfo, but 7.1.x is required."
        Install-PowerShell71
        Write-Host "Restarting script with PowerShell 7.1..."
        $scriptPath = $MyInvocation.MyCommand.Path
        Start-Process -FilePath $pwshexePath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Wait
        exit
    }
}

# --- PART 2: Your main script runs below this line inside PowerShell 7.1 ---

# <== Insert your entire Windows 11 upgrade script here ==>

# Example just showing detection (replace with your full script):
Write-Host "Running your main Windows 11 upgrade script in PowerShell 7.1..."

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
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_EnglishInternational_x64.iso?t=e9713b42-b188-4e21-bbab-15f2984ea13c&P1=1748679776&P2=601&P3=2&P4=HIOojbxnysdmUAJrgV6GntXJMwx4De%2bkcDnouTEoAY%2fUG9NZsMNsQ7qagf1XmWCllHyGMD7TDxVijSkoi4NjQ1FaRogKzij4sMT3cVh6P%2b2pdzVAfnGlh4OKjxWMSPYsGo6KYe3i9UeGHrgIf3HtmO%2b%2b%2fyqROEZR8v4EZuszI8GcQwjuk4MopPyw9%2bddVLva3AmI0gs1Jn%2bq0AvzSyC1zMvpsF1MG6%2bBMq1ufgCogVZi36wTuEfDNM%2f7MlZBxganFbCLXVgSTC%2fHy%2fmEIC%2fXwyQyc4ChZez8lFqy9I0owrDTkKd02elNNo5ieuTjQ%2fzre%2fDFZlMvH6ozbTWfAopGUg%3d%3d"
    $destination = "$env:Temp\Win11_24H2_ENGB.iso"
} elseif ($locale -eq "en-US") {
    $isoUrl = "https://software.download.prss.microsoft.com/dbazure/Win11_24H2_English_x64.iso?t=458e6475-663d-49b0-b8ad-3e780082f098&P1=1748679754&P2=601&P3=2&P4=skb9535EwOB%2fjOMSpqClCbZDs5Ac4UJwHrIaDAsJQ3X%2focq55c1jdyIFyrZrZCxMt%2fSBtwBTmdItdiuh47yLgbytwY%2bpJMiq%2fIbQcgV9rWSRMD10XXud%2bWEiCBAIQul9Jmu088NbIG7iAe2wmsu5FaN5GQK%2fjeEUO%2fHQIcNl8vcfOeXmX2gL3CHtVBr63a90KrRed2uI7dCVqeT7Rm5bkFIpS67PDCbGIS7ZflgjGxiMHMSOoeYpSGY2aAxKITvzL5npjsRy0BAax3K9O0LDncmhAI0mVdyWGKJ0X25dgpBbtezI6Q%2fhAWsrtgR9UHxjes5%2fK7X4P%2f3oW2OshOtefQ%3d%3d"
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

$downloadSuccess = $false

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
} finally {
    $httpClient.Dispose()
}

# Final check
if (-not $downloadSuccess) {
    Write-Host "All download methods failed. Please check your internet connection." -ForegroundColor Red
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
        Write-Output "Unmounted: $($iso.ImagePath)"
    } catch {
        Write-Warning "Failed to unmount: $($iso.ImagePath) - $_"
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

Write-Host "Rebooting System..."
#Restart-Computer -Force