<## Ensure PowerShell Runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}#>

# ---------- Config (fill these) ----------
$isoUrl_EN_US  = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_English_x64.iso?t=3ee7ee35-10b2-48ce-a351-236595f2b5ed&P1=1759574708&P2=601&P3=2&P4=WLqJZ3hn2QNQx4rHkPCFINnGDnffLooljCtq9fv3BA8zyTQpWwGd7a3Ob8lk%2batNdISaa%2fKL4cDum%2bBCnTgAHXfN3emOVCwfZm32pfeQdScuOp31%2bb276OnKeIO0gscyNcXM7t8J%2bsV9MdBfETkGiWTAvFlzfz9buRnNYW7EAzSUiL9Yt9egA4RUv29e7DuLt8OmvF5J0b3cgT1NJ6k1P9FcvKwwsyZ4MgVXld8usTHrvZIGUk%2fiEq%2bEFzuk0M%2bEkJsTNUbk03gCpPdOEQ8VUC%2f7Rhm%2fYI4C6gRiv%2fT%2bfd3iuCZowENxdq1SddM80x4bd4Yk41PPp44iNBYioviXBg%3d%3d"
$isoUrl_EN_GB  = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_EnglishInternational_x64.iso?t=95caafc2-e00e-4c59-8743-5e7100d809df&P1=1759574695&P2=601&P3=2&P4=1OCb9b%2bIYanJaBXcyFCdAInlobAb2VIYhjtrNpTCp5JvVwmbzyurV6B4r%2fF6pCogu2nc2ZuBQ0jaT1uFpgeFgkOqwxl3CD2XVPKTR%2fKc7wK0qzRZJP46x5s53PT3UX9ykV5l3yaPuM1RKSueO9vj%2f%2bFnHctjDSpzYHHTg988pRWt1D0l7pTZNccy8SmwpC4BgIQAAkBhmfSdxKqeua10Qi3EZuFm%2fQZ3Xbj8C0pFA9MUzqsk6kAbYoofaX15pmo3TE87O8VsNUdJT1spv94J1kC8EcOW6Fweh57CduOoFVVPqTZLnVW4LGXdpSN8%2f7FLgciV9l%2fMMCHwetsIsoI1KQ%3d%3d"

# Provide either a SHA256 hex string or a URL that returns the hash. Leave empty ("") to skip verification.
$Checksum = ""

# Minimum free space for temp selection (20 GB default)
$MinimumTempBytes = (20 * 1024 * 1024 * 1024)

# ---------- Detect Installed Language ----------
$locale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''
switch ($locale) {
    "en-GB" { $languageName = "English (UK)"; $isoUrl = $isoUrl_EN_GB; $destinationName = "Win11_25H2_ENGB.iso" }
    "en-US" { $languageName = "English (US)"; $isoUrl = $isoUrl_EN_US; $destinationName = "Win11_25H2_ENUS.iso" }
    default { $languageName = $locale; Write-Warning "Unsupported/unknown language ($locale). Defaulting to en-US."; $isoUrl = $isoUrl_EN_US; $destinationName = "Win11_25H2.iso" }
}
Write-Host "Detected Language: $languageName - Selected ISO URL: $($isoUrl -replace '^(https?://).*','$1...')"

# --- Choose Temp location: prefer C: if it has >= MinimumBytes, otherwise find another drive ---
function Select-TempRoot {
    param([long]$MinimumBytes = (20 * 1024 * 1024 * 1024))
    try {
        $envTempRoot = [System.IO.Path]::GetPathRoot($env:TEMP)
        if ($envTempRoot) {
            $deviceId = $envTempRoot.TrimEnd('\')
            $logical = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID = '$deviceId'" -ErrorAction SilentlyContinue
            if ($logical -and $logical.FreeSpace -ge $MinimumBytes) { return $env:TEMP.TrimEnd('\') }
        }
    } catch { }

    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Sort-Object -Property DeviceID
    foreach ($d in $drives) {
        if ($d.FreeSpace -ge $MinimumBytes) {
            $root = "$($d.DeviceID)\"
            $candidateTemp = Join-Path -Path $root -ChildPath "Temp"
            try {
                if (-not (Test-Path $candidateTemp)) { New-Item -Path $candidateTemp -ItemType Directory -Force | Out-Null }
                $testFile = Join-Path $candidateTemp ".__writetest.tmp"
                Set-Content -Path $testFile -Value "ok" -ErrorAction Stop
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                return $candidateTemp.TrimEnd('\')
            } catch { continue }
        }
    }
    return $env:TEMP.TrimEnd('\')
}

$TempRoot = Select-TempRoot -MinimumBytes $MinimumTempBytes
if ($TempRoot -match "^[A-Za-z]:$") {
    $TempRoot = Join-Path $TempRoot "Temp"
    if (-not (Test-Path $TempRoot)) { New-Item -Path $TempRoot -ItemType Directory -Force | Out-Null }
}
Write-Host "Using temp root: $TempRoot"
$destination = Join-Path -Path $TempRoot -ChildPath $destinationName

# ---------- Helpers ----------
function Format-Size { param([long]$bytes)
    if ($bytes -ge 1GB) { "{0:N2} GB" -f ($bytes / 1GB) }
    elseif ($bytes -ge 1MB) { "{0:N2} MB" -f ($bytes / 1MB) }
    elseif ($bytes -ge 1KB) { "{0:N2} KB" -f ($bytes / 1KB) } else { "$bytes B" }
}
function Format-Speed { param([double]$bytesPerSecond)
    if ($bytesPerSecond -ge 1GB) { "{0:N2} GB/s" -f ($bytesPerSecond / 1GB) }
    elseif ($bytesPerSecond -ge 1MB) { "{0:N2} MB/s" -f ($bytesPerSecond / 1MB) }
    elseif ($bytesPerSecond -ge 1KB) { "{0:N2} KB/s" -f ($bytesPerSecond / 1KB) } else { "{0:N2} B/s" -f $bytesPerSecond }
}
function Format-ETA { param([double]$seconds)
    if ($seconds -lt 0 -or [double]::IsNaN($seconds)) { return "Unknown" }
    $s = [math]::Round($seconds)
    $h = [math]::Floor($s / 3600); $m = [math]::Floor(($s % 3600) / 60); $sec = $s % 60
    $parts = @(); if ($h -gt 0) { $parts += "${h}h" }; if ($m -gt 0) { $parts += "${m}m" }; $parts += "${sec}s"
    return ($parts -join ' ')
}

# ---------- SHA256 helpers ----------
function Resolve-ChecksumString { param($checksumOrUrl)
    if (-not $checksumOrUrl -or $checksumOrUrl.Trim() -eq "") { return $null }
    if ($checksumOrUrl -match '^https?://') {
        try {
            if (-not ("System.Net.Http.HttpClient" -as [type])) { Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue }
            $hc = New-Object System.Net.Http.HttpClient
            $txt = $hc.GetStringAsync($checksumOrUrl).Result
            $hc.Dispose()
            if ($txt) { return ($txt.Trim() -split '\s+')[0].Trim() }
        } catch { Write-Warning "Failed to fetch checksum from URL: $_"; return $null }
    } else { return $checksumOrUrl.Trim() }
    return $null
}
function Verify-FileSHA256 { param($filePath, $expectedHex)
    if (-not (Test-Path $filePath)) { throw "File not found: $filePath" }
    if (-not $expectedHex) { Write-Host "No checksum supplied; skipping verification."; return $true }
    Write-Host "Verifying SHA256..."
    $hash = Get-FileHash -Path $filePath -Algorithm SHA256
    $computed = $hash.Hash.ToLowerInvariant(); $expected = $expectedHex.Trim().ToLowerInvariant()
    if ($computed -eq $expected) { Write-Host "SHA256 verification passed."; return $true } else { Write-Warning "SHA256 mismatch! Expected: $expected`nActual:   $computed"; return $false }
}

# ---------- Download with resume support (ETA aware) ----------
function Download-WithResume { param([Parameter(Mandatory=$true)][string]$Url, [Parameter(Mandatory=$true)][string]$OutFile)
    if (-not ("System.Net.Http.HttpClient" -as [type])) { Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue }
    $start = 0
    if (Test-Path $OutFile) { try { $start = (Get-Item $OutFile).Length } catch { $start = 0 } if ($start -gt 0) { Write-Host "Partial file detected. Size: $(Format-Size $start). Attempting resume..." } }
    $client = New-Object System.Net.Http.HttpClient
    try {
        $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
        if ($start -gt 0) { $request.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($start, $null) }
        $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

        if ($response.StatusCode -eq [System.Net.HttpStatusCode]::OK -and $start -gt 0) {
            Write-Warning "Server did not return Partial Content. Restarting full download (overwriting partial file)."
            try { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue } catch {}
            $start = 0; $response.Dispose()
            $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
            $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) { throw "Download failed: $($response.StatusCode)" }
        } elseif ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK -and $response.StatusCode -ne [System.Net.HttpStatusCode]::PartialContent) {
            throw "Download failed: $($response.StatusCode) $($response.ReasonPhrase)"
        }

        $content = $response.Content
        $remoteLength = $content.Headers.ContentLength
        $totalLength = if ($remoteLength -ne $null) { $start + [long]$remoteLength } else { -1 }

        if ($start -eq 0) { $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None) }
        else { $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None); $fs.Seek($start, 'Begin') | Out-Null }

        $stream = $content.ReadAsStreamAsync().Result
        $bufferSize = 10 * 1024 * 1024; $buffer = New-Object byte[] $bufferSize
        $downloadedThisSession = 0; $sessionStart = Get-Date

        while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fs.Write($buffer, 0, $bytesRead)
            $downloadedThisSession += $bytesRead
            $downloadedTotal = $start + $downloadedThisSession
            $elapsed = (Get-Date) - $sessionStart
            $speed = if ($elapsed.TotalSeconds -gt 0) { $downloadedThisSession / $elapsed.TotalSeconds } else { 0 }

            if ($totalLength -gt 0 -and $speed -gt 0) {
                $remaining = $totalLength - $downloadedTotal
                $etaSeconds = $remaining / $speed
                $progress = ($downloadedTotal / $totalLength) * 100
                $etaFormatted = Format-ETA $etaSeconds
                Write-Host -NoNewline "`rDownloaded: $(Format-Size $downloadedTotal) / $(Format-Size $totalLength) ($([math]::Round($progress,2))%) | Speed: $(Format-Speed $speed) | ETA: $etaFormatted   "
            } else {
                $etaFormatted = "Unknown"
                Write-Host -NoNewline "`rDownloaded: $(Format-Size $downloadedTotal) | Speed: $(Format-Speed $speed) | ETA: $etaFormatted   "
            }
        }
        Write-Host "`nDownload finished: $OutFile"
        $stream.Close(); $stream.Dispose(); $fs.Close(); $fs.Dispose(); $response.Dispose()
    } catch { throw "Download error: $_" } finally { if ($client) { $client.Dispose() } }
}

# ---------- Step 0: If file exists, try mount to verify; otherwise download with resume & verify ----------
$downloadSuccess = $false
if (Test-Path $destination) {
    Write-Host "`nFile already exists: $destination"
    Write-Host "Attempting to mount to verify integrity..."
    try {
        $img = Mount-DiskImage -ImagePath $destination -ErrorAction Stop -PassThru
        Dismount-DiskImage -ImagePath $destination -ErrorAction SilentlyContinue
        Write-Host "ISO mounted and dismounted successfully. Integrity OK."
        $downloadSuccess = $true
    } catch {
        Write-Warning "Existing ISO failed to mount. Will re-download/resume."
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
    }
}

if (-not $downloadSuccess) {
    try {
        Write-Host "`nStarting download (with resume support) to: $destination"
        Download-WithResume -Url $isoUrl -OutFile $destination

        $expected = Resolve-ChecksumString -checksumOrUrl $Checksum
        if ($expected) {
            $ok = Verify-FileSHA256 -filePath $destination -expectedHex $expected
            if (-not $ok) {
                Write-Warning "Checksum verification failed. Removing file and aborting."
                Remove-Item $destination -Force -ErrorAction SilentlyContinue
                throw "Checksum mismatch"
            }
        } else {
            Write-Host "No checksum configured; skipping SHA256 verification."
        }
    } catch {
        Write-Error "Download/verify flow failed: $_"
        exit 1
    }
}

# ---------- Step 2: Mount ISO (clean unmount first) ----------
Write-Host "`nUnmounting any ISO images previously mounted..."
try {
    $mounted = Get-DiskImage | Where-Object { $_.ImagePath -ne $null }
    foreach ($mi in $mounted) { try { Dismount-DiskImage -ImagePath $mi.ImagePath -ErrorAction SilentlyContinue } catch {} }
} catch {}

$isoPath = Get-ChildItem -Path ($TempRoot + '\') -Filter "Win11*.iso" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
if (-not $isoPath -and (Test-Path $destination)) { $isoPath = $destination }
if (-not $isoPath) { Write-Host "`nNo ISO file found in Temp Folder ($TempRoot)." -ForegroundColor Red; exit 1 }

Write-Host "`nISO found: $isoPath"
try {
    $mount = Mount-DiskImage -ImagePath $isoPath -ErrorAction Stop -PassThru
    Start-Sleep -Seconds 2
    $vol = Get-DiskImage -ImagePath $isoPath | Get-Volume -ErrorAction SilentlyContinue
    if ($vol -and $vol.DriveLetter) {
        $driveLetter = $vol.DriveLetter
        Write-Host "Mounted at $driveLetter`:"
    } else { Write-Warning "Mounted but couldn't detect drive letter." }
} catch {
    Write-Error "Failed to mount ISO: $_"; exit 1
}

$setupPath = "$driveLetter`:\setup.exe"
if (-not (Test-Path $setupPath)) { Write-Error "setup.exe not found on ISO. Exiting."; exit 1 }

# ---------- Step 3: Windows 11 upgrade (Silent Install) ----------
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
try { Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue } catch { Write-Warning "Failed to dismount ISO: $_" }

Write-Host "`nWindows 11 upgrade process finished..."
#Write-Host "`nRebooting System..."
# Restart-Computer -Force
