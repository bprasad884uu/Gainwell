<#
.SYNOPSIS
  Windows 11 All-in-One Debloat / Hardening Script (with Aggressive option)

.DESCRIPTION
  - Cleans temp folders
  - Disables consumer features, activity history, telemetry (incl. tasks)
  - Optional "Aggressive" mode for service trimming
  - Appx debloat (Store bloat)
  - Edge debloat via policy keys
  - GameDVR, Location, Background Apps toggles
  - Hibernation controls + "LaptopMode"
  - Teredo disable / undo
  - PowerShell 7 install/upgrade + Terminal default + Win+X menu
  - Opts out of PowerShell 7 telemetry
  - Disk Cleanup / DISM SxS cleanup (optional)
  - Idempotent and guarded with try/catch

.PARAMETER Aggressive
  Enables aggressive service configuration (still avoids critical services).

.PARAMETER RunDiskCleanup
  Runs CleanMgr and DISM StartComponentCleanup /ResetBase.

.PARAMETER LaptopMode
  Enables hibernation and sets conservative power timeouts (good for laptops).

.PARAMETER DisableRecall
  Disables Windows Recall / AI Data Analysis feature (if present).

.PARAMETER EnableRecall
  Enables Windows Recall / AI Data Analysis feature (if present).

.PARAMETER UndoTeredo
  Re-enable Teredo (undo for Teredo step).

.PARAMETER UndoBackgroundApps
  Re-enable background Store apps (undo for background apps step).

.NOTES
  Test on your machine first. Some changes require sign out or reboot.
#>

[CmdletBinding()]
param(
  [switch]$Aggressive,
  [switch]$RunDiskCleanup,
  [switch]$LaptopMode,
  [switch]$DisableRecall,
  [switch]$EnableRecall,
  [switch]$UndoTeredo,
  [switch]$UndoBackgroundApps,
  [switch]$TrimSSDs
)

# If no parameters provided, set default ones
if ($PSBoundParameters.Count -eq 0) {
    Write-Host "[i] No parameters specified - running with defaults: Aggressive, RunDiskCleanup, LaptopMode, DisableRecall" -ForegroundColor Yellow
    $Aggressive     = $true
    $RunDiskCleanup = $true
    $LaptopMode     = $true
    $DisableRecall  = $true
	$TrimSSDs		= $true
}

# -------------------------
# Helpers
# -------------------------
function Write-OK([string]$msg){ Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info([string]$msg){ Write-Host "[..] $msg" -ForegroundColor Cyan }
function Write-Warn([string]$msg){ Write-Warning $msg }
function Write-Err([string]$msg){ Write-Host "[ERR] $msg" -ForegroundColor Red }

function Ensure-Admin {
  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "Please run this script as Administrator."
    exit 1
  }
}

function Ensure-Key($Path){
  try { if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null } } catch {}
}

function Set-RegValue($Path, $Name, $Value, $Type="DWord"){
  try {
    Ensure-Key $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
  } catch {
    Write-Warn "Failed to set $Path\$Name"
  }
}

function Disable-FullTaskPath {
  param([Parameter(Mandatory)][string]$FullPath)
  try {
    $parts = $FullPath -split '\\'
    if ($parts.Length -lt 2){ return }
    $name = $parts[-1]
    $taskPath = "\" + ($parts[0..($parts.Length-2)] -join '\')
    $t = Get-ScheduledTask -TaskPath $taskPath -TaskName $name -ErrorAction SilentlyContinue
    if ($t){ $t | Disable-ScheduledTask -ErrorAction SilentlyContinue }
  } catch {}
}

function Set-ServiceStartupType {
  param([Parameter(Mandatory)][string]$ServiceName, [Parameter(Mandatory)][ValidateSet('Automatic','AutomaticDelayedStart','Manual','Disabled')] [string]$StartupType)
  try {
    $matches = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $matches){ Write-Warn "Service '$ServiceName' not found."; return }
    foreach($svc in $matches){
      Write-Info "Configuring '$($svc.Name)' => $StartupType"
      if ($StartupType -eq 'AutomaticDelayedStart'){
        sc.exe config $svc.Name start= delayed-auto | Out-Null
      } else {
        sc.exe config $svc.Name start= $StartupType | Out-Null
      }
    }
  } catch {
    Write-Warn "Failed to set $ServiceName startup: $_"
  }
}

# -------------------------
# Start
# -------------------------
Ensure-Admin

# -------------------------
# Delete Temporary Files
# -------------------------

function Show-ProgressBar {
    param (
        [int]$Current,
        [int]$Total,
        [string]$Message = "Cleaning"
    )

    if ($Total -eq 0) { return }

    $percent = [math]::Round(($Current / $Total) * 100)
    $barLength = 50
    $filledLength = [math]::Floor(($percent / 100) * $barLength)
    $bar = '=' * $filledLength + '>' + ' ' * ($barLength - $filledLength)
    Write-Host -NoNewline "`r[$bar] $percent% - $Message" -ForegroundColor Magenta
}

function Report-Drives {
    Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, 
    @{Name='TotalSize';Expression={[math]::Round($_.Size / 1GB, 2)}},
    @{Name='FreeSpace';Expression={[math]::Round($_.FreeSpace / 1GB, 2)}},
    @{Name='UsedSpace';Expression={[math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)}}
}

function Drive-Space {
    Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, 
    @{Name='TotalSize';Expression={[math]::Round($_.Size / 1GB, 2)}},
    @{Name='FreeSpace';Expression={[math]::Round($_.FreeSpace / 1GB, 2)}},
    @{Name='UsedSpace';Expression={[math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)}},
    @{Name='Used%';Expression={[math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1)}}
}

function Format-Size {
    param (
        [Parameter(Mandatory=$true)]
        [long]$size
    )
    
    if ($size -ge 1TB) { return "{0:N2} TB" -f ($size / 1TB) }
    if ($size -ge 1GB) { return "{0:N2} GB" -f ($size / 1GB) }
    if ($size -ge 1MB) { return "{0:N2} MB" -f ($size / 1MB) }
    if ($size -ge 1KB) { return "{0:N2} KB" -f ($size / 1KB) }
    return "$size bytes"
}

function Report-Drive-Space {
    Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $drive = $_
        $usedPercent = [math]::Round((($drive.Size - $drive.FreeSpace) / $drive.Size) * 100, 1)
        $freePercent = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 1)

        if ($usedPercent -lt 80) { $statusTag = "[OK]"; $statusColor = "Green" }
        elseif ($usedPercent -lt 90) { $statusTag = "[WARNING]"; $statusColor = "Yellow" }
        else { $statusTag = "[CRITICAL]"; $statusColor = "Red" }

        Write-Host "`nDeviceID  : $($drive.DeviceID)" -ForegroundColor Cyan
        Write-Host "TotalSize : $(Format-Size $drive.Size)" -ForegroundColor White
        Write-Host "FreeSpace : $(Format-Size $drive.FreeSpace)" -ForegroundColor Green
        Write-Host "UsedSpace : $(Format-Size ($drive.Size - $drive.FreeSpace))" -ForegroundColor Yellow
        Write-Host "Used%     : " -NoNewline; Write-Host "$usedPercent %" -ForegroundColor $statusColor
        Write-Host "Free%     : " -NoNewline; Write-Host "$freePercent %" -ForegroundColor Green
        Write-Host "`n[Status]   : " -NoNewline; Write-Host "$statusTag" -ForegroundColor $statusColor
    }
}

function SSD-Optimize {
    $ssds = Get-PhysicalDisk | Where-Object { $_.MediaType -eq 'SSD' }

    if ($ssds.Count -eq 0) {
        Write-Host "`n[!] No SSD found." -ForegroundColor Red
        return
    }

    Write-Host "`n[+] SSD TRIM Optimization..." -ForegroundColor Cyan

    $totalDisks = $ssds.Count; $index = 0

    foreach ($disk in $ssds) {
        $index++
        Show-ProgressBar -Current $index -Total $totalDisks -Message "Optimizing Disk"
        Write-Host "`nSSD found: $($disk.FriendlyName)" -ForegroundColor Yellow

        $trimStatus = fsutil behavior query DisableDeleteNotify
        if ($trimStatus -notmatch 'DisableDeleteNotify = 0') {
            Write-Host "Enabling TRIM..." -ForegroundColor Cyan
            fsutil behavior set DisableDeleteNotify 0 | Out-Null
            Write-Host "TRIM has been enabled." -ForegroundColor Green
        } else {
            Write-Host "TRIM is already enabled." -ForegroundColor Green
        }

        $diskNumber = (Get-Disk | Where-Object { $_.FriendlyName -eq $disk.FriendlyName }).Number
        foreach ($partition in Get-Partition -DiskNumber $diskNumber) {
            if ($partition.DriveLetter) {
                Write-Host "Performing manual TRIM on drive $($partition.DriveLetter)..." -ForegroundColor Cyan
                Optimize-Volume -DriveLetter $partition.DriveLetter -ReTrim
                Write-Host "`nManual TRIM completed on drive $($partition.DriveLetter)." -ForegroundColor Green
            }
        }
    }

    Write-Host "`nSSD optimization completed." -ForegroundColor Cyan
}

$beforeCleanUp = Report-Drives

function Remove-JunkFiles {
    param([string[]]$Paths, [string]$SectionName)
    $totalFreed = 0; $items = @()

    Write-Host "`n=== [$SectionName] ===" -ForegroundColor Cyan

    foreach ($path in $Paths) {
        if (Test-Path $path) {
            try { $items += Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue } 
            catch { Write-Warning "Access denied: $path" }
        }
    }

    $totalItems = $items.Count; $currentItem = 0

    foreach ($item in $items) {
        $currentItem++
        Show-ProgressBar -Current $currentItem -Total $totalItems -Message "Removing: $SectionName"
        try {
            $size = if (-not $item.PSIsContainer) { $item.Length } else { 0 }
            Remove-Item $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
            $totalFreed += $size
        } catch { Write-Warning "`nCould not delete: $($item.FullName)" }
    }

    $freedMB = [math]::Round($totalFreed / 1MB, 2)
    Write-Host "`n-- Freed $freedMB MB in section '$SectionName'" -ForegroundColor Green

    return $totalFreed
}

Write-Host "`n==> Stopping Windows Update service..." -ForegroundColor Yellow
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service usosvc -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$totalCleaned = 0
$userDirs = Get-ChildItem "C:\Users" -Directory
$totalUserDirs = $userDirs.Count; $currentUserDir = 0

foreach ($user in $userDirs) {
    $currentUserDir++; $userProfile = $user.FullName
    $userPaths = @(
        "$userProfile\AppData\Local\Temp",
        "$userProfile\AppData\Roaming\Microsoft\Windows\Recent",
        "$userProfile\AppData\Local\Microsoft\Windows\Explorer",
        "$userProfile\AppData\Local\Microsoft\Windows\INetCache",
        "$userProfile\AppData\Local\Microsoft\Edge\User Data\Default\Cache",
        "$userProfile\AppData\Local\Google\Chrome\User Data\Default\Cache",
        "$userProfile\AppData\Local\Mozilla\Firefox\Profiles",
        "$userProfile\AppData\Local\D3DSCache"
    )
    $knownAppCaches = @(
        "$userProfile\AppData\Roaming\Microsoft\Teams\Cache",
        "$userProfile\AppData\Roaming\Microsoft\Teams\GPUCache",
        "$userProfile\AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage",
        "$userProfile\AppData\Local\Microsoft\OneDrive\logs",
        "$userProfile\AppData\Local\Adobe\CameraRaw\Cache",
        "$userProfile\AppData\Roaming\Adobe\Common\Media Cache Files",
        "$userProfile\AppData\Roaming\Adobe\Common\Media Cache"
    )
    $allPathsToClean = $userPaths + $knownAppCaches

    Show-ProgressBar -Current $currentUserDir -Total $totalUserDirs -Message "Cleaning User: $userProfile"
    $totalCleaned += Remove-JunkFiles -Paths $allPathsToClean -SectionName "User and App Caches"
}

$systemPaths = @(
    "C:\Windows\Temp",
    "C:\Windows\Logs",
    "C:\Windows\Prefetch",
    "C:\Windows\SoftwareDistribution\Download",
    "C:\Windows\SoftwareDistribution\DataStore",
    "C:\Windows\System32\LogFiles",
    "C:\ProgramData\Microsoft\Windows Defender\Scans\History",
    "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache",
    "C:\Windows\Panther",
    "C:\$WINDOWS.~BT",
    "C:\$Windows.~WS",
    "C:\Windows.old",
    "C:\ProgramData\USOPrivate\UpdateStore",
    "C:\ProgramData\Microsoft\Windows\WER",
    "C:\ProgramData\Microsoft\Diagnosis",
    "C:\Program Files\rempl",
    "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp",
    "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp",
    "C:\Windows\DeliveryOptimization",
    "C:\Windows\Downloaded Program Files",
    "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Projects"
)

$currentSystemPath = 0
foreach ($path in $systemPaths) {
    $currentSystemPath++
    Show-ProgressBar -Current $currentSystemPath -Total $systemPaths.Count -Message "Cleaning System Paths"
    if ($path -eq "C:\Windows.old" -and (Test-Path $path)) {
        try {
            takeown /F $path /A /R /D Y | Out-Null
            icacls $path /grant Administrators:F /T | Out-Null
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        } catch { Write-Host "Failed to reset permissions for $path ($($_.Exception.Message))" -ForegroundColor Red }
    }
    $totalCleaned += Remove-JunkFiles -Paths @($path) -SectionName "System Cleanup"
}

function Clear-RecycleBin {
    $freed = 0; $totalItems = 0; $currentItem = 0
    $drives = Get-PSDrive -PSProvider FileSystem

    foreach ($drive in $drives) {
        $recyclePath = Join-Path $drive.Root '$Recycle.Bin'
        if (Test-Path $recyclePath) { $totalItems += (Get-ChildItem -Path $recyclePath -Recurse -Force -ErrorAction SilentlyContinue).Count }
    }

    foreach ($drive in $drives) {
        $recyclePath = Join-Path $drive.Root '$Recycle.Bin'
        if (Test-Path $recyclePath) {
            foreach ($item in Get-ChildItem -Path $recyclePath -Recurse -Force -ErrorAction SilentlyContinue) {
                try { Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
                $currentItem++
                Show-ProgressBar -Current $currentItem -Total $totalItems -Message "Cleaning Recycle Bin ($currentItem of $totalItems)"
            }
        }
    }

    try { $shell = New-Object -ComObject Shell.Application; $shell.NameSpace(0x0a).Self.InvokeVerb("R&efresh") } catch {}
    return $freed
}

$totalCleaned += Clear-RecycleBin

Write-Host "`n==> Restarting Windows Update service..." -ForegroundColor Yellow
Start-Service wuauserv -ErrorAction SilentlyContinue
Start-Service usosvc -ErrorAction SilentlyContinue

if ($TrimSSDs) { SSD-Optimize }

# -------------------------
# Disable Consumer Features and Activity History
# -------------------------
Write-Info "Disabling consumer features and activity history..."
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
Write-OK "Consumer features and activity history disabled."

# -------------------------
# Disable Telemetry (incl. tasks)
# -------------------------
function Disable-Telemetry {
  Write-Info "Disabling telemetry scheduled tasks..."
  $tasks = @(
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "Microsoft\Windows\Autochk\Proxy",
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "Microsoft\Windows\Feedback\Siuf\DmClient",
    "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
    "Microsoft\Windows\Windows Error Reporting\QueueReporting",
    "Microsoft\Windows\Application Experience\MareBackup",
    "Microsoft\Windows\Application Experience\StartupAppTask",
    "Microsoft\Windows\Application Experience\PcaPatchDbTask",
    "Microsoft\Windows\Maps\MapsUpdateTask"
  )
  foreach($t in $tasks){ Disable-FullTaskPath -FullPath $t }

  Write-Info "Applying telemetry-related registry tweaks..."
  $regs = @(
    @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0; Type="DWord"},
    @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0; Type="DWord"},
    @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="ContentDeliveryAllowed"; Value=0; Type="DWord"},
    @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="OemPreInstalledAppsEnabled"; Value=0; Type="DWord"},
    @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"; Value=0; Type="DWord"},
    @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEverEnabled"; Value=0; Type="DWord"},
    @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"; Value=0; Type="DWord"},
    @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SystemPaneSuggestionsEnabled"; Value=0; Type="DWord"},
    @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name="DisabledByGroupPolicy"; Value=1; Type="DWord"},
    @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name="Disabled"; Value=1; Type="DWord"},
    @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"; Name="DODownloadMode"; Value=0; Type="DWord"},
    @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name="DODownloadMode"; Value=0; Type="DWord"},
    @{ Path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name="fAllowToGetHelp"; Value=0; Type="DWord"},
    @{ Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableTailoredExperiencesWithDiagnosticData"; Value=1; Type="DWord"},
    @{ Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"; Name="EnableFeeds"; Value=0; Type="DWord"}
  )
  foreach($r in $regs){ Set-RegValue $r.Path $r.Name $r.Value $r.Type }

  Write-Info "Extra telemetry/UX hardening..."
  try { bcdedit /set "{current}" bootmenupolicy Legacy | Out-Null } catch {}
  # Remove Edge "Managed by organization"
  try { if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge"){ Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -ErrorAction SilentlyContinue } } catch {}
  # Group svchost by RAM
  try {
    $ramKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $ramKB -Force | Out-Null
  } catch {}
  # Block diagtrack auto-logger
  try {
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    if (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"){ Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl" -Force -ErrorAction SilentlyContinue }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
  } catch {}
  # Defender sample submission -> prompt
  try { Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue | Out-Null } catch {}

  Write-OK "Telemetry disabled."
}
Disable-Telemetry

# -------------------------
# Disable GameDVR
# -------------------------
Write-Info "Disabling GameDVR..."
$gameDVRRegs = @(
  @{ Path = "HKCU:\System\GameConfigStore"; Name = "GameDVR_FSEBehavior"; Value = 2; Type = "DWord" },
  @{ Path = "HKCU:\System\GameConfigStore"; Name = "GameDVR_Enabled"; Value = 0; Type = "DWord" },
  @{ Path = "HKCU:\System\GameConfigStore"; Name = "GameDVR_HonorUserFSEBehaviorMode"; Value = 1; Type = "DWord" },
  @{ Path = "HKCU:\System\GameConfigStore"; Name = "GameDVR_EFSEFeatureFlags"; Value = 0; Type = "DWord" },
  @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name = "AllowGameDVR"; Value = 0; Type = "DWord" }
)
foreach($i in $gameDVRRegs){ Set-RegValue $i.Path $i.Name $i.Value $i.Type }
Write-OK "GameDVR disabled."

# -------------------------
# Location Tracking
# -------------------------
<#Write-Info "Disabling Location Tracking..."
Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny" "String"
Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0
Set-RegValue "HKLM:\SYSTEM\Maps" "AutoUpdateEnabled" 0
Write-OK "Location tracking disabled."#>

# -------------------------
# Disk Cleanup (all drives)
# -------------------------
Write-Info "Running Disk Cleanup and component store cleanup on all drives..."

# Disable low disk space notifications
Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoLowDiskSpaceChecks" 1 "DWord"
Write-Info "Disabled Windows low disk space notifications."

# -------------------------------
# Legacy: cleanmgr.exe
# -------------------------------
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path $_.Root }

foreach ($drive in $drives) {
    try {
        Write-Host "`n[*] Cleaning drive $($drive.Root)" -ForegroundColor Cyan

        # Configure a temporary registry key to store cleanup settings for this drive
        $sageName = "SilentClean_$($drive.Name.TrimEnd(':'))"
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

        # Run cleanmgr silently using /VERYLOWDISK
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/d $($drive.Root.TrimEnd('\')) /VERYLOWDISK /sagerun:$sageName" -Wait -NoNewWindow
    } catch {
        Write-Warning "Failed Disk Cleanup on $($drive.Root): $($_.Exception.Message)"
    }
}

# -------------------------------
# Modern: DISM Component Cleanup
# -------------------------------
try {
    Write-Info "Running DISM Component Cleanup..."
    Start-Process -FilePath "Dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase /NoRestart" -Wait -NoNewWindow
    Write-OK "DISM cleanup completed."
} catch {
    Write-Warning "DISM cleanup failed: $($_.Exception.Message)"
}

Write-OK "`n[*] Full Silent Disk Cleanup finished on all drives."

# -------------------------
# PowerShell 7 Setup and Integration
# -------------------------
Write-Info "Checking PowerShell 7 installation..."
$pwshPath   = "C:\Program Files\PowerShell\7\pwsh.exe"

# --- Get latest release info from GitHub ---
try {
    $releasesJson = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing
    $tag          = $releasesJson.tag_name.TrimStart("v")  # e.g. "7.5.2"
    $targetVer    = [Version]$tag
    $asset        = $releasesJson.assets | Where-Object { $_.name -like "*win-x64.msi" }
    $msiUrl       = $asset.browser_download_url
    $msiFile      = "$env:TEMP\$($asset.name)"
    Write-Info "Latest PowerShell release detected: $targetVer"
} catch {
    Write-Warn "Failed to fetch latest release info from GitHub. Defaulting to 7.5.2."
    $targetVer  = [Version]"7.5.2"
    $msiUrl     = "https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.msi"
    $msiFile    = "$env:TEMP\PowerShell-7.5.2-win-x64.msi"
}

function Get-InstalledPwshVersion {
    param([string]$exePath)
    if (-not (Test-Path $exePath)) { return $null }
    try {
        $out = & $exePath -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
        return [Version]$out.Trim()
    } catch { return $null }
}

$installedVer = Get-InstalledPwshVersion -exePath $pwshPath
if ($installedVer) {
    Write-Info "Detected PowerShell version: $installedVer"
} else {
    Write-Info "PowerShell 7 not detected."
}

if (-not $installedVer -or $installedVer -lt $targetVer) {
    Write-Info "Installing/upgrading PowerShell to version $targetVer..."

    try {
        # --- Formatting functions ---
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

        # --- HttpClient download with progress ---
        if (-not ("System.Net.Http.HttpClient" -as [type])) {
            Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
        }

        $httpClientHandler = New-Object System.Net.Http.HttpClientHandler
        $httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

        Write-Host "`nStarting download of PowerShell $targetVer..."
        $response = $httpClient.GetAsync($msiUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

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
        $fileStream = [System.IO.File]::OpenWrite($msiFile)
        $bufferSize = 10MB
        $buffer = New-Object byte[] ($bufferSize)
        $downloaded = 0
        $startTime = Get-Date

        Write-Host "`nDownloading PowerShell MSI..."
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
        Write-Host "`nDownload Complete: $msiFile"
        $httpClient.Dispose()

        Start-Process "msiexec.exe" -ArgumentList "/i `"$msiFile`" /quiet /norestart" -Wait
        Remove-Item $msiFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warn "Installation failed: $_"
    }
} else {
    Write-OK "PowerShell $installedVer is up to date (>= $targetVer). Skipping install."
}

if (Test-Path $pwshPath) { 
    Write-OK "PowerShell 7 present: $pwshPath" 
} else { 
    Write-Warn "PowerShell 7 not found after install attempt." 
}

# Replace Win+X menu PowerShell links
Write-Info "Updating Win+X menu to use PowerShell 7..."
$winxPath = "$env:LocalAppData\Microsoft\Windows\WinX"
if ((Test-Path $winxPath) -and (Test-Path $pwshPath)) {
    try {
        $shortcuts = Get-ChildItem -Path $winxPath -Recurse -Filter *.lnk
        foreach ($sc in $shortcuts) {
            $wshell = New-Object -ComObject WScript.Shell
            $shortcut = $wshell.CreateShortcut($sc.FullName)
            if ($shortcut.TargetPath -match "powershell.exe") {
                $shortcut.TargetPath = $pwshPath
                $shortcut.IconLocation = "$pwshPath,0"
                $shortcut.Save()
                Write-Info "Updated Win+X shortcut: $($sc.FullName)"
            }
        }
        Write-OK "Win+X menu now launches PowerShell 7 (normal + admin). Sign out/in to see changes."
    } catch { 
        Write-Warn "Failed to update Win+X shortcuts: $_" 
    }
} else { 
    Write-Warn "Win+X path or pwsh.exe missing - skipping." 
}

# PowerShell 7 telemetry opt out
Write-Info "Opting out of PowerShell telemetry..."
try { 
    [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT','1','Machine') 
} catch {}
Write-OK "PowerShell 7 telemetry disabled."

# -------------------------
# Recall / AI Data Analysis
# -------------------------
function Disable-Recall {
  Write-Info "Disabling Windows Recall / AI Data Analysis..."
  Ensure-Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "DisableAIDataAnalysis" 1
  try {
    $feature = (dism /online /Get-Features | Select-String "Recall")
    if ($feature){ DISM /Online /Disable-Feature /FeatureName:Recall /NoRestart | Out-Null } else { Write-Info "Recall feature not detected." }
  } catch {}
  Write-OK "Recall disabled."
}
function Enable-Recall {
  Write-Info "Enabling Windows Recall / AI Data Analysis..."
  try { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -ErrorAction SilentlyContinue } catch {}
  try {
    $feature = (dism /online /Get-Features | Select-String "Recall")
    if ($feature){ DISM /Online /Enable-Feature /FeatureName:Recall /NoRestart | Out-Null } else { Write-Info "Recall feature not detected." }
  } catch {}
  Write-OK "Recall enable attempted."
}
if ($DisableRecall){ Disable-Recall }
if ($EnableRecall){ Enable-Recall }

# -------------------------
# Hibernation Controls
# -------------------------
if ($LaptopMode){
  Write-Info "Enabling Hibernation and configuring laptop defaults..."
  try { Start-Process -FilePath powercfg -ArgumentList "/hibernate on" -NoNewWindow -Wait } catch {}
  Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" "Attributes" 2
  Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\94ac6d29-73ce-41a6-809f-6363ba21b47e" "Attributes" 2
  try {
    Start-Process -FilePath powercfg -ArgumentList "/change standby-timeout-ac 0" -NoNewWindow -Wait
    Start-Process -FilePath powercfg -ArgumentList "/change standby-timeout-dc 60" -NoNewWindow -Wait
    Start-Process -FilePath powercfg -ArgumentList "/change monitor-timeout-ac 20" -NoNewWindow -Wait
    Start-Process -FilePath powercfg -ArgumentList "/change monitor-timeout-dc 10" -NoNewWindow -Wait
  } catch {}
  Write-OK "Hibernation set as default (LaptopMode)."
} else {
  # leave default; if you want to hard-disable hibernation, uncomment below lines
  # Write-Info "Disabling Hibernation..."
  # powercfg.exe /hibernate off | Out-Null
  # Write-OK "Hibernation disabled."
}

# -------------------------
# Disable / Undo Teredo
# -------------------------
<#function Configure-Teredo {
  param([switch]$Undo)
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
  $regName = "DisabledComponents"
  $origVal = 0
  $newVal  = 1
  try {
    if (-not $Undo){
      Write-Info "Disabling Teredo..."
      Ensure-Key $regPath
      Set-RegValue $regPath $regName $newVal
      Start-Process -FilePath "netsh" -ArgumentList "interface teredo set state disabled" -NoNewWindow -Wait
      Write-OK "Teredo disabled."
    } else {
      Write-Info "Restoring Teredo..."
      Ensure-Key $regPath
      Set-RegValue $regPath $regName $origVal
      Start-Process -FilePath "netsh" -ArgumentList "interface teredo set state default" -NoNewWindow -Wait
      Write-OK "Teredo restored."
    }
  } catch { Write-Warn "Teredo configuration failed: $_" }
}
Configure-Teredo -Undo:$UndoTeredo#>

# -------------------------
# Background Apps Disable / Undo
# -------------------------
function Configure-BackgroundApps {
  param([switch]$Undo)
  $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
  $regName = "GlobalUserDisabled"
  $origVal = 0
  $newVal  = 1
  try {
    if (-not $Undo){
      Write-Info "Disabling Background Apps..."
      Ensure-Key $regPath
      Set-RegValue $regPath $regName $newVal
      Write-OK "Background apps disabled."
    } else {
      Write-Info "Restoring Background Apps..."
      Ensure-Key $regPath
      Set-RegValue $regPath $regName $origVal
      Write-OK "Background apps restored."
    }
  } catch { Write-Warn "Background apps step failed: $_" }
}
Configure-BackgroundApps -Undo:$UndoBackgroundApps

# -------------------------
# Services (Full list; Aggressive uses more Manual/Disabled)
# -------------------------
Write-Info "Configuring service startup types (Aggressive=$($Aggressive.IsPresent))..."

# Define your full list (deduped) - defaults balanced for stability
$services = @(
  [PSCustomObject]@{ Name = "AJRouter"; StartupType = if($Aggressive){"Disabled"} else {"Manual"} },
  [PSCustomObject]@{ Name = "ALG"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "AppIDSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "AppMgmt"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "AppReadiness"; StartupType = if($Aggressive){"Manual"} else {"Manual"} },
  [PSCustomObject]@{ Name = "AppVClient"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "AppXSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Appinfo"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "AssignedAccessManagerSvc"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "AudioEndpointBuilder"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "AudioSrv"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "AxInstSV"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "BDESVC"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "BFE"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "BITS"; StartupType = "AutomaticDelayedStart" },
  [PSCustomObject]@{ Name = "BTAGService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "BcastDVRUserService_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "BluetoothUserService_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "BrokerInfrastructure"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "Browser"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CAPI2"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CDPSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CDPUserSvc_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "COMSysApp"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CaptureService_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CertPropSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "ClipSVC"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CloudBackupRestoreSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CloudExperienceHostBroker"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CmService"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "ConsentUxUserSvc_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CoreMessagingRegistrar"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "CredentialEnrollmentManagerUserSvc_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "CryptSvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "CscService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "DPS"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "DcomLaunch"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "DeviceAssociationService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "DeviceInstall"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "DevicePickerUserSvc_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "DevicesFlowUserSvc_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "DevQueryBroker"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Dhcp"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "DiagTrack"; StartupType = if($Aggressive){"Disabled"} else {"Manual"} },
  [PSCustomObject]@{ Name = "DispBrokerDesktopSvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "DisplayEnhancementService"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "DmEnrollmentSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Dnscache"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "DoSvc"; StartupType = if($Aggressive){"Disabled"} else {"Manual"} },
  [PSCustomObject]@{ Name = "Dot3svc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "DsmSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "DsSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "DusmSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "EFS"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "EapHost"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "EntAppSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "EventLog"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "EventSystem"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "FDResPub"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Fax"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "FontCache"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "FrameServer"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "GPSvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "GraphicsPerfSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "HvHost"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "ICSSVC"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "IKEEXT"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "InstallService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "InventorySvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "IpxlatCfgSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "KeyIso"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "KtmRm"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "LxssManager"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "LSM"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "LanmanServer"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "LanmanWorkstation"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "LicenseManager"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "LmHosts"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "MSDTC"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "MSiSCSI"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "MapsBroker"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "MessagingService_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "MsKeyboardFilter"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "NcaSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "NcbService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "NcdAutoSetup"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "NetTcpPortSharing"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "Netlogon"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Netman"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "NgcCtnrSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "NgcSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "NlaSvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "Nsi"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "OneSyncSvc_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "P9RdrService_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "PNRPsvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "PNRPAutoReg"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "PcaSvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "PeerDistSvc"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "PenService_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "PerfHost"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "PhoneSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "PlugPlay"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "PolicyAgent"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Power"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "PrintNotify"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "ProfSvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "PushToInstall"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "QWAVE"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "RasAuto"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "RasMan"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "RemoteAccess"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "RemoteRegistry"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "RmSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "RpcEptMapper"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "RpcLocator"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "RpcSs"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "SCPolicySvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "SNMPTRAP"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "SNMP"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "SSDPSRV"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "SamSs"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "ScDeviceEnum"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Schedule"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "SecurityHealthService"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "SensrSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "SensorDataService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "SensorService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "SessionEnv"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "SgrmBroker"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "SharedAccess"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "ShellHWDetection"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "Spooler"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "SstpSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "StateRepository"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "StorSvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "SysMain"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "SystemEventsBroker"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "TabletInputService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "TapiSrv"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "TermService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Themes"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "TimeBroker"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "TimeBrokerSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "TokenBroker"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "TrkWks"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "TrustedInstaller"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "UI0Detect"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "UdkUserSvc_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "UmRdpService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "UnistoreSvc_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "UsoSvc"; StartupType = "AutomaticDelayedStart" },
  [PSCustomObject]@{ Name = "VacSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "VaultSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "VSS"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "W32Time"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WEPHOSTSVC"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WMPNetworkSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WPDBusEnum"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WSService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WSearch"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "Wcmsvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "WdNisSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WebClient"; StartupType = "Disabled" },
  [PSCustomObject]@{ Name = "Wecsvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WerSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WiaRpc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WinDefend"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "WinHttpAutoProxySvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WinRM"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "Winmgmt"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "WlanSvc"; StartupType = "Automatic" },
  [PSCustomObject]@{ Name = "WpcMonSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WpnService"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WpnUserService_*"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "WwanSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "XblAuthManager"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "XblGameSave"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "XboxGipSvc"; StartupType = "Manual" },
  [PSCustomObject]@{ Name = "XboxNetApiSvc"; StartupType = "Manual" }
)

foreach($svc in $services){ Set-ServiceStartupType -ServiceName $svc.Name -StartupType $svc.StartupType }
Write-OK "Service startup types updated."

# -------------------------
# Appx Debloat (WPFTweaksDeBloat style)
# -------------------------
Write-Info "Removing Microsoft Store bloatware..."
$appxList = @(
  "Microsoft.AppConnector",
  "Microsoft.BingFinance",
  "Microsoft.BingNews",
  "Microsoft.BingSports",
  "Microsoft.BingTranslator",
  "Microsoft.BingFoodAndDrink",
  "Microsoft.BingHealthAndFitness",
  "Microsoft.BingTravel",
  "Microsoft.MinecraftUWP",
  "Microsoft.MicrosoftSolitaireCollection",
  "Microsoft.News",
  "Microsoft.SkypeApp",
  "Microsoft.Wallet",
  "Microsoft.Whiteboard",
  "*EclipseManager*",
  "*ActiproSoftwareLLC*",
  "*Duolingo-LearnLanguagesforFree*",
  "*PandoraMediaInc*",
  "*CandyCrush*",
  "*BubbleWitch3Saga*",
  "*Wunderlist*",
  "*Flipboard*",
  "*Twitter*",
  "*Facebook*",
  "*Royal Revolt*",
  "*Sway*",
  "*Speed Test*",
  "*Viber*",
  "*Netflix*",
  "*LinkedInforWindows*",
  "*HiddenCityMysteryofShadows*",
  "*Hulu*",
  "*HiddenCity*",
  "*Microsoft.Advertising.Xaml*"
)
foreach($pkg in $appxList){
  Write-Info "Removing: $pkg"
  try { Get-AppxPackage -Name $pkg -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue } catch {}
}

<# Clean Teams uninstallers if present
Write-Info "Cleaning Teams uninstall entries..."
try {
  $us = (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty | Where-Object { $_.DisplayName -like '*Teams*' }).UninstallString
  if ($us){
    $us = ($us.Replace('/I', '/uninstall ') + ' /quiet').Replace('  ', ' ')
    $FilePath = ($us.Substring(0, $us.IndexOf('.exe') + 4).Trim())
    $ProcessArgs = ($us.Substring($us.IndexOf('.exe') + 5).Trim().Replace('  ', ' '))
    $proc = Start-Process -FilePath $FilePath -ArgumentList $ProcessArgs -PassThru
    $proc.WaitForExit()
  }
} catch {}#>
Write-OK "Debloat (Store apps) completed."

# -------------------------
# Edge Debloat Tweaks
# -------------------------
Write-Info "Applying Edge debloat policy tweaks..."
$edgeTweaks = @(
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"; Name="CreateDesktopShortcutDefault"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeEnhanceImagesEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PersonalizationReportingEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ShowRecommendationsEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="HideFirstRunExperience"; Value=1 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="UserFeedbackAllowed"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ConfigureDoNotTrack"; Value=1 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="AlternateErrorPagesEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeCollectionsEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeFollowEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeShoppingAssistantEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="MicrosoftEdgeInsiderPromotionEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ShowMicrosoftRewards"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="WebWidgetAllowed"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="DiagnosticData"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="EdgeAssetDeliveryServiceEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="CryptoWalletEnabled"; Value=0 },
  @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="WalletDonationEnabled"; Value=0 }
)
foreach($t in $edgeTweaks){ Set-RegValue $t.Path $t.Name $t.Value }
Write-OK "Edge debloat applied."

# -------------------------
# Clear Run dialog MRU history
# -------------------------
<#$runMRURelativePath = "Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
$hku = "Registry::HKEY_USERS"

# Get ALL subkeys (including system accounts and classes)
$sids = Get-ChildItem $hku

foreach ($sid in $sids) {
    $runMRUPath = Join-Path $sid.PSPath $runMRURelativePath

    if (Test-Path $runMRUPath) {
        try {
            # Remove all values except MRUList
            $values = Get-ItemProperty -Path $runMRUPath | Select-Object -Property * -ExcludeProperty MRUList
            foreach ($property in $values.PSObject.Properties.Name) {
                if ($property -notmatch "^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$") {
                    Remove-ItemProperty -Path $runMRUPath -Name $property -ErrorAction SilentlyContinue
                }
            }

            # Clear MRUList value
            Set-ItemProperty -Path $runMRUPath -Name "MRUList" -Value ""

            Write-Output "Cleared Run MRU history for hive: $($sid.PSChildName)"
        }
        catch {
            Write-Warning "Failed to clear Run MRU for hive: $($sid.PSChildName) - $_"
        }
    }
    else {
        Write-Output "No RunMRU key found for hive: $($sid.PSChildName)"
    }
}
#>
#======================
#Final Result
#======================
$totalMB = [math]::Round($totalCleaned / 1MB, 2)
Write-Host "`n==============================" -ForegroundColor White
    Write-Host " CLEANUP COMPLETE" -ForegroundColor Cyan
    Write-Host " Total disk space freed: $totalMB MB" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor White

if ($totalMB -eq 0) {
    Write-Host "`nNothing significant found to clean." -ForegroundColor DarkYellow
}

$afterCleanup = Drive-Space

# Show the Before and After available space
foreach ($before in $beforeCleanup) {
    $after = $afterCleanup | Where-Object { $_.DeviceID -eq $before.DeviceID }
    if ($after) {
        $beforeFree = [decimal]$before.FreeSpace
        $afterFree  = [decimal]$after.FreeSpace
        $diff       = $afterFree - $beforeFree
        $absDiff    = [math]::Abs($diff)

        $label = if ($diff -lt 0) { "Used" } else { "Freed" }

        if ($absDiff -lt 1) {
            $diffValue = [math]::Round($absDiff * 1024, 1)
            $unit = "MB"
        } else {
            $diffValue = [math]::Round($absDiff, 3)
            $unit = "GB"
        }

        Write-Host "`nDrive $($before.DeviceID):"
        Write-Host " Before Cleanup - Free Space: $beforeFree GB"
        Write-Host " After Cleanup  - Free Space: $afterFree GB"
        Write-Host " Difference     - ${label}: $diffValue $unit`n"
    }
}
# Optional: Summarize drive-reported differences
$sumOfDifferences = 0
foreach ($before in $beforeCleanup) {
    $after = $afterCleanup | Where-Object { $_.DeviceID -eq $before.DeviceID }
    if ($after) {
        $diff = [decimal]$after.FreeSpace - [decimal]$before.FreeSpace
        $sumOfDifferences += $diff * 1024  # Convert GB diff to MB
    }
}

Write-Host "`n------------------------------" -ForegroundColor DarkGray

$sumOfDifferences = [math]::Round($sumOfDifferences, 2)
$avgUsedPercent = ($afterCleanup | Measure-Object -Property 'Used%' -Average).Average
Write-Host "`n[Summary Comparison]" -ForegroundColor White
Write-Host " Reported per-drive freed space : $sumOfDifferences MB" -ForegroundColor Yellow
Write-Host " Total deleted file size        : $totalMB MB" -ForegroundColor Cyan
Write-Host " Difference (if any)            : $([math]::Round($totalMB - $sumOfDifferences, 2)) MB" -ForegroundColor Gray
Write-Host " Avg. Drive Utilization After Cleanup : $([math]::Round($avgUsedPercent, 1))%" -ForegroundColor DarkCyan

Write-Host "`n------------------------------" -ForegroundColor DarkGray
Report-Drive-Space

Write-Host "`n==============================" -ForegroundColor White
Write-Host "`nSystem cleaned" -ForegroundColor DarkYellow
Write-Host "==============================" -ForegroundColor White

Write-OK "All steps completed. A restart is recommended."