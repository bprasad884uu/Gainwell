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

# -------------------------
# Functions
# -------------------------

function Show-Progress {
    param([int]$Current, [int]$Total, [string]$Message)
    $percent = if ($Total -gt 0) { [math]::Round(($Current / $Total) * 100, 0) } else { 100 }
    Write-Progress -Activity "Deep Disk Cleanup" -Status $Message -PercentComplete $percent
}

function Drive-Space {
    Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, 
        @{Name='TotalSize';Expression={[math]::Round($_.Size / 1GB, 2)}},
        @{Name='FreeSpace';Expression={[math]::Round($_.FreeSpace / 1GB, 2)}},
        @{Name='UsedSpace';Expression={[math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)}},
        @{Name='Used%';Expression={[math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1)}}
}

function Format-Size {
    param([long]$size)
    if ($size -ge 1TB) { return "{0:N2} TB" -f ($size / 1TB) }
    if ($size -ge 1GB) { return "{0:N2} GB" -f ($size / 1GB) }
    if ($size -ge 1MB) { return "{0:N2} MB" -f ($size / 1MB) }
    if ($size -ge 1KB) { return "{0:N2} KB" -f ($size / 1KB) }
    return "$size bytes"
}

function Remove-JunkFiles {
    param([string[]]$Paths, [string]$SectionName)
    $totalFreed = 0
    $items = @()
    foreach ($path in $Paths) { if (Test-Path $path) { $items += Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue } }
    $totalItems = $items.Count
    $currentItem = 0

    foreach ($item in $items) {
        $currentItem++
        Show-Progress -Current $currentItem -Total $totalItems -Message "Removing: $SectionName"
        try {
            if (-not $item.PSIsContainer) { $size = $item.Length } else { $size = 0 }
            Remove-Item $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
            $totalFreed += $size
        } catch {}
    }
    return $totalFreed
}

function Clear-RecycleBin {
    $freed = 0
    $drives = Get-PSDrive -PSProvider FileSystem
    foreach ($drive in $drives) {
        $recyclePath = Join-Path $drive.Root '$Recycle.Bin'
        if (Test-Path $recyclePath) {
            $items = Get-ChildItem -Path $recyclePath -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                try { Remove-Item $item.FullName -Recurse -Force -ErrorAction SilentlyContinue; if (-not $item.PSIsContainer) { $freed += $item.Length } } catch {}
            }
        }
    }
    return $freed
}

function SSD-Optimize {
    $ssds = Get-PhysicalDisk | Where-Object { $_.MediaType -eq 'SSD' }
    foreach ($disk in $ssds) {
        $diskNumber = (Get-Disk | Where-Object { $_.FriendlyName -eq $disk.FriendlyName }).Number
        $partitions = Get-Partition -DiskNumber $diskNumber
        foreach ($partition in $partitions) {
            if ($partition.DriveLetter) { Optimize-Volume -DriveLetter $partition.DriveLetter -ReTrim }
        }
    }
}

function Report-Drive-Space {
    param([array]$Before, [array]$After)
    foreach ($before in $Before) {
        $after = $After | Where-Object { $_.DeviceID -eq $before.DeviceID }
        if ($after) {
            $diff = [decimal]$after.FreeSpace - [decimal]$before.FreeSpace
            $label = if ($diff -lt 0) { "Used" } else { "Freed" }
            $diffValue = if ([math]::Abs($diff) -lt 1) { [math]::Round([math]::Abs($diff) * 1024, 1); "MB" } else { [math]::Round([math]::Abs($diff),3); "GB" }
            Write-Host "Drive $($before.DeviceID): $label $diffValue"
        }
    }
}

# -------------------------
# Main Script
# -------------------------
$beforeCleanup = Drive-Space
$totalCleaned = 0

# -------------------------
# User Directories Cleanup
# -------------------------
$userDirs = Get-ChildItem "C:\Users" -Directory
$currentUserDir = 0
$totalUserDirs = $userDirs.Count

foreach ($user in $userDirs) {
    $currentUserDir++
    $userProfile = $user.FullName
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
    $totalCleaned += Remove-JunkFiles -Paths ($userPaths + $knownAppCaches) -SectionName "User and App Caches"
}

# -------------------------
# System Paths Cleanup
# -------------------------
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

foreach ($path in $systemPaths) { $totalCleaned += Remove-JunkFiles -Paths @($path) -SectionName "System Cleanup" }

# -------------------------
# Recycle Bin Cleanup
# -------------------------
$totalCleaned += Clear-RecycleBin

# -------------------------
# SSD TRIM
# -------------------------
if ($TrimSSDs) { SSD-Optimize }

# -------------------------
# Cleanup Summary
# -------------------------
$totalMB = [math]::Round($totalCleaned / 1MB, 2)
Write-Host "`n=============================="
Write-Host " CLEANUP COMPLETE" -ForegroundColor Cyan
Write-Host " Total disk space freed: $totalMB MB"
Write-Host "=============================="

$afterCleanup = Drive-Space
Report-Drive-Space -Before $beforeCleanup -After $afterCleanup

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
Write-Info "Disabling Location Tracking..."
Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny" "String"
Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0
Set-RegValue "HKLM:\SYSTEM\Maps" "AutoUpdateEnabled" 0
Write-OK "Location tracking disabled."

# -------------------------
# Disk Cleanup (all drives, no popups)
# -------------------------
Write-Info "Running Disk Cleanup and component store cleanup on all drives..."

# Get all filesystem drives
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path $_.Root }

foreach ($drive in $drives) {
    try {
        Write-Host "`n[*] Cleaning drive $($drive.Root)" -ForegroundColor Cyan
        # Run cleanmgr silently
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/d $($drive.Root.TrimEnd('\')) /VERYLOWDISK" -Wait -NoNewWindow
    } catch {
        Write-Warning "Failed Disk Cleanup on $($drive.Root): $($_.Exception.Message)"
    }
}

# Component Store cleanup (system drive only)
try {
    Start-Process -FilePath "Dism.exe" -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow
} catch {
    Write-Warning "Failed component store cleanup: $($_.Exception.Message)"
}

Write-OK "Disk cleanup completed on all drives."

# -------------------------
# PowerShell 7 Setup and Integration
# -------------------------
Write-Info "Checking PowerShell 7 installation..."
$pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"
$msiUrl   = "https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.msi"
$msiFile  = "$env:TEMP\PowerShell-7.5.2-win-x64.msi"

if (-not (Test-Path $pwshPath)){
  Write-Info "Installing PowerShell 7..."
  $installed = $false
  try {
    winget install --id Microsoft.Powershell --source winget -e --accept-package-agreements --accept-source-agreements
    $installed = $true
  } catch { Write-Warn "winget install failed." }

  if (-not $installed -or -not (Test-Path $pwshPath)){
    Write-Info "Falling back to MSI..."
    try {
      Invoke-WebRequest -Uri $msiUrl -OutFile $msiFile -UseBasicParsing
      Start-Process "msiexec.exe" -ArgumentList "/i `"$msiFile`" /quiet /norestart" -Wait
      Remove-Item $msiFile -Force -ErrorAction SilentlyContinue
    } catch { Write-Err "Failed to install PowerShell 7 from MSI." }
  }
} else {
  Write-Info "PowerShell 7 detected - attempting upgrade via winget..."
  try { winget upgrade --id Microsoft.Powershell --source winget -e --accept-package-agreements --accept-source-agreements } catch {}
}

if (Test-Path $pwshPath){ Write-OK "PowerShell 7 present: $pwshPath" } else { Write-Warn "PowerShell 7 not found after install attempt." }

# Set default profile in Windows Terminal
$terminalSettings = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path $terminalSettings){
  Write-Info "Setting Windows Terminal default profile to PowerShell 7..."
  try {
    $settings = Get-Content $terminalSettings -Raw | ConvertFrom-Json
    $pwshProfile = $settings.profiles.list | Where-Object { $_.commandline -like "*pwsh.exe" }
    if ($pwshProfile){
      $settings.defaultProfile = $pwshProfile.guid
      $settings | ConvertTo-Json -Depth 10 | Set-Content $terminalSettings -Encoding utf8
      Write-OK "Windows Terminal default set to PowerShell 7."
    } else { Write-Warn "PowerShell 7 profile not found in Terminal settings.json" }
  } catch { Write-Warn "Failed to update Windows Terminal settings: $_" }
} else { Write-Warn "Windows Terminal settings.json not found - skipping." }

# Replace Win+X menu PowerShell links
Write-Info "Updating Win+X menu to use PowerShell 7..."
$winxPath = "$env:LocalAppData\Microsoft\Windows\WinX"
if ((Test-Path $winxPath) -and (Test-Path $pwshPath)) {
  try {
    $shortcuts = Get-ChildItem -Path $winxPath -Recurse -Filter *.lnk
    foreach ($sc in $shortcuts) {
      $wshell = New-Object -ComObject WScript.Shell
      $shortcut = $wshell.CreateShortcut($sc.FullName)
      if ($shortcut.TargetPath -match "powershell.exe"){
        $shortcut.TargetPath = $pwshPath
        $shortcut.IconLocation = "$pwshPath,0"
        $shortcut.Save()
        Write-Info "Updated Win+X shortcut: $($sc.FullName)"
      }
    }
    Write-OK "Win+X menu now launches PowerShell 7 (normal + admin). Sign out/in to see changes."
  } catch { Write-Warn "Failed to update Win+X shortcuts: $_" }
} else { Write-Warn "Win+X path or pwsh.exe missing - skipping." }

# PowerShell 7 telemetry opt out
Write-Info "Opting out of PowerShell telemetry..."
try { [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT','1','Machine') } catch {}
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
    Start-Process -FilePath powercfg -ArgumentList "/change standby-timeout-ac 60" -NoNewWindow -Wait
    Start-Process -FilePath powercfg -ArgumentList "/change standby-timeout-dc 60" -NoNewWindow -Wait
    Start-Process -FilePath powercfg -ArgumentList "/change monitor-timeout-ac 10" -NoNewWindow -Wait
    Start-Process -FilePath powercfg -ArgumentList "/change monitor-timeout-dc 1" -NoNewWindow -Wait
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
function Configure-Teredo {
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
Configure-Teredo -Undo:$UndoTeredo

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
  [PSCustomObject]@{ Name = "SysMain"; StartupType = if($Aggressive){"Manual"} else {"Automatic"} },
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
  [PSCustomObject]@{ Name = "WSearch"; StartupType = if($Aggressive){"Manual"} else {"AutomaticDelayedStart"} },
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
  "Microsoft.BingWeather",
  "Microsoft.BingFoodAndDrink",
  "Microsoft.BingHealthAndFitness",
  "Microsoft.BingTravel",
  "Microsoft.MinecraftUWP",
  "Microsoft.GetHelp",
  "Microsoft.Getstarted",
  "Microsoft.Messaging",
  "Microsoft.MicrosoftSolitaireCollection",
  "Microsoft.News",
  "Microsoft.SkypeApp",
  "Microsoft.Wallet",
  "Microsoft.Whiteboard",
  "Microsoft.WindowsAlarms",
  "microsoft.windowscommunicationsapps",
  "Microsoft.WindowsFeedbackHub",
  "Microsoft.WindowsMaps",
  "Microsoft.WindowsSoundRecorder",
  "Microsoft.ScreenSketch",
  "Microsoft.MixedReality.Portal",
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

# Clean Teams uninstallers if present
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
} catch {}
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

Write-OK "All steps completed. A restart is recommended."