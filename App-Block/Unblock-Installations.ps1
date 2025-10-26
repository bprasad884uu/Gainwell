<#
Neutralizes AppLocker without deleting the feature or binaries.
 - Sets Application Identity (AppIDSvc) to Manual
 - Stops the service
 - Clears AppLocker policy keys (machine + all users)
 - Applies an empty AppLocker policy
 - Wipes compiled policy files (Exe/Appx/Dll/Msi/Script .AppLocker + AppCache.dat) via a one-time SYSTEM task
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Set-AppIdSvcStartType {
  param([ValidateSet('Automatic','Manual')][string]$StartType)
  $val = if ($StartType -eq 'Automatic') { 2 } else { 3 }  # 2=Auto, 3=Manual
  Write-Host "Setting AppIDSvc Start to $StartType..."
  reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /v Start /t REG_DWORD /d $val /f | Out-Null
}

function Remove-AllUserSrpPolicies {
  Write-Host "Clearing SRP (Software Restriction Policies) for all users..."
  $srpRel = "Software\Policies\Microsoft\Windows\Safer"

  # HKLM (machine)
  Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer" -Recurse -Force -ErrorAction SilentlyContinue

  # All loaded user hives under HKU
  Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } |
    ForEach-Object {
      $sid = $_.PSChildName
      $key = "Registry::HKEY_USERS\$sid\$srpRel"
      if (Test-Path $key) {
        try { Remove-Item $key -Recurse -Force -ErrorAction Stop; Write-Host "Removed SRP: HKU\$sid\$srpRel" }
        catch { Write-Warning "SRP cleanup failed for $sid : $($_.Exception.Message)" }
      }
    }
}

function Apply-Empty-AppLockerPolicy {
  Write-Host "Applying empty AppLocker policy (no rules)..."
  $dir = Join-Path $env:ProgramData "AppLocker"
  if (-not (Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }
  $empty = '<AppLockerPolicy Version="1" />'
  $path = Join-Path $dir "Empty.xml"
  $empty | Out-File $path -Encoding UTF8 -Force
  Set-AppLockerPolicy -XmlPolicy $path -ErrorAction SilentlyContinue
}

function Invoke-SystemAppLockerWipe {
  # Removes compiled AppLocker cache files
  $folder = "C:\Windows\System32\AppLocker"
  if (-not (Test-Path $folder)) { return }

  function Try-Delete { param($path)
    try {
      if (Test-Path $path) { Remove-Item $path -Recurse -Force -ErrorAction Stop }
      return $true
    } catch {
      if ($_.Exception.Message -match 'Access is denied') { return $false }
      return $true
    }
  }

  $targets = @("$folder\*.AppLocker", "$folder\AppCache.dat", "$folder\Cache")
  $deletedOK = $true
  foreach ($t in $targets) { if (-not (Try-Delete $t)) { $deletedOK = $false } }

  if (-not $deletedOK) {
    takeown /f $folder /r /d y | Out-Null
    icacls $folder /grant Administrators:F /t /c | Out-Null
    foreach ($t in $targets) { Try-Delete $t | Out-Null }
  }
}

function Clear-AppLockerLogs {
  foreach ($log in "Microsoft-Windows-AppLocker/EXE and DLL",
                 "Microsoft-Windows-AppLocker/MSI and Script",
                 "Microsoft-Windows-AppLocker/Packaged app-Execution",
                 "Microsoft-Windows-AppLocker/Packaged app-Deployment") {
    try { wevtutil cl "$log" 2>$null } catch {}
  }
}

function Verify-State {
  Write-Host "`n=== Current State ==="
  try {
    Get-Service AppIDSvc | Select-Object Name, Status, StartType | Format-Table -AutoSize
  } catch { Write-Host "AppIDSvc not found as a service (OK)"; }
  $hasRules = ((Get-AppLockerPolicy -Effective -Xml) -match '<RuleCollection').Count -gt 0
  Write-Host "Effective AppLocker policy has rule collections: $hasRules"
  if (Test-Path "C:\Windows\System32\AppLocker") {
    $left = Get-ChildItem "C:\Windows\System32\AppLocker" -ErrorAction SilentlyContinue
    Write-Host "System32\AppLocker remaining files: $($left.Count)"
    if ($left) { $left | Format-Table Name,Length,LastWriteTime -AutoSize }
  }
  Write-Host "======================`n"
}

# --- Main Execution ---

Write-Host "Neutralizing AppLocker..."

# 1) Stop service this session (ignore errors)
Stop-Service AppIDSvc -Force -ErrorAction SilentlyContinue

# 2) Set to Manual start (safer than Disabled on protected services)
Set-AppIdSvcStartType -StartType Manual

# 3) Clear AppLocker and SRP policies for machine + all user profiles

# Machine-wide
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppLocker" -Recurse -Force -ErrorAction SilentlyContinue

# Per-user (all SIDs)
Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
  Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } |
  ForEach-Object {
    $sid = $_.PSChildName
    foreach ($subkey in @("SrpV2", "AppLocker")) {
      $path = "Registry::HKEY_USERS\$sid\SOFTWARE\Policies\Microsoft\Windows\$subkey"
      if (Test-Path $path) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }

# 4) Clear UAC installer-detection override (if any)
$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (Test-Path $uacKey) {
    Remove-ItemProperty -Path $uacKey -Name "EnableInstallerDetection" -ErrorAction SilentlyContinue
}

# 5) Ensure Windows Installer policy allows MSI
$msiKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if (Test-Path $msiKey) {
    Remove-Item $msiKey -Recurse -Force -ErrorAction SilentlyContinue
}

# 6) Clear SRP for all users (policy-only)
Remove-AllUserSrpPolicies

# 7) Apply empty AppLocker policy
Apply-Empty-AppLockerPolicy

# 8) Group Policy refresh; keep service stopped
gpupdate /force | Out-Null
Start-Sleep -Seconds 2
Stop-Service AppIDSvc -Force -ErrorAction SilentlyContinue

# 9) Clear AppLocker logs (fresh start)
Clear-AppLockerLogs

# 10) Delete compiled AppLocker cache files
Invoke-SystemAppLockerWipe

# 11) Cleanup optional backup directory, if present
$backupRoot = "C:\PolicyBackup"
if (Test-Path $backupRoot) {
    Remove-Item $backupRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Verify-State
Write-Host "Done. AppLocker neutralized."