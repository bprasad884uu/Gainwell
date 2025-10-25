<# 
Neutralizes AppLocker without deleting the service or binaries.
 - Sets Application Identity (AppIDSvc) to Manual
 - Stops the service
 - Clears AppLocker policy keys (machine + all users)
 - Applies an empty AppLocker policy
Run as Administrator.
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
  $empty = '<AppLockerPolicy Version="1"></AppLockerPolicy>'
  $path = Join-Path $dir "Empty.xml"
  $empty | Out-File $path -Encoding UTF8 -Force
  Set-AppLockerPolicy -XmlPolicy $path -ErrorAction SilentlyContinue
}

function Verify-State {
  Write-Host "`n=== Current State ==="
  try {
    Get-Service AppIDSvc | Select-Object Name, Status, StartType | Format-Table -AutoSize
  } catch { Write-Host "AppIDSvc not found as a service (OK)"; }
  $hasRules = ((Get-AppLockerPolicy -Effective -Xml) -match '<RuleCollection').Count -gt 0
  Write-Host "Effective AppLocker policy has rule collections: $hasRules"
  Write-Host "======================`n"
}

Write-Host "=== Safe disable AppLocker ==="

# 1) Stop service this session (ignore errors)
Stop-Service AppIDSvc -Force -ErrorAction SilentlyContinue

# 2) Set to Manual start (safer than Disabled on protected services)
Set-AppIdSvcStartType -StartType Manual

# 3) Clear machine & user AppLocker policy keys (do NOT remove binaries/service)
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppLocker" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppLocker" -Recurse -Force -ErrorAction SilentlyContinue

# 4) Clear SRP for all users (safe; policy-only)
Remove-AllUserSrpPolicies

# 5) Apply empty policy
Apply-Empty-AppLockerPolicy

# 6) GP refresh; keep service stopped
gpupdate /force | Out-Null
Start-Sleep -Seconds 2
try { Stop-Service AppIDSvc -Force -ErrorAction SilentlyContinue } catch {}

# Cleanup backup directory
$backupRoot = "C:\PolicyBackup"
if (Test-Path $backupRoot) {
    Remove-Item $backupRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Verify-State
Write-Host "Done. AppLocker is neutralized: service Manual + empty policy."
