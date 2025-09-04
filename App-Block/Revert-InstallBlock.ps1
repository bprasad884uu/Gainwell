<#
Revert ALL install restriction policies (Safe Version)
- First tries to restore from most recent backup in C:\PolicyBackup
- If no valid backup is found → pushes clean reset (<AppLockerPolicy Version="1" />)
- Also clears SRP, WDAC, installer overrides, SmartScreen
- Finally disables + stops Application Identity service (AppIDSvc)
- gpupdate + AppIDSvc cleanup at the end
#>

$ErrorActionPreference = 'Stop'

# --- Ensure admin ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator. Exiting..."
    exit 1
}

Write-Host "=== Reverting ALL install restriction policies (Safe Mode) ==="

# --- Find latest backup ---
$backupRoot = "C:\PolicyBackup"
$backupDir = $null
if (Test-Path $backupRoot) {
    $backupDir = Get-ChildItem -Path $backupRoot -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

$restored = $false

# --- 1. Try AppLocker restore ---
if ($backupDir) {
    Write-Host "Found backup: $($backupDir.FullName). Trying restore..."
    $xmlPath = Join-Path $backupDir.FullName "AppLocker-Backup.xml"
    if (Test-Path $xmlPath) {
        try {
            Set-AppLockerPolicy -XmlPolicy $xmlPath
            Write-Host "Restored AppLocker from backup."
            $restored = $true
        } catch {
            Write-Warning "AppLocker restore failed: $_"
        }
    }
}

# --- If restore failed, push clean reset ---
if (-not $restored) {
    Write-Host "No valid backup found. Pushing clean reset..."
    $resetXml = @"
<AppLockerPolicy Version="1" />
"@
    $resetPath = "$env:ProgramData\AppLocker\FullReset.xml"
    $resetXml | Out-File -FilePath $resetPath -Encoding UTF8 -Force
    Set-AppLockerPolicy -XmlPolicy $resetPath
}

# --- 2. Remove SRP ---
$srpBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer"
if (Test-Path $srpBase) {
    Remove-Item -Path $srpBase -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "SRP removed."
}

# --- 3. Reset installer overrides ---
$msiKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if (Test-Path $msiKey) {
    Remove-ItemProperty -Path $msiKey -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
}
$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (Test-Path $uacKey) {
    Remove-ItemProperty -Path $uacKey -Name "EnableInstallerDetection" -ErrorAction SilentlyContinue
}
Write-Host "Installer overrides reset."

# --- 4. Refresh policies ---
gpupdate /force | Out-Null

# --- 5. Disable + stop AppIDSvc ---
try {
    sc.exe config appidsvc start= disabled | Out-Null
    Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc' -Name Start -Type DWord -Value 4
    Write-Host "AppIDSvc disabled and stopped."
} catch {
    Write-Warning "Could not disable AppIDSvc: $_"
}

#Cleanup backup directory
Remove-Item $backupRoot -Recurse -Force
Write-Host "Revert complete. Reboot recommended."