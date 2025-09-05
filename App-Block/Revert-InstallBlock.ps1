<#
Revert ALL install restriction policies (Safe Version)
- First tries to restore from most recent backup in C:\PolicyBackup
- If no valid backup is found → pushes clean reset (<AppLockerPolicy Version="1" />)
- Resets SRP safer key to default baseline (with ExecutableTypes list)
- Clears installer overrides
- Finally disables + stops Application Identity service (AppIDSvc)
- gpupdate + AppIDSvc cleanup at the end
#>

$ErrorActionPreference = 'Stop'

Write-Host "=== Reverting ALL install restriction policies (Safe Mode) ==="

# --- Find latest backup ---
$backupRoot = "C:\PolicyBackup"
$backupDir = $null
if (Test-Path $backupRoot) {
    $backupDir = Get-ChildItem -Path $backupRoot -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

$restored = $false

## --- 1. Find latest backup ---
$backupRoot = "C:\PolicyBackup"
$backupDir = $null
if (Test-Path $backupRoot) {
    $backupDir = Get-ChildItem -Path $backupRoot -Directory |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1
}

# --- 1. Try AppLocker + SRP restore ---
$restored = $false

if ($backupDir) {
    Write-Host "`nFound backup: $($backupDir.FullName). Trying restore..."
    $xmlPath = Join-Path $backupDir.FullName "AppLocker-Backup.xml"
    $regFile = Join-Path $backupDir.FullName "SRP-Backup.reg"

    if (Test-Path $xmlPath) {
        try {
            Set-AppLockerPolicy -XmlPolicy $xmlPath -ErrorAction Stop
            Write-Host "`nRestored AppLocker from backup."
            $restored = $true
        } catch {
            Write-Warning "`nAppLocker restore failed: $($_.Exception.Message)"
        }
    }

    if (Test-Path $regFile) {
        Write-Host "`nRestoring SRP policy from backup: $regFile"
        try {
            # Use reg.exe import. Quote the path to handle spaces.
            $arg = "import `"$regFile`""
            Start-Process -FilePath "reg.exe" -ArgumentList $arg -Wait -NoNewWindow -ErrorAction Stop
            Write-Host "SRP backup restored successfully."
            $restored = $true
        } catch {
            Write-Warning "Failed to restore SRP backup. Error: $($_.Exception.Message)"
        }
    }
}

# --- If restore failed, push clean reset ---
if (-not $restored) {
    Write-Host "`nNo valid backup restored. Pushing clean reset..."

    # AppLocker clean reset
    $resetXml = @'
<AppLockerPolicy Version="1" />
'@
    $appLockerDir = Join-Path $env:ProgramData "AppLocker"
    if (-not (Test-Path $appLockerDir)) {
        New-Item -Path $appLockerDir -ItemType Directory -Force | Out-Null
    }
    $resetPath = Join-Path $appLockerDir "FullReset.xml"
    $resetXml | Out-File -FilePath $resetPath -Encoding UTF8 -Force

    try {
        Set-AppLockerPolicy -XmlPolicy $resetPath -ErrorAction Stop
        Write-Host "AppLocker reset applied."
    } catch {
        Write-Warning "Failed to apply AppLocker reset: $($_.Exception.Message)"
    }
	
    # SRP (Safer) baseline reset
    Write-Host "`nResetting SRP safer key to baseline..."

    $saferBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"

    # Ensure base key exists
    if (-not (Test-Path $saferBase)) {
        New-Item -Path $saferBase -Force | Out-Null
        Write-Host "Created $saferBase"
    }

    # Set baseline values
    $exeTypesString = "ADE;ADP;BAS;BAT;CHM;CMD;COM;CPL;CRT;EXE;HLP;HTA;INF;INS;ISP;LNK;MDB;MDE;MSC;MSI;MSP;MST;OCX;PCD;PIF;REG;SCR;SHS;URL;VB;WSC"
    $exeArray = $exeTypesString -split ';'

    New-ItemProperty -Path $saferBase -Name "DefaultLevel" -Value 0x00040000 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $saferBase -Name "TransparentEnabled" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $saferBase -Name "PolicyScope" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $saferBase -Name "authenticodeenabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $saferBase -Name "ExecutableTypes" -Value $exeArray -PropertyType MultiString -Force | Out-Null

    # Ensure the '0' container with PATHS + HASHES
    $zeroKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0"
    if (-not (Test-Path $zeroKey)) { New-Item -Path $zeroKey -Force | Out-Null }
    if (-not (Test-Path (Join-Path $zeroKey "PATHS"))) { New-Item -Path (Join-Path $zeroKey "PATHS") -Force | Out-Null }
    if (-not (Test-Path (Join-Path $zeroKey "HASHES"))) { New-Item -Path (Join-Path $zeroKey "HASHES") -Force | Out-Null }

    Write-Host "`nSRP safer key reset to baseline."
}

# --- 2. Reset installer overrides ---
$msiKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if (Test-Path $msiKey) {
    Remove-ItemProperty -Path $msiKey -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
}
$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (Test-Path $uacKey) {
    Remove-ItemProperty -Path $uacKey -Name "EnableInstallerDetection" -ErrorAction SilentlyContinue
}
Write-Host "`nInstaller overrides reset."

# --- 3. Refresh policies ---
gpupdate /force | Out-Null

# --- 4. Disable + stop AppIDSvc ---
try {
    sc.exe config appidsvc start= disabled | Out-Null
    Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc' -Name Start -Type DWord -Value 4
    Write-Host "`nAppIDSvc disabled and stopped."
} catch {
    Write-Warning "`nCould not disable AppIDSvc: $_"
}

# Cleanup backup directory
if (Test-Path $backupRoot) {
    Remove-Item $backupRoot -Recurse -Force
    Write-Host "`nBackup directory $backupRoot removed."
}

Write-Host "`nRevert complete. Reboot recommended."
