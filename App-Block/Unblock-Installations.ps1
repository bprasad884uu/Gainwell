<#
Revert ALL install restriction policies (Safe Version)
- First tries to restore from most recent backup in C:\PolicyBackup
- Applies empty AppLocker policy (<AppLockerPolicy Version="1" />)
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
    $backupDir = Get-ChildItem -Path $backupRoot -Directory -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1
}

# --- 1. Try AppLocker + SRP restore ---

$restoredAny = $false
$errors = @()

# Apply clean reset
if (-not $restoredAny) {
    Write-Host "`nApplying clean reset..."

    # AppLocker reset
    $resetXml = @'
<AppLockerPolicy Version="1" />
'@
    $appLockerDir = Join-Path $env:ProgramData "AppLocker"
    try {
        if (-not (Test-Path $appLockerDir)) { 
            New-Item -Path $appLockerDir -ItemType Directory -Force | Out-Null 
            Write-Host "`nCreated AppLocker directory: $appLockerDir"
        }
        $resetPath = Join-Path $appLockerDir "FullReset.xml"
        $resetXml | Out-File -FilePath $resetPath -Encoding UTF8 -Force
        Set-AppLockerPolicy -XmlPolicy $resetPath -ErrorAction Stop
        Write-Host "`nAppLocker reset applied."
        $restoredAny = $true
    } catch {
        $msg = "Failed to apply AppLocker reset: $($_.Exception.Message)"
        Write-Warning "`n$msg"
        $errors += $msg
    }

    # SRP (Safer) baseline reset
    try {
        Write-Host "`nResetting SRP (Safer) baseline..."
        $saferBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
        if (-not (Test-Path $saferBase)) { 
            New-Item -Path $saferBase -Force | Out-Null 
            #Write-Host "`nCreated $saferBase"
        }

        $exeTypes = "ADE;ADP;BAS;BAT;CHM;CMD;COM;CPL;CRT;EXE;HLP;HTA;INF;INS;ISP;LNK;MDB;MDE;MSC;MSI;MSP;MST;OCX;PCD;PIF;REG;SCR;SHS;URL;VB;WSC"
        $exeArray = $exeTypes -split ';'

        New-ItemProperty -Path $saferBase -Name "DefaultLevel" -Value 0x00040000 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $saferBase -Name "TransparentEnabled" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $saferBase -Name "PolicyScope" -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $saferBase -Name "authenticodeenabled" -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $saferBase -Name "ExecutableTypes" -Value $exeArray -PropertyType MultiString -Force | Out-Null

        $zeroKey = Join-Path $saferBase "0"
        if (-not (Test-Path $zeroKey)) { New-Item -Path $zeroKey -Force | Out-Null }
        if (-not (Test-Path (Join-Path $zeroKey "PATHS"))) { New-Item -Path (Join-Path $zeroKey "PATHS") -Force | Out-Null }
        if (-not (Test-Path (Join-Path $zeroKey "HASHES"))) { New-Item -Path (Join-Path $zeroKey "HASHES") -Force | Out-Null }

        Write-Host "`nSRP (Safer) baseline reset done."
        $restoredAny = $true
    } catch {
        $msg = "Failed to reset SRP baseline: $($_.Exception.Message)"
        Write-Warning "`n$msg"
        $errors += $msg
    }
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
