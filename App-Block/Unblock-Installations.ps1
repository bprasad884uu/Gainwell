<#
Unblock / Reset ALL install restriction policies (Clean Version)
- Applies empty AppLocker policy (<AppLockerPolicy Version="1" />)
- Resets SRP safer key to default baseline (ExecutableTypes list)
- Clears installer overrides
- Disables + stops Application Identity service (AppIDSvc)
- Removes backup folder (C:\PolicyBackup) if present
#>

$ErrorActionPreference = 'Stop'
Write-Host "=== Resetting ALL install restriction policies ==="

# --- 1. AppLocker reset ---
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
} catch {
    Write-Warning "`nFailed to apply AppLocker reset: $($_.Exception.Message)"
}

# --- 2. SRP (Safer) baseline reset ---
try {
    Write-Host "`nResetting SRP (Safer) baseline..."
    $saferBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
    if (-not (Test-Path $saferBase)) { 
        New-Item -Path $saferBase -Force | Out-Null 
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
} catch {
    Write-Warning "`nFailed to reset SRP baseline: $($_.Exception.Message)"
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
Write-Host "`nInstaller overrides reset."

# --- 4. Refresh policies ---
gpupdate /force | Out-Null

# --- 5. Disable + stop AppIDSvc ---
try {
    sc.exe config appidsvc start= disabled | Out-Null
    Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc' -Name Start -Type DWord -Value 4
    Write-Host "`nAppIDSvc disabled and stopped."
} catch {
    Write-Warning "`nCould not disable AppIDSvc: $($_.Exception.Message)"
}

# --- 6. Remove backup folder if exists ---
$backupRoot = "C:\PolicyBackup"
if (Test-Path $backupRoot) {
    Remove-Item $backupRoot -Recurse -Force
    Write-Host "`nBackup directory $backupRoot removed."
}

Write-Host "`nReset complete. Reboot recommended."
