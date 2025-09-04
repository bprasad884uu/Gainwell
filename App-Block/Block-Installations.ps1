<#
AppLocker Policy in ENFORCE mode (Hybrid model + Refined PS Temp Fix + Installer Elevation + Non-System Drive Block)
- Local Admins + Domain Admins allowed everywhere.
- Standard Users only allowed:
  * Windows, Program Files, Program Files (x86), ProgramData
  * Microsoft-signed DLLs + Scripts (system-critical)
  * Store Apps (Appx)
  * PowerShell engine test scripts (__PSScriptPolicyTest*.ps1 in Temp)
- EXE + MSI limited to system paths (no user self-install).
- Per-user installers blocked (AppData, Downloads, Desktop, Temp).
- All installers (MSI + EXE) require Admin.
- Known installer names blocked on non-system drives (D:, E:, F:, ...).
- Block Policy with Auto-Backup (Timestamped)
- Saves AppLocker, SRP, WDAC backup into C:\PolicyBackup\<date_time>
- Then applies restrictions
#>

param (
    [string[]]$WhitelistedApps       = @("Diagsmart*.exe", "Uninstall*.exe"),
    [string[]]$WhitelistedPaths      = @(),
    [string[]]$WhitelistedPublishers = @("O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US","CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US")
)

# Checking Windows Compatibility
$OSType = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($OSType -ne 1) {
    Write-Host "Non-client OS detected. Exiting script."
    exit
}

$ErrorActionPreference = 'Stop'

# --- Create timestamped backup folder ---
$timestamp = Get-Date -Format "ssMMyyyyddHHmm"
$backupDir = "C:\PolicyBackup\$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

Write-Host "=== Creating Backup ($backupDir) ==="

# 1. Backup AppLocker (VALID XML)
try {
    $xmlPath = Join-Path $backupDir "AppLocker-Backup.xml"
    Get-AppLockerPolicy -Effective -Xml | Out-File -FilePath $xmlPath -Encoding UTF8
    Write-Host "AppLocker backed up to $xmlPath"
} catch { Write-Warning "AppLocker backup failed: $_" }

# 2. Backup SRP
try {
    $regFile = Join-Path $backupDir "SRP-Backup.reg"
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer" $regFile /y | Out-Null
    Write-Host "SRP registry exported to $regFile"
} catch { Write-Warning "SRP backup failed (may not exist)." }

<# 3. Backup WDAC
try {
    $ciPath = "C:\Windows\System32\CodeIntegrity"
    $ciBackupDir = Join-Path $backupDir "CodeIntegrity"
    if (Test-Path $ciPath) {
        New-Item -ItemType Directory -Path $ciBackupDir -Force | Out-Null
        Copy-Item -Path "$ciPath\*.p7b" -Destination $ciBackupDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "WDAC policies copied to $ciBackupDir"
    }
} catch { Write-Warning "WDAC backup failed: $_" }
#>
Write-Host "=== Backup complete. Applying Block Policy... ==="

$ErrorActionPreference = 'Stop'

# --- Check for elevation ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator. Exiting..."
    exit 1
}

Write-Host "=== Detecting Windows Edition ==="
$edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
Write-Host "Detected Edition: $edition"

# --- Enforce elevation for installers ---
Write-Host "Enforcing installer elevation policies..."

# MSI must always require Admin
$msiKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if (-not (Test-Path $msiKey)) { New-Item -Path $msiKey -Force | Out-Null }
Set-ItemProperty -Path $msiKey -Name "AlwaysInstallElevated" -Value 0 -Type DWord

# UAC installer detection (setup.exe, install.exe, update.exe)
$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $uacKey)) { New-Item -Path $uacKey -Force | Out-Null }
Set-ItemProperty -Path $uacKey -Name "EnableInstallerDetection" -Value 1 -Type DWord

# Block per-user installations (EXE/MSI in User Profiles)
$srpKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths"
if (-not (Test-Path $srpKey)) { New-Item -Path $srpKey -Force | Out-Null }
New-Item -Path "$srpKey\{0001}" -Force | Out-Null
Set-ItemProperty -Path "$srpKey\{0001}" -Name "ItemData" -Value "%OSDRIVE%\Users\*" -Type String
Set-ItemProperty -Path "$srpKey\{0001}" -Name "SaferFlags" -Value 0x00000000 -Type DWord

# Block known installer names on non-system drives
$driveLetters = @("D:","E:","F:","G:","H:")
$counter = 100
foreach ($drive in $driveLetters) {
    foreach ($pattern in @("setup.exe","install.exe","update.exe","*.msi")) {
        $ruleId = "{000$counter}"
        New-Item -Path "$srpKey\$ruleId" -Force | Out-Null
        Set-ItemProperty -Path "$srpKey\$ruleId" -Name "ItemData" -Value "$drive\*\$pattern" -Type String
        Set-ItemProperty -Path "$srpKey\$ruleId" -Name "SaferFlags" -Value 0x00000000 -Type DWord
        $counter++
    }
}

Write-Host "All installers (system-wide, per-user, and non-system drives) now require Administrator privileges."

# --- AppLocker setup ---
function Enable-AppIDSvc {
    sc.exe config appidsvc start= auto | Out-Null
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
}
function New-RuleGuid { [guid]::NewGuid().ToString().ToUpper() }
function Get-DomainAdminsSID {
    try {
        $domainAdmins = New-Object System.Security.Principal.NTAccount("Domain Admins")
        $sid = $domainAdmins.Translate([System.Security.Principal.SecurityIdentifier])
        return $sid.Value
    } catch {
        Write-Host "Could not resolve Domain Admins SID. Skipping Domain Admins rule."
        return $null
    }
}

function Apply-AppLockerEnforcePolicy {
    Enable-AppIDSvc
    $domainAdminsSID = Get-DomainAdminsSID

    $applockerXml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">

  <!-- EXE Rules -->
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Local Admins - EXE" Description="Local Admins can run EXEs" UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
"@
    if ($domainAdminsSID) {
        $applockerXml += @"
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Domain Admins - EXE" Description="Domain Admins can run EXEs" UserOrGroupSid="$domainAdminsSID" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
"@
    }
    $applockerXml += @"
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - Windows EXE" Description="Allow EXEs from Windows" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - Program Files EXE" Description="Allow EXEs from Program Files" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - Program Files (x86) EXE" Description="Allow EXEs from Program Files (x86)" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%ProgramFiles(x86)%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - ProgramData EXE" Description="Allow EXEs from ProgramData" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%ProgramData%\*"/></Conditions></FilePathRule>
"@
      # App Whitelist
    foreach ($app in $WhitelistedApps) {
        $applockerXml += @"
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - $app" Description="Allow $app anywhere" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*\$app"/></Conditions>
    </FilePathRule>
"@
    }

    # Path Whitelist
    foreach ($path in $WhitelistedPaths) {
        $applockerXml += @"
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - $path" Description="Allow path $path" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="$path"/></Conditions>
    </FilePathRule>
"@
    }

    # Publisher Whitelist
    foreach ($publisher in $WhitelistedPublishers) {
        $applockerXml += @"
    <FilePublisherRule Id="$(New-RuleGuid)" Name="Allow Publisher - $publisher" Description="Allow signed apps from $publisher" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="$publisher" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@
    }
	$applockerXml += @"
  </RuleCollection>

  <!-- Script Rules -->
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Local Admins - Scripts" Description="Local Admins can run scripts" UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
    <FilePublisherRule Id="$(New-RuleGuid)" Name="Allow Everyone - Microsoft Signed Scripts" Description="Allow Microsoft-signed scripts (PowerShell, etc.)" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - PowerShell Policy Test Scripts" Description="Allow PowerShell engine’s __PSScriptPolicyTest*.ps1 temp files" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\Users\*\AppData\Local\Temp\__PSScriptPolicyTest*.ps1"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - Windows Scripts" Description="Allow scripts from Windows" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - Program Files Scripts" Description="Allow scripts from Program Files" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - ProgramData Scripts" Description="Allow scripts from ProgramData" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%ProgramData%\*"/></Conditions></FilePathRule>
  </RuleCollection>

  <!-- DLL Rules -->
  <RuleCollection Type="Dll" EnforcementMode="Enabled">
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Local Admins - DLL" Description="Local Admins can load DLLs" UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
    <FilePublisherRule Id="$(New-RuleGuid)" Name="Allow Everyone - Microsoft Signed DLLs" Description="Allow Microsoft-signed DLLs (Defender, OneDrive, etc.)" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - Windows DLLs" Description="Allow DLLs from Windows" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - Program Files DLLs" Description="Allow DLLs from Program Files" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - ProgramData DLLs" Description="Allow DLLs from ProgramData" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%ProgramData%\*"/></Conditions></FilePathRule>
  </RuleCollection>

  <!-- MSI Rules -->
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Local Admins - MSI" Description="Local Admins can run MSIs" UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - Program Files MSI" Description="Allow MSIs from Program Files" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="$(New-RuleGuid)" Name="Allow Everyone - ProgramData MSI" Description="Allow MSIs from ProgramData" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%ProgramData%\*"/></Conditions></FilePathRule>
  </RuleCollection>

  <!-- Appx Rules -->
  <RuleCollection Type="Appx" EnforcementMode="Enabled">
    <FilePublisherRule Id="$(New-RuleGuid)" Name="Allow Everyone - All Signed Appx" Description="Allow all signed packaged apps" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>

</AppLockerPolicy>
"@

    $dir = Join-Path $env:ProgramData "AppLocker"
    $xmlPath = Join-Path $dir "EnforceStdInstall-Hybrid-PSRefined-AIO.xml"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    try {
        $applockerXml | Out-File -FilePath $xmlPath -Encoding UTF8 -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not save XML to $xmlPath (access denied). Continuing..."
    }

    Write-Host "Applying Hybrid ENFORCE AppLocker policy (AIO with installer elevation + non-system drive block)..."
    Set-AppLockerPolicy -XmlPolicy $xmlPath -Merge
    gpupdate /force | Out-Null

    try {
        Restart-Service -Name AppIDSvc -Force -ErrorAction Stop
        Write-Host "Application Identity service restarted."
    } catch {
        Write-Warning "Could not restart AppIDSvc. You may need to reboot."
    }

    Write-Host "Enforce policy applied successfully."
}

if ($edition -match "Enterprise|Education|Professional") {
    Apply-AppLockerEnforcePolicy
} else {
    Write-Host "SRP Enforce version not supported here."
}
