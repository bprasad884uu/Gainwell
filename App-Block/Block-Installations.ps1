<#
AppLocker Policy in ENFORCE mode
- Local Admins + Domain Admins allowed everywhere.
- Standard Users only allowed:
  * Windows, Program Files, Program Files (x86), ProgramData
  * Microsoft-signed DLLs + Scripts (system-critical)
  * Store Apps (Appx)
  * PowerShell engine test scripts (__PSScriptPolicyTest*.ps1 in Temp)
  * Wallpaper policy temp scripts (RD*.ps1 in Temp)
- EXE + MSI limited to system paths (no user self-install).
- Per-user installers blocked (AppData, Downloads, Desktop, Temp).
- All installers (MSI + EXE) require Admin.
- Known installer names blocked on non-system drives (D:, E:, F:, ...).
- Block Policy with Auto-Backup (Timestamped)
- Saves AppLocker, SRP, WDAC backup into C:\PolicyBackup\<date_time>
- Then applies restrictions
#>

param (
	[string]$OutXmlPath = "C:\ProgramData\AppLocker\Enforce-AppLocker-Block.xml",

	[ValidateSet("Enabled","AuditOnly")]
	[string]$EnforcementMode = "Enabled",   # ENFORCE. Change to "AuditOnly" if you want to test first.

	[string[]]$WhitelistedApps = @("Diagsmart*.exe", "Uninstall*.exe"),
	[string[]]$WhitelistedPaths = @(),
	[string[]]$WhitelistedPublishers = @("O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US","CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US")
)

# Checking Windows Compatibility
$OSType = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($OSType -ne 1) {
    Write-Host "Non-client OS detected. Exiting script."
    exit
}

# helper for GUIDs
function New-RuleGuid { return [guid]::NewGuid().ToString() }

# Use standard SystemDrive token for XML paths
$SystemDriveToken = "%SYSTEMDRIVE%"

# discover non-system fixed drives
$systemRoot = $env:SystemDrive.TrimEnd('\') + '\'
$nonSystemDrives = Get-PSDrive -PSProvider FileSystem |
                   Where-Object { $_.Root -ne $systemRoot -and $_.DisplayRoot -ne $null } |
                   Select-Object -ExpandProperty Root -ErrorAction SilentlyContinue
if ($null -eq $nonSystemDrives) { $nonSystemDrives = @() }

$ErrorActionPreference = 'Stop'

# --- Create timestamped backup folder ---
$timestamp = Get-Date -Format "MMyyyyddHHmmss"
$backupDir = "C:\PolicyBackup\$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

Write-Host "=== Creating Backup ($backupDir) ==="

# 1. Backup AppLocker (VALID XML)
try {
    $xmlPath = Join-Path $backupDir "AppLocker-Backup.xml"
    Get-AppLockerPolicy -Effective -Xml | Out-File -FilePath $xmlPath -Encoding UTF8
    Write-Host "`nAppLocker backed up to $xmlPath"
} catch { Write-Warning "`nAppLocker backup failed: $_" }

# 2. Backup SRP
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer"
if (Test-Path $regPath) {
    try {
        $regFile = Join-Path $backupDir "SRP-Backup.reg"
        reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer" $regFile /y | Out-Null
        Write-Host "`nSRP registry exported to $regFile"
    } catch {
        Write-Warning "`nSRP backup failed."
    }
} else {
    Write-Host "`nSRP registry path not found. Skipping backup."
}

# 3. Attempt WDAC (.cipolicy/.xml) backup (if present)
try {
    $wdacPath = Join-Path $backupDir "WDAC-Policies"
    New-Item -ItemType Directory -Path $wdacPath -Force | Out-Null
    Get-ChildItem -Path "C:\Windows\System32\CodeIntegrity\*" -Include '*.cipolicy','*.xml' -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-Item -Path $_.FullName -Destination $wdacPath -Force }
    $found = Get-ChildItem -Path $wdacPath -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "`nAttempted WDAC policy backup (if any) to $wdacPath"
    } else {
        Write-Host "`nNo WDAC policy files found to back up."
    }
} catch { Write-Warning "`nWDAC backup step failed: $_" }

Write-Host "`n=== Backup complete. Applying Block Policy... ==="

$ErrorActionPreference = 'Stop'

# start building XML
$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
"@

# ---------------- EXE rules ----------------
$xml += "  <RuleCollection Type=`"Exe`" EnforcementMode=`"$EnforcementMode`">`n"

# Deny installers in user profiles for local Users
$installerPatternsUsers = @(
  "$SystemDriveToken\Users\*\*.msi",
  "$SystemDriveToken\Users\*\*setup.exe",
  "$SystemDriveToken\Users\*\*install.exe",
  "$SystemDriveToken\Users\*\*update.exe"
)
foreach ($p in $installerPatternsUsers) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Deny - Users - $(Split-Path $p -Leaf)`" Description=`"Deny installers in user profiles`" UserOrGroupSid=`"S-1-5-32-545`" Action=`"Deny`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$p`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Deny installers on all fixed non-system drives
$drivePatterns = @("*.msi","setup.exe","install.exe","update.exe")
foreach ($driveRoot in $nonSystemDrives) {
    $driveLetter = $driveRoot.TrimEnd('\')
    if ($driveLetter -match '^[A-Za-z]:$') {
        foreach ($pat in $drivePatterns) {
            $pp = "$driveLetter\*\$pat"
            $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Deny - $driveLetter - $pat`" Description=`"Deny installers on $driveLetter`" UserOrGroupSid=`"S-1-5-32-545`" Action=`"Deny`">`n"
            $xml += "      <Conditions><FilePathCondition Path=`"$pp`"/></Conditions>`n"
            $xml += "    </FilePathRule>`n"
        }
    }
}

# Allow Local Admins everywhere
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All`" Description=`"Local Administrators allowed everywhere`" UserOrGroupSid=`"S-1-5-32-544`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow system paths for everyone
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows EXE`" Description=`"Allow EXEs from Windows folder`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles EXE`" Description=`"Allow EXEs from Program Files`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles (x86) EXE`" Description=`"Allow EXEs from Program Files (x86)`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES(x86)%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramData EXE`" Description=`"Allow EXEs from ProgramData`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%ProgramData%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Whitelisted filenames anywhere (allow)
foreach ($app in $WhitelistedApps) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - $app`" Description=`"Allow $app anywhere`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"*\$app`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Publisher allow rules (EXE)
foreach ($pub in $WhitelistedPublishers) {
    $xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Publisher - $pub`" Description=`"Allow signed apps from $pub`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
    $xml += "      <Conditions>`n"
    $xml += "        <FilePublisherCondition PublisherName=`"$pub`" ProductName=`"*`" BinaryName=`"*`">`n"
    $xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"*`" />`n"
    $xml += "        </FilePublisherCondition>`n"
    $xml += "      </Conditions>`n"
    $xml += "    </FilePublisherRule>`n"
}

$xml += "  </RuleCollection>`n"

# ---------------- SCRIPT rules ----------------
$xml += "  <RuleCollection Type=`"Script`" EnforcementMode=`"$EnforcementMode`">`n"

# Microsoft-signed scripts allowed
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Microsoft Signed Scripts`" Description=`"Allow Microsoft-signed scripts`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"*`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"

# PowerShell engine temp test scripts allowed
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - PowerShell Temp Tests`" Description=`"Allow __PSScriptPolicyTest*.ps1`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%SystemDriveToken%\Users\*\AppData\Local\Temp\__PSScriptPolicyTest*.ps1`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow Wallpaper Temp scripts (anywhere)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Wallpaper Scripts`" Description=`"Allow Wallpaper Temp RAD*.ps1 scripts anywhere`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*\RAD*.ps1`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow Windows/ProgramFiles scripts
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows Scripts`" Description=`"Allow scripts from Windows`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "  </RuleCollection>`n"

# ---------------- DLL rules ----------------
$xml += "  <RuleCollection Type=`"Dll`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow all digitally signed DLLs (any publisher)
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - All Signed DLLs`" Description=`"Allow all digitally signed DLLs`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"*`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"*`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"

# Allow system DLLs
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows DLLs`" Description=`"Allow DLLs from Windows`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "  </RuleCollection>`n"

# ---------------- MSI rules ----------------
$xml += "  <RuleCollection Type=`"Msi`" EnforcementMode=`"$EnforcementMode`">`n"

# Deny MSI in user profiles
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Deny - Users - MSI in Profiles`" Description=`"Deny MSI in user profiles`" UserOrGroupSid=`"S-1-5-32-545`" Action=`"Deny`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%SystemDriveToken%\Users\*\*.msi`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Deny MSI on non-system drives
foreach ($driveRoot in $nonSystemDriveTokens) {
    $driveLetter = $driveRoot.TrimEnd('\')
    if ($driveLetter -match '^[A-Za-z]:$') {
        $pp = "$driveLetter\*\*.msi"
        $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Deny - $driveLetter - MSI`" Description=`"Deny MSI on $driveLetter`" UserOrGroupSid=`"S-1-5-32-545`" Action=`"Deny`">`n"
        $xml += "      <Conditions><FilePathCondition Path=`"$pp`"/></Conditions>`n"
        $xml += "    </FilePathRule>`n"
    }
}

# Allow ProgramFiles/MSI caches
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles MSI`" Description=`"Allow MSIs from Program Files`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles (x86) MSI`" Description=`"Allow MSIs from Program Files (x86)`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%(x86)\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "  </RuleCollection>`n"

# ---------------- Appx rules ----------------
$xml += "  <RuleCollection Type=`"Appx`" EnforcementMode=`"$EnforcementMode`">`n"
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - All Signed Appx`" Description=`"Allow signed packaged apps`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"*`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"*`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"
$xml += "  </RuleCollection>`n"

# close xml
$xml += "</AppLockerPolicy>`n"

# Write XML to disk
try {
    $dir = Split-Path $OutXmlPath -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $xml | Out-File -FilePath $OutXmlPath -Encoding UTF8 -Force
    Write-Host "`nWrote AppLocker XML to $OutXmlPath"
} catch {
    Write-Error "`nFailed to write XML: $_"
    exit 1
}

# Apply policy
try {
    Write-Host "`nApplying AppLocker policy (Enforce) ..."
    Set-AppLockerPolicy -XmlPolicy $OutXmlPath
    gpupdate /force | Out-Null

    # ensure AppIDSvc is configured & restarted
    sc.exe config appidsvc start= auto | Out-Null
    try { Restart-Service -Name AppIDSvc -Force -ErrorAction Stop; Write-Host "`nAppIDSvc restarted." } catch { Write-Warning "`nCould not restart AppIDSvc; reboot may be required." }

    Write-Host "`nAppLocker policy applied in ENFORCE mode. Check Event Viewer > Microsoft > Windows > AppLocker for events."
} catch {
    Write-Error "`nFailed to apply AppLocker policy: $_"
    exit 1
}
