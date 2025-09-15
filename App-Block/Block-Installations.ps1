<#
AppLocker Policy in ALLOW-LIST mode for Users; full access for Administrators.
- Administrators allowed everywhere (local admins and domain admins who are members).
- Standard Users allowed only explicit system folders, trusted publishers, whitelisted filenames, and whitelisted explicit paths.
- Centralized whitelisted paths include %WINDIR%, %PROGRAMFILES%, %PROGRAMFILES(x86)%, %ProgramData% to keep XML small.
- Backups of AppLocker, SRP, WDAC are created in C:\PolicyBackup\<timestamp>
- Test in AuditOnly first.
#>

param (
    [string]$OutXmlPath = "C:\ProgramData\AppLocker\Enforce-AppLocker-Block.xml",

    [ValidateSet("Enabled","AuditOnly")]
    [string]$EnforcementMode = "Enabled",   # Use "AuditOnly" for testing; switch to "Enabled" when confirmed.

    [string[]]$WhitelistedApps = @(
        "Diagsmart*.exe",
        "Uninstall*.exe",
        "ITD_EFILING_JFX*.jar"
    ),

    [string[]]$WhitelistedPaths = @(
        "%WINDIR%\*",
        "%PROGRAMFILES%\*",
        "%PROGRAMFILES(x86)%\*",
        "%ProgramData%\*",
        "%OSDRIVE%\Siemens\*",
        "%OSDRIVE%\Java\*",
        "%OSDRIVE%\USERS\*\.SWT\*",
        "%OSDRIVE%\USERS\*\TEAMCENTER\*",
        "D:\ManageEngine*\*",
        "E:\ManageEngine*\*",
        "%OSDRIVE%\DEVSUITEHOME*\*",
        "%OSDRIVE%\QUEST_TOAD\*",
        "%OSDRIVE%\USERS\*\APPDATA\LOCALLOW\ORACLE\*",
        "%OSDRIVE%\USERS\Administrator\APPDATA\LOCALLOW\ORACLE\*",
        "%OSDRIVE%\Users\*\Appdata\Local\Packages\*",
        "%OSDRIVE%\FG WILSON*\*"
    ),

    [string[]]$WhitelistedPublishers = @(
        "CN=Microsoft Corporation, O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US",
        "CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US",
        "CN=Oracle America, O=Oracle America, L=Redwood City, S=California, C=US",
        "CN=ZOHO Corporation Private Limited, O=ZOHO Corporation Private Limited, L=Chennai, S=Tamil Nadu, C=IN"
    ),

    [string[]]$WhitelistedScripts = @(
        "%OSDRIVE%\Users\*\AppData\Local\Temp\TempScript.ps1",
        "%OSDRIVE%\USERS\*\APPDATA\LOCAL\TEMP\RAD*.ps1",
        "%OSDRIVE%\USERS\*\APPDATA\LOCAL\TEMP\__PSSCRIPTPOLICYTEST*.ps*",
        "%OSDRIVE%\Users\*\AppData\Local\Temp\IPW*.*",
        "%OSDRIVE%\USERS\*\APPDATA\LOCALLOW\ORACLE\*.msi",
        "D:\jarfile\*.jar"
    )
)

# SIDs
[string]$AdministratorsSid = "S-1-5-32-544"   # local Administrators group (covers domain admins if they are members)
[string]$UsersSid = "S-1-5-32-545"            # built-in Users group

# check client OS
$OSType = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($OSType -ne 1) {
    Write-Host "Non-client OS detected. Exiting script."
    exit
}

# normalize whitelists
$WhitelistedScripts = ($WhitelistedScripts | ForEach-Object {
    if ($_ -eq $null) { return }
    $_.ToString().Trim() -replace '/','\'
}) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

$WhitelistedPaths = ($WhitelistedPaths | ForEach-Object {
    if ($_ -eq $null) { return }
    $p = $_.ToString().Trim() -replace '/', '\'
    $p = $p -replace '\\{2,}', '\'
    $p
}) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

# helpers
function XmlEscape([string]$s) {
    if ($null -eq $s) { return "" }
    return [System.Security.SecurityElement]::Escape($s)
}
function New-RuleGuid { return [guid]::NewGuid().ToString() }

$SystemDriveToken = "%OSDRIVE%"

# detect non-system fixed drives like D:\, E:\
$systemRoot = ($env:SystemDrive.TrimEnd('\') + '\')
$nonSystemDrives = Get-PSDrive -PSProvider FileSystem |
    Where-Object { ($_.Root -ne $systemRoot) -and ($_.Root -match '^[A-Za-z]:\\$') } |
    ForEach-Object { $_.Root } -ErrorAction SilentlyContinue
if ($null -eq $nonSystemDrives) { $nonSystemDrives = @() }

$ErrorActionPreference = 'Stop'

# backup folder
$backupRoot = "C:\PolicyBackup"
if (-not (Test-Path $backupRoot)) { New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null }
$tsFolder = Get-Date -Format "MMyyyyddHHmmss"
$backupDir = Join-Path $backupRoot $tsFolder
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

$humanTs = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$meta = @{
    CreatedAt        = $humanTs
    BackupFolderName = $tsFolder
    BackupFolderPath = $backupDir
    ComputerName     = $env:COMPUTERNAME
    User             = [Environment]::UserName
    ScriptPath       = $MyInvocation.MyCommand.Path
}
$metaFile = Join-Path $backupDir 'backup-info.txt'
$meta.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" } | Out-File -FilePath $metaFile -Encoding UTF8 -Force
Write-Host "=== Creating Backup ($backupDir) ==="

# backup AppLocker effective policy
try {
    $xmlPath = Join-Path $backupDir "AppLocker-Backup.xml"
    Get-AppLockerPolicy -Effective -Xml | Out-File -FilePath $xmlPath -Encoding UTF8
    Write-Host "`nAppLocker backed up to $xmlPath"
} catch { Write-Warning "`nAppLocker backup failed: $_" }

# backup SRP
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer"
if (Test-Path $regPath) {
    try {
        $regFile = Join-Path $backupDir "SRP-Backup.reg"
        reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer" $regFile /y | Out-Null
        Write-Host "`nSRP registry exported to $regFile"
    } catch { Write-Warning "`nSRP backup failed." }
} else { Write-Host "`nSRP registry path not found. Skipping backup." }

# backup WDAC artifacts if present
try {
    $wdacPath = Join-Path $backupDir "WDAC-Policies"
    New-Item -ItemType Directory -Path $wdacPath -Force | Out-Null
    Get-ChildItem -Path "C:\Windows\System32\CodeIntegrity\*" -Include '*.cipolicy','*.xml' -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-Item -Path $_.FullName -Destination $wdacPath -Force }
    $found = Get-ChildItem -Path $wdacPath -ErrorAction SilentlyContinue
    if ($found) { Write-Host "`nAttempted WDAC policy backup (if any) to $wdacPath" } else { Write-Host "`nNo WDAC policy files found to back up." }
} catch { Write-Warning "`nWDAC backup step failed: $_" }

Write-Host "`n=== Backup complete. Building AppLocker XML... ==="

$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
"@

# Helper loop: create FilePathRule for Users from $WhitelistedPaths
function Add-Users-Path-RulesToXml {
    param($collectionName)
    foreach ($p in $WhitelistedPaths) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $path = $p
        if ($path -notmatch '[*?]') {
            if ($path -match '\\$') { $path = $path + '*' } else { $path = $path + '\*' }
        }
        $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Users - Path - $path`" Description=`"Allow Users from $path ($collectionName)`" UserOrGroupSid=`"$UsersSid`" Action=`"Allow`">`n"
        $xml += "      <Conditions><FilePathCondition Path=`"$path`"/></Conditions>`n"
        $xml += "    </FilePathRule>`n"
    }
}

# ---------------- EXE rules ----------------
$xml += "  <RuleCollection Type=`"Exe`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Admins everything
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Admins - All EXE`" Description=`"Allow Administrators everything (EXE)`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow Users based on centralized whitelist paths
Add-Users-Path-RulesToXml -collectionName "Exe"

# Allow Users signed apps from trusted publishers (if listed)
foreach ($pub in $WhitelistedPublishers) {
    $pubEsc = XmlEscape($pub)
    $xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Users - Publisher - $pubEsc`" Description=`"Allow signed EXE from $pubEsc for Users`" UserOrGroupSid=`"$UsersSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions>`n"
    $xml += "        <FilePublisherCondition PublisherName=`"$pubEsc`" ProductName=`"*`" BinaryName=`"*`">`n"
    $xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
    $xml += "        </FilePublisherCondition>`n"
    $xml += "      </Conditions>`n"
    $xml += "    </FilePublisherRule>`n"
}

# Allow Users specific filenames anywhere (whitelisted apps)
foreach ($app in $WhitelistedApps) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Users - File - $app`" Description=`"Allow specific filename for Users: $app`" UserOrGroupSid=`"$UsersSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"*\$app`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

$xml += "  </RuleCollection>`n"

# ---------------- SCRIPT rules ----------------
$xml += "  <RuleCollection Type=`"Script`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Admins everywhere for scripts
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Admins - All Scripts`" Description=`"Allow Administrators everything (Scripts)`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow Users based on centralized whitelist paths (for scripts)
Add-Users-Path-RulesToXml -collectionName "Script"

# Allow Users Microsoft-signed scripts (keeps system-signed scripts working)
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Users - Microsoft Signed Scripts`" Description=`"Allow Microsoft-signed scripts for Users`" UserOrGroupSid=`"$UsersSid`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"

# Whitelisted scripts (explicit or filename patterns) for Users
foreach ($s in $WhitelistedScripts) {
    if ([string]::IsNullOrWhiteSpace($s)) { continue }
    if ($s -match '[\\/]' -or $s -match '[:%]') { $conditionPath = $s } else { $conditionPath = "*\$s" }

    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Users - Script - $s`" Description=`"Allow whitelisted script for Users: $s`" UserOrGroupSid=`"$UsersSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$conditionPath`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

$xml += "  </RuleCollection>`n"

# ---------------- DLL rules ----------------
$xml += "  <RuleCollection Type=`"Dll`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Admins everywhere (DLL)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Admins - All DLLs`" Description=`"Allow Administrators everything (DLLs)`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow Users based on centralized whitelist paths (for DLLs)
Add-Users-Path-RulesToXml -collectionName "Dll"

# Allow Users Microsoft-signed DLLs (system-critical)
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Users - Microsoft Signed DLLs`" Description=`"Allow Microsoft-signed DLLs for Users`" UserOrGroupSid=`"$UsersSid`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"

$xml += "  </RuleCollection>`n"

# ---------------- MSI rules ----------------
$xml += "  <RuleCollection Type=`"Msi`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Admins everywhere (MSI)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Admins - All MSI`" Description=`"Allow Administrators everything (MSI)`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow Users based on centralized whitelist paths (for MSI)
Add-Users-Path-RulesToXml -collectionName "Msi"

# Allow Users specifically whitelisted MSI filenames
foreach ($app in $WhitelistedApps) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Users - MSI - $app`" Description=`"Allow MSI filename/pattern for Users: $app`" UserOrGroupSid=`"$UsersSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"*\$app`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

$xml += "  </RuleCollection>`n"

# ---------------- Appx rules ----------------
$xml += "  <RuleCollection Type=`"Appx`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Admins everywhere (Appx)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Admins - All Appx`" Description=`"Allow Administrators everything (Appx)`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow Users signed Appx packages (store apps)
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Users - Signed Appx`" Description=`"Allow signed Appx packages for Users`" UserOrGroupSid=`"$UsersSid`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"*`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"

# Allow Users Appx from whitelisted paths
Add-Users-Path-RulesToXml -collectionName "Appx"

$xml += "  </RuleCollection>`n"

# close AppLockerPolicy XML
$xml += "</AppLockerPolicy>`n"

# write XML to disk
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
	# Clear any existing AppLocker rules
    Write-Host "`nClearing existing AppLocker policy..."
    Set-AppLockerPolicy -XMLPolicy "<AppLockerPolicy Version=`"1`"></AppLockerPolicy>" -Merge
    Write-Host "Existing AppLocker policy cleared."

	# Apply the new one
    Write-Host "`nApplying AppLocker policy ..."
    Set-AppLockerPolicy -XmlPolicy $OutXmlPath
    gpupdate /force | Out-Null

    # ensure AppIDSvc is configured & restarted
    sc.exe config appidsvc start= auto | Out-Null
    try { Restart-Service -Name AppIDSvc -Force -ErrorAction Stop; Write-Host "`nAppIDSvc restarted." } catch { Write-Warning "`nCould not restart AppIDSvc; reboot may be required." }

    Write-Host "`nAppLocker policy applied. Check Event Viewer > Applications and Services Logs > Microsoft > Windows > AppLocker for events."
} catch {
    Write-Error "`nFailed to apply AppLocker policy: $_"
    exit 1
}
