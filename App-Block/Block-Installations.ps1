<#
AppLocker Policy in ENFORCE mode
- Local Admins + Domain Admins allowed everywhere.
- Standard Users only allowed:
  * Windows, Program Files, Program Files (x86), ProgramData
  * Microsoft-signed DLLs + Scripts (system-critical)
  * Store Apps (Appx)
  * PowerShell engine test scripts (__PSScriptPolicyTest*.ps1 in Temp)
  * Wallpaper policy temp scripts (RAD*.ps1 in Temp)
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

	[string[]]$WhitelistedApps = @(
	"Diagsmart*.exe",
	"Uninstall*.exe",
	"ITD_EFILING_JFX*.jar"
	),
	
	[string[]]$WhitelistedPaths = @(
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
	"%OSDRIVE%\FG WILSON*\*",
	"%OSDRIVE%\USERS\*\APPDATA\LOCAL\MICROSOFT\*"
	),
	
	[string[]]$WhitelistedPublishers = @(
	"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
	"CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US",
	"CN=Oracle America, O=Oracle America, L=Redwood City, S=California, C=US",
	"CN=ZOHO Corporation Private Limited, O=ZOHO Corporation Private Limited, L=Chennai, S=Tamil Nadu, C=IN",
	"CN=Adobe Inc., O=Adobe Inc., L=San Jose, S=ca, C=US"
	),
	
	[string[]]$WhitelistedScripts = @(
	"%OSDRIVE%\Users\*\AppData\Local\Temp\TempScript.ps1",
	"%OSDRIVE%\USERS\*\APPDATA\LOCAL\TEMP\RAD*.ps1",
	"%OSDRIVE%\USERS\*\APPDATA\LOCAL\TEMP\__PSSCRIPTPOLICYTEST*.ps*",
	"%OSDRIVE%\Users\*\AppData\Local\Temp\IPW*.*",
	"D:\jarfile\*.jar"
	)    # default temp script patterns included
)

	# Who should the whitelisted scripts/paths be allowed for?
	# Use "S-1-1-0" for Everyone (default), or "S-1-5-32-544" for Local Administrators.
	[string]$AdministratorsSid = "S-1-5-32-544"
	[string]$UsersSid = "S-1-5-32-545"
	[string]$EveryoneSid = "S-1-1-0"

# Checking Windows Compatibility
$OSType = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($OSType -ne 1) {
    Write-Host "Non-client OS detected. Exiting script."
    exit
}

# Normalize and deduplicate WhitelistedScripts to avoid duplicate rules and inconsistent slashes
$WhitelistedScripts = ($WhitelistedScripts | ForEach-Object {
    if ($_ -eq $null) { return }
    $_.ToString().Trim() -replace '/','\'
}) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

# Normalize and deduplicate WhitelistedPaths
$WhitelistedPaths = ($WhitelistedPaths | ForEach-Object {
    if ($_ -eq $null) { return }
    $p = $_.ToString().Trim() -replace '/', '\'
    $p = $p -replace '\\{2,}', '\'
    $p
}) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

# ---------------- XML helper ----------------
function XmlEscape([string]$s) {
    if ($null -eq $s) { return "" }
    return [System.Security.SecurityElement]::Escape($s)
}

# helper for GUIDs
function New-RuleGuid { return [guid]::NewGuid().ToString() }

# Use standard SystemDrive token for XML paths
$SystemDriveToken = "%OSDRIVE%"

# discover non-system fixed drives (only roots like C:\, D:\ etc.)
$systemRoot = ($env:SystemDrive.TrimEnd('\') + '\')
$nonSystemDrives = Get-PSDrive -PSProvider FileSystem |
    Where-Object {
        # accept roots like "D:\"
        ($_.Root -ne $systemRoot) -and
        ($_.Root -match '^[A-Za-z]:\\$')
    } |
    ForEach-Object { $_.Root } -ErrorAction SilentlyContinue
if ($null -eq $nonSystemDrives) { $nonSystemDrives = @() }

$ErrorActionPreference = 'Stop'

# --- Create timestamped backup folder ---
# create root if missing
$backupRoot = "C:\PolicyBackup"
if (-not (Test-Path $backupRoot)) { New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null }

# create a timestamped folder (keeps your "random-looking" style if desired)
$tsFolder = Get-Date -Format "MMyyyyddHHmmss"   # your original style; change if you prefer sortable ts
$backupDir = Join-Path $backupRoot $tsFolder
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

# write metadata (human-friendly timestamp + details) into the timestamped folder
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

# Block all executable, script, and installer types
$installerPatterns = @("*.exe","*.com","*.bat","*.cmd","*.ps1","*.vbs","*.js","*.jse","*.wsf","*.wsh","*.msi","*.msp")

# Deny installers on all fixed non-system drives
foreach ($driveRoot in $nonSystemDrives) {
    $driveLetter = $driveRoot.TrimEnd('\')   # "D:"
    if ($driveLetter -match '^[A-Za-z]:$') {
        foreach ($pat in $installerPatterns) {
            $ppRaw  = "$driveLetter\*\$pat"      # e.g. "D:\*\*.exe"
            $pp     = XmlEscape($ppRaw)
            $name   = XmlEscape("Deny - $driveLetter - $pat")
            $desc   = XmlEscape("Deny $pat files on $driveLetter for standard users")
            $user   = XmlEscape($UsersSid)       # <-- keep this as Users SID

            $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"$name`" Description=`"$desc`" UserOrGroupSid=`"$user`" Action=`"Deny`">`n"
            $xml += "      <Conditions><FilePathCondition Path=`"$pp`"/></Conditions>`n"
            $xml += "    </FilePathRule>`n"
        }
    }
}

# Allow Local Admins everywhere (EXE)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All`" Description=`"Local Administrators allowed everywhere`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow system paths for everyone (EXE)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows EXE`" Description=`"Allow EXEs from Windows folder`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles EXE`" Description=`"Allow EXEs from Program Files`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles (x86) EXE`" Description=`"Allow EXEs from Program Files (x86)`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES(x86)%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow ProgramData for EXEs (everyone)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramData EXE`" Description=`"Allow EXEs from ProgramData`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%ProgramData%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Whitelisted filenames anywhere (allow)
foreach ($app in $WhitelistedApps) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - $app`" Description=`"Allow $app anywhere`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"*\$app`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Whitelisted paths (EXE) — allow EXEs from explicit folders
foreach ($p in $WhitelistedPaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }

    # ensure path pattern ends with wildcard so folder root is covered
    $path = $p
    # if user passed a folder path (no wildcard), append \* 
    if ($path -notmatch '[*?]') {
        if ($path -match '\\$') { $path = $path + '*' } else { $path = $path + '\*' }
    }

    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Path - $path`" Description=`"Allow EXEs from $path`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$path`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Publisher allow rules (EXE)
foreach ($pub in $WhitelistedPublishers) {
    $pubEsc = XmlEscape($pub)
    $xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Publisher - $pubEsc`" Description=`"Allow signed apps from $pubEsc`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions>`n"
    $xml += "        <FilePublisherCondition PublisherName=`"$pubEsc`" ProductName=`"*`" BinaryName=`"*`">`n"
    $xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
    $xml += "        </FilePublisherCondition>`n"
    $xml += "      </Conditions>`n"
    $xml += "    </FilePublisherRule>`n"
}

$xml += "  </RuleCollection>`n"

# ---------------- SCRIPT rules ----------------
$xml += "  <RuleCollection Type=`"Script`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Local Admins everywhere for Scripts (added so admins retain full access)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All (Scripts)`" Description=`"Local Administrators allowed everywhere for scripts`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Microsoft-signed scripts allowed
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Microsoft Signed Scripts`" Description=`"Allow Microsoft-signed scripts`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"

# ---- WhitelistedScripts support (allow either filename patterns anywhere or explicit paths) ----
foreach ($s in $WhitelistedScripts) {
    if ([string]::IsNullOrWhiteSpace($s)) { continue }

    # If entry looks like a path (contains backslash, forward slash, percent token, or drive letter), treat as path.
    if ($s -match '[\\/]' -or $s -match '[:%]') {
        $conditionPath = $s
    } else {
        # treat as filename/pattern and allow anywhere
        $conditionPath = "*\$s"
    }

    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Script - $s`" Description=`"Allow whitelisted script: $s`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$conditionPath`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Whitelisted paths (Scripts) — allow scripts from explicit folders
foreach ($p in $WhitelistedPaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }

    $path = $p
    if ($path -notmatch '[*?]') {
        if ($path -match '\\$') { $path = $path + '*' } else { $path = $path + '\*' }
    }

    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Script Path - $path`" Description=`"Allow scripts from $path`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$path`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Allow Windows/ProgramFiles/ProgramData scripts (everyone)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows Scripts`" Description=`"Allow scripts from Windows`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles Scripts`" Description=`"Allow scripts from Program Files`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles (x86) Scripts`" Description=`"Allow scripts from Program Files (x86)`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES(x86)%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramData Scripts`" Description=`"Allow scripts from ProgramData`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%ProgramData%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "  </RuleCollection>`n"

# ---------------- DLL rules ----------------
$xml += "  <RuleCollection Type=`"Dll`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Local Admins everywhere for DLLs (added so admins retain full access)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All (DLLs)`" Description=`"Local Administrators allowed everywhere for DLLs`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow all digitally signed DLLs (any publisher)
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - All Signed DLLs`" Description=`"Allow all digitally signed DLLs`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"*`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"

# Allow system DLLs and core program folders
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows DLLs`" Description=`"Allow DLLs from Windows`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - DLL - ProgramFiles`" Description=`"Allow DLLs from Program Files`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - DLL - ProgramFiles (x86)`" Description=`"Allow DLLs from Program Files (x86)`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES(x86)%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

foreach ($p in $WhitelistedPaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }

    $path = $p
    if ($path -notmatch '[*?]') {
        if ($path -match '\\$') { $path = $path + '*' } else { $path = $path + '\*' }
    }

    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - DLL Path - $path`" Description=`"Allow DLLs from $path`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$path`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Allow ProgramData for DLLs (everyone)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - DLL - ProgramData`" Description=`"Allow DLLs from ProgramData`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%ProgramData%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "  </RuleCollection>`n"

# ---------------- MSI rules ----------------
$xml += "  <RuleCollection Type=`"Msi`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Local Admins everywhere for MSI (added so admins retain full access)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All (MSI)`" Description=`"Local Administrators allowed everywhere for MSI`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Whitelisted filenames anywhere (MSI)
foreach ($app in $WhitelistedApps) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - MSI - $app`" Description=`"Allow MSI filename/pattern: $app`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"*\$app`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

foreach ($p in $WhitelistedPaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }

    $path = $p
    if ($path -notmatch '[*?]') {
        if ($path -match '\\$') { $path = $path + '*' } else { $path = $path + '\*' }
    }

    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - MSI Path - $path`" Description=`"Allow MSIs from $path`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$path`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Allow ProgramFiles/MSI caches
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles MSI`" Description=`"Allow MSIs from Program Files`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles (x86) MSI`" Description=`"Allow MSIs from Program Files (x86)`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES(x86)%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow ProgramData for MSIs (everyone)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramData MSI`" Description=`"Allow MSIs from ProgramData`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%ProgramData%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "  </RuleCollection>`n"

# ---------------- Appx rules ----------------
$xml += "  <RuleCollection Type=`"Appx`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Local Admins everywhere for Appx (added so admins retain full access)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All (Appx)`" Description=`"Local Administrators allowed everywhere for Appx`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - All Signed Appx`" Description=`"Allow signed packaged apps`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"*`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
$xml += "        </FilePublisherCondition>`n"
$xml += "      </Conditions>`n"
$xml += "    </FilePublisherRule>`n"

# Whitelisted filenames anywhere (Appx)
foreach ($app in $WhitelistedApps) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Appx - $app`" Description=`"Allow Appx filename/pattern: $app`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"*\$app`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

foreach ($p in $WhitelistedPaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }

    $path = $p
    if ($path -notmatch '[*?]') {
        if ($path -match '\\$') { $path = $path + '*' } else { $path = $path + '\*' }
    }

    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Appx Path - $path`" Description=`"Allow Appxs from $path`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$path`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

$xml += "  </RuleCollection>`n"

# close xml
$xml += "</AppLockerPolicy>`n"

# Write XML to disk
try {
    $dir = Split-Path $OutXmlPath -Parent
#Reset to default
Copy-Item -Path $dir\FullReset.xml $OutXmlPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $xml | Out-File -FilePath $OutXmlPath -Encoding UTF8 -Force
    Write-Host "`nWrote AppLocker XML to $OutXmlPath"
} catch {
    Write-Error "`nFailed to write XML: $_"
    exit 1
}

# Add "Install as administrator" option for .MSI files
try {
    $baseKey = "Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\runas"
    $cmdKey  = "$baseKey\command"

    # Create parent key if not exists
    if (-not (Test-Path $baseKey)) {
        New-Item -Path $baseKey -Force | Out-Null
    }

    # Set the menu text
    Set-ItemProperty -Path $baseKey -Name '(default)' -Value "Install as administrator"

    # Create command subkey if missing
    if (-not (Test-Path $cmdKey)) {
        New-Item -Path $cmdKey -Force | Out-Null
    }

    # Set command line to use msiexec with elevation
    Set-ItemProperty -Path $cmdKey -Name '(default)' -Value 'msiexec.exe /i "%1"'

    Write-Host "`n'Install as administrator' option added to MSI right-click menu."
    Write-Host "   Right-click any .MSI file -> You'll see 'Install as administrator'."
}
catch {
    Write-Error "Failed to add context menu: $_"
}

# Apply policy
try {
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