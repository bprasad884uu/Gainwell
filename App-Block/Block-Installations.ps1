<#
Clean minimal AppLocker script (Allow-only).
- Admins allowed everywhere.
- Everyone allowed for system folders and explicit whitelisted publishers/paths/files/scripts.
- No explicit Deny rules (implicit deny remains for anything not allowed).
- Backs up AppLocker/SRP/WDAC to C:\PolicyBackup\<timestamp>.
#>

param (
    [string]$OutXmlPath = "C:\ProgramData\AppLocker\Enforce-AppLocker-Block.xml",

    [ValidateSet("Enabled","AuditOnly")]
    [string]$EnforcementMode = "Enabled",    # Start with AuditOnly for testing

    [string[]]$WhitelistedApps = @(
		"DIAGSMART*.exe",
		"Uninstall*.exe",
		"uninst.exe",
		"Generic RBI Converter*.EXE",	#for Accounts
		"On-premises data gateway*.exe",
		"PROSCAN.exe",
		"javaw.exe",
		"ZoomInstaller*.exe",
		"Zoom_cm*.exe",
		"MSTeams*.exe",
		"Mechanic.exe",
		"DCEditor.exe",
		"FLASHUTIL.EXE",
		"ASCENT.exe",
		"hrmstipl.exe",
		"PresentationLauncher.exe",
		"WinSCP.exe",
		"cardPresso*.exe",
		"Etk.exe",
		"DIAGWINFORMS.EXE",
		"CRISSIGNER.EXE",
		"REM_RC_Desktop_v1.85.3.2.exe",
		"EOWP.19.2.91.0.EXE",
		"msiexec.exe",
		"GSTSigner.exe",
		"MB_RELAY_FRONTEND.EXE",
		"AU_.EXE",
		"KSOLAUNCH.EXE",
		"KSOMISC.EXE",
		"CrisSigner.exe",
		"hexcal_3.52.exe",
		"PCM_DOWNLOADER.EXE"
    ),
	
	[string[]]$WhitelistedMsiNames = @(
		"DataMovement.PersonalGatewayComponents.msi",
		"e-Filing_F145-F146_V1.0.msi"
	),

    [string[]]$WhitelistedPaths = @(
		"D:\ManageEngine*\*",
		"E:\ManageEngine*\*",
		"%OSDRIVE%\Siemens\*",
		"%OSDRIVE%\Java\*",
		"%ProgramFiles%\WindowsApps\*",
        "%OSDRIVE%\Users\*\AppData\Local\Microsoft\Teams\*",
        "%OSDRIVE%\Users\*\AppData\Local\Programs\*",
        "%ProgramData%\Microsoft\Windows\Start Menu\Programs\*",
		"%OSDRIVE%\Users\*\.SWT\*",
		"%OSDRIVE%\Users\*\TEAMCENTER\*",
		"%OSDRIVE%\DEVSUITEHOME*\*",
		"%OSDRIVE%\QUEST_TOAD\*",
		"%OSDRIVE%\Users\*\AppData\LocalLow\ORACLE\*",
		"%OSDRIVE%\Users\*\AppData\Local\Packages\*",
		"%OSDRIVE%\FG WILSON*\*",
		"%OSDRIVE%\Users\*\AppData\Local\MICROSOFT\*",
		"%OSDRIVE%\Users\*\AppData\Local\TEMP\JNA*\JNA*.*",
		"%OSDRIVE%\ProgramData\Mercedes-Benz\*",			#Xentry
		"%OSDRIVE%\ProgramData\Daimler-Truck\*",			#Xentry
		"%OSDRIVE%\ProgramData\ZenZefiT\*",					#Xentry
		"%OSDRIVE%\Users\*\AppData\Local\CHROMIUM*\*",		#Xentry
		"D:\Zmysql-query-browser*\MySQL Query Browser*\*",
		"D:\CBT\*",
		"%OSDRIVE%\GRADE-X_DATA\*",
		"%OSDRIVE%\Users\*\AppData\Local\APPS\*",
		"%OSDRIVE%\Users\*\AppData\Local\Programs\Naukri Launcher\*",
		"%OSDRIVE%\IREPSSigner\*",
		"%OSDRIVE%\Users\*\AppData\Roaming\Polycom\*",
		"%OSDRIVE%\Program Files (x86)\Bosch\*",
		"D:\WEICHAI\*",
		"%PROGRAMFILES%\Java\*\bin\*",
		"%PROGRAMFILES(x86)%\Java\*\bin\*",
		"%OSDRIVE%\Users\*\AppData\Roaming\ZOOM\*",
		"%OSDRIVE%\Users\*\AppData\Local\Programs\edison-shift-reporter\*",
		"%OSDRIVE%\Users\*\AppData\Local\Grammarly\*",
		"%OSDRIVE%\Users\*\AppData\Local\Programs\device-controller\*",
		"D:\EARTHWORKS TRAINING SIMULATOR 2.21.40\SIMULATOR\*",
		"%OSDRIVE%\Users\*\AppData\Local\CITRIX\*",
		"%OSDRIVE%\g0xin\*",
		"%OSDRIVE%\Users\*\AppData\Roaming\Yealink\Yealink Wireless Presentation Pod\*",
		"D:\TRIAL\*",
		"%OSDRIVE%\CADNEST\*",
		"%OSDRIVE%\QUEST SOFTWARE\*",
		"%OSDRIVE%\USERS\*\APPDATA\ROAMING\QUEST SOFTWARE\*",
		"%OSDRIVE%\USERS\*\Desktop\HDFC BANK\*",
		"%OSDRIVE%\USERS\*\APPDATA\LOCAL\PROGRAMS\ITDE-FILING_F145-F146\*",
		"%OSDRIVE%\USERS\*\APPDATA\ROAMING\LeroySome\*",
		"%OSDRIVE%\USERS\*\APPDATA\LOCAL\DROPBOX\*",
		"%OSDRIVE%\USERS\*\APPDATA\ROAMING\DROPBOX\*",
		"%OSDRIVE%\GSTARSOFT\DWGFASTVIEW\*",
		"%OSDRIVE%\USERS\*\APPDATA\ROAMING\LEROYSOMER\*",
		"E:\OneDrive - Gainwell Commosales Private Limited\D Drive of old Laptop\D colon folders\Training modules all\*",
		"D:\Program Files (x86)\diagsmart\*",
		"%OSDRIVE%\PDS Connector\*",
		"%OSDRIVE%\CrisSigner\CrisSigner\*"
    ),

    [string[]]$WhitelistedPublishers = @(
		# Microsoft
		"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US",
		# Google
		"O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US",
		# Oracle
		"O=ORACLE AMERICA, INC., L=REDWOOD CITY, S=CALIFORNIA, C=US",
		# Adobe
		"O=ADOBE INC., L=SAN JOSE, S=CALIFORNIA, C=US",
		# Zoho
		"O=ZOHO CORPORATION PRIVATE LIMITED, L=CHENNAI, S=TAMIL NADU, C=IN",
		# VMware
		"O=VMWARE, INC., L=PALO ALTO, S=CALIFORNIA, C=US",
		# Cisco
		"O=CISCO SYSTEMS, INC., L=SAN JOSE, S=CALIFORNIA, C=US",
		# Citrix
		"O=CITRIX SYSTEMS, INC., L=FORT LAUDERDALE, S=FLORIDA, C=US",
		# Zoom
		"O=ZOOM VIDEO COMMUNICATIONS, INC., L=SAN JOSE, S=CALIFORNIA, C=US",
		# HP
		"O=HP INC., L=PALO ALTO, S=CALIFORNIA, C=US",
		# Dell
		"O=DELL INC, L=ROUND ROCK, S=TEXAS, C=US",
		# Lenovo
		"O=LENOVO (SINGAPORE) PTE. LTD., L=SINGAPORE, C=SG",
		# Intel
		"O=INTEL CORPORATION, L=SANTA CLARA, S=CALIFORNIA, C=US",
		# NVIDIA
		"O=NVIDIA CORPORATION, L=SANTA CLARA, S=CALIFORNIA, C=US",
		# AMD
		"O=ADVANCED MICRO DEVICES, INC., L=SANTA CLARA, S=CALIFORNIA, C=US",
		# WEICHAI
		"O=WEICHAI POWER CO., LTD., S=???, C=CN"
    ),

    [string[]]$WhitelistedScripts = @(
		"%OSDRIVE%\Users\*\AppData\Local\Temp\TempScript.ps1",
		"%OSDRIVE%\Users\*\AppData\Local\TEMP\RAD*.TMP.ps1",
		"%OSDRIVE%\Users\*\AppData\Local\TEMP\__PSSCRIPTPOLICYTEST*.ps*",
		"%OSDRIVE%\Users\*\AppData\Local\Temp\IPW*.*",
		"%OSDRIVE%\Users\*\AppData\Local\TEMP\*\START.BAT",			#For Xentry Software Installation
		"D:\Outlook_Mail_Merge_Attachment_v1.1.9_BETA\Outlook Mail Merge Attachment.vbs",
		"*.ica"
    )
)

[string]$AdministratorsSid = "S-1-5-32-544"
[string]$UsersSid = "S-1-5-32-545"
[string]$EveryoneSid = "S-1-1-0"

# Validate client OS
$OSType = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($OSType -ne 1) {
    Write-Host "Non-client OS detected. Exiting script."
    exit
}

# normalize lists
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

function XmlEscape([string]$s) {
    if ($null -eq $s) { return "" }
    return [System.Security.SecurityElement]::Escape($s)
}
function New-RuleGuid { return [guid]::NewGuid().ToString() }

$ErrorActionPreference = 'Stop'

# start building XML
$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
"@

# ---------------- EXE rules ----------------
$xml += "  <RuleCollection Type=`"Exe`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Admins everywhere
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All (EXE)`" Description=`"Local Administrators allowed everywhere`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow system paths for Everyone (EXE)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows EXE`" Description=`"Allow EXEs from Windows folder`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles EXE`" Description=`"Allow EXEs from Program Files`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles (x86) EXE`" Description=`"Allow EXEs from Program Files (x86)`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES(x86)%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramData EXE`" Description=`"Allow EXEs from ProgramData`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%ProgramData%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Windows Installer cache EXEs
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows Installer Cache EXE`" Description=`"Allow EXEs from Windows Installer cache`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\Installer\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Package Cache EXEs (Burn/Visual C++/Edge/WebView2/etc.)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Package Cache EXE`" Description=`"Allow EXEs from Package Cache`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%ProgramData%\Package Cache\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Config.Msi temp transaction folder
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Config.Msi EXE`" Description=`"Allow EXEs from Config.Msi`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%OSDRIVE%\Config.Msi\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Whitelisted filenames anywhere (EXE)
foreach ($app in $WhitelistedApps) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - $app`" Description=`"Allow $app anywhere`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"*\$app`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Whitelisted paths (EXE)
foreach ($p in $WhitelistedPaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    $path = $p
    if ($path -notmatch '[*?]') {
        if ($path -match '\\$') { $path = $path + '*' } else { $path = $path + '\*' }
    }
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Path - $path`" Description=`"Allow EXEs from $path`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$path`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# ---------------- Publisher rules ----------------
# Publisher allow rules (EXE) - useful but maintain exact Subject strings
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

# Allow Admins everywhere (Scripts)
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

# Whitelisted scripts (filename or explicit path)
foreach ($s in $WhitelistedScripts) {
    if ([string]::IsNullOrWhiteSpace($s)) { continue }
    if ($s -match '[\\/]' -or $s -match '[:%]') { $conditionPath = $s } else { $conditionPath = "*\$s" }
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Script - $s`" Description=`"Allow whitelisted script: $s`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"$conditionPath`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Whitelisted script paths
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

# System script paths
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

# Allow Admins everywhere (DLL)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All (DLLs)`" Description=`"Local Administrators allowed everywhere for DLLs`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# >>> PERMISSIVE: allow all DLLs everywhere (very permissive - use with caution)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - All DLLs - Global`" Description=`"Allow all DLL loads from any path (very permissive)`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "  </RuleCollection>`n"

# ---------------- MSI rules ----------------
$xml += "  <RuleCollection Type=`"Msi`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Admins everywhere (MSI)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All (MSI)`" Description=`"Local Administrators allowed everywhere for MSI`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Whitelisted MSI filenames anywhere
foreach ($mapp in $WhitelistedMsiNames) {
    $xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - MSI - $mapp`" Description=`"Allow MSI filename/pattern: $mapp`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions><FilePathCondition Path=`"*\$mapp`"/></Conditions>`n"
    $xml += "    </FilePathRule>`n"
}

# Whitelisted MSI paths (from your generic allowed paths list)
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

# ProgramFiles MSI caches (sometimes installers sit here)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles MSI`" Description=`"Allow MSIs from Program Files`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramFiles (x86) MSI`" Description=`"Allow MSIs from Program Files (x86)`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%PROGRAMFILES(x86)%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# ProgramData and user Package Cache (common for bootstrapper extracts)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - ProgramData MSI`" Description=`"Allow MSIs from ProgramData`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%ProgramData%\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Package Cache MSI`" Description=`"Allow MSIs from Package Cache`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%OSDRIVE%\Users\*\AppData\Local\Package Cache\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Windows Installer cache for repair/uninstall
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Windows Installer Cache`" Description=`"Allow MSIs from %WINDIR%\Installer`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%WINDIR%\Installer\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Config.Msi MSI transactions
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - Config.Msi MSI`" Description=`"Allow MSIs from Config.Msi`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"%OSDRIVE%\Config.Msi\*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Publisher allow rules (MSI)
foreach ($pub in $WhitelistedPublishers) {
    $pubEsc = XmlEscape($pub)
    $xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow MSI Publisher - $pubEsc`" Description=`"Allow signed MSI from $pubEsc`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
    $xml += "      <Conditions>`n"
    $xml += "        <FilePublisherCondition PublisherName=`"$pubEsc`" ProductName=`"*`" BinaryName=`"*`">`n"
    $xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
    $xml += "        </FilePublisherCondition>`n"
    $xml += "      </Conditions>`n"
    $xml += "    </FilePublisherRule>`n"
}

$xml += "  </RuleCollection>`n"

# ---------------- Appx rules ----------------
$xml += "  <RuleCollection Type=`"Appx`" EnforcementMode=`"$EnforcementMode`">`n"

# Allow Admins everywhere (Appx)
$xml += "    <FilePathRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow Local Admins - All (Appx)`" Description=`"Local Administrators allowed everywhere for Appx`" UserOrGroupSid=`"$AdministratorsSid`" Action=`"Allow`">`n"
$xml += "      <Conditions><FilePathCondition Path=`"*`"/></Conditions>`n"
$xml += "    </FilePathRule>`n"

# Allow signed Appx for Everyone
$xml += "    <FilePublisherRule Id=`"" + (New-RuleGuid) + "`" Name=`"Allow - All Signed Appx`" Description=`"Allow signed packaged apps`" UserOrGroupSid=`"$EveryoneSid`" Action=`"Allow`">`n"
$xml += "      <Conditions>`n"
$xml += "        <FilePublisherCondition PublisherName=`"*`" ProductName=`"*`" BinaryName=`"*`">`n"
$xml += "          <BinaryVersionRange LowSection=`"0.0.0.0`" HighSection=`"65535.65535.65535.65535`" />`n"
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

# Add "Install as administrator" option for .MSI files (optional convenience)
try {
    $baseKey = "Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\runas"
    $cmdKey  = "$baseKey\command"
    if (-not (Test-Path $baseKey)) { New-Item -Path $baseKey -Force | Out-Null }
    Set-ItemProperty -Path $baseKey -Name '(default)' -Value "Install as administrator"
    if (-not (Test-Path $cmdKey)) { New-Item -Path $cmdKey -Force | Out-Null }
    Set-ItemProperty -Path $cmdKey -Name '(default)' -Value 'msiexec.exe /i "%1"'
    Write-Host "`n'Install as administrator' option added to MSI right-click menu."
} catch {
    Write-Warning "Failed to add MSI context menu: $_"
}

# Apply policy — reset first for a clean baseline, then apply new policy
try {
    $appLockerDir = Join-Path $env:ProgramData "AppLocker"
    if (-not (Test-Path $appLockerDir)) { New-Item -Path $appLockerDir -ItemType Directory -Force | Out-Null }

    # Step 1: Create blank XML and save to disk
    $resetXml = '<AppLockerPolicy Version="1" />'
    $resetPath = Join-Path $appLockerDir "FullReset.xml"
    $resetXml | Out-File -FilePath $resetPath -Encoding UTF8 -Force

    # Step 2: Clear the previously applied policy
    try {
        Set-AppLockerPolicy -XmlPolicy $resetPath -ErrorAction Stop
        Write-Host "`nAppLocker reset applied (FullReset.xml)."
    } catch {
        Write-Warning "`nAppLocker reset failed (continuing): $($_.Exception.Message)"
    }

    # Step 3: Apply the new policy
    Write-Host "`nApplying new AppLocker policy..."
    Set-AppLockerPolicy -XmlPolicy $OutXmlPath -ErrorAction Stop

    gpupdate /force | Out-Null
    sc.exe config appidsvc start= auto | Out-Null
    try {
       if ((Get-Service AppIDSvc).Status -ne "Running") {
            Start-Service AppIDSvc -ErrorAction Stop
        } else {
            Restart-Service AppIDSvc -Force -ErrorAction Stop
        }
        Write-Host "`nAppIDSvc restarted."
    } catch {
        Write-Warning "`nCould not restart AppIDSvc - reboot may be required."
    }
	
    Write-Host "`nAppLocker policy applied. Check Event Viewer > Applications and Services Logs > Microsoft > Windows > AppLocker for events."
} catch {
    Write-Error "`nFailed to apply AppLocker policy: $_"
    exit 1
}