<#
Install-AdminLauncher.ps1
Single-file installer:
 - Prompts for admin user and password (during install)
 - Stores encrypted credential to C:\ProgramData\AdminLauncher\cred.dat (machine DPAPI)
 - Writes launcher to C:\Windows\System32\ADMPASS.ps1
 - Writes hidden wrapper to C:\Windows\System32\ADMPASS.vbs
 - Sets ACLs so normal users can execute the launcher

Usage: Run elevated once:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-AdminLauncher.ps1
#>

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Relaunch elevated if not elevated
if (-not (Test-IsElevated)) {
    Write-Host "Not elevated. Relaunching elevated..."
    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if (-not $pwsh) { $pwsh = (Get-Command powershell).Source }
    if (-not $pwsh) {
        Write-Error "Cannot locate powershell executable to relaunch. Start an elevated powershell and re-run this script."
        exit 1
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $pwsh
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } catch {
        Write-Error ("Failed to relaunch elevated: {0}" -f $_)
    }
    exit
}

# Config
$installFolder = 'C:\ProgramData\AdminLauncher'
$requestsFolder = Join-Path $installFolder 'Requests'
$credFile = Join-Path $installFolder 'cred.dat'
$launcherPath = "$env:windir\System32\ADMPASS.ps1"
$vbsWrapperPath = "$env:windir\System32\ADMPASS.vbs"

# DPAPI wrapper via Add-Type
$dpApiCs = @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class DPAPIWrapper
{
    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        string szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        System.Text.StringBuilder pszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut);

    private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

    public static byte[] Protect(byte[] plainBytes)
    {
        DATA_BLOB inBlob = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        inBlob.cbData = plainBytes.Length;
        inBlob.pbData = Marshal.AllocHGlobal(plainBytes.Length);
        Marshal.Copy(plainBytes, 0, inBlob.pbData, plainBytes.Length);

        bool success = CryptProtectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref outBlob);
        Marshal.FreeHGlobal(inBlob.pbData);
        if (!success) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        byte[] outBytes = new byte[outBlob.cbData];
        Marshal.Copy(outBlob.pbData, outBytes, 0, outBlob.cbData);
        Marshal.FreeHGlobal(outBlob.pbData);
        return outBytes;
    }

    public static byte[] Unprotect(byte[] cipherBytes)
    {
        DATA_BLOB inBlob = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        inBlob.cbData = cipherBytes.Length;
        inBlob.pbData = Marshal.AllocHGlobal(cipherBytes.Length);
        Marshal.Copy(cipherBytes, 0, inBlob.pbData, cipherBytes.Length);

        StringBuilder descr = new StringBuilder();
        bool success = CryptUnprotectData(ref inBlob, descr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref outBlob);
        Marshal.FreeHGlobal(inBlob.pbData);
        if (!success) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        byte[] outBytes = new byte[outBlob.cbData];
        Marshal.Copy(outBlob.pbData, outBytes, 0, outBlob.cbData);
        Marshal.FreeHGlobal(outBlob.pbData);
        return outBytes;
    }
}
'@

# Load DPAPIWrapper if not present
if (-not ([System.Management.Automation.PSTypeName]'DPAPIWrapper').Type) {
    try {
        Add-Type -TypeDefinition $dpApiCs -Language CSharp -ErrorAction Stop
    } catch {
        Write-Error ("Failed to compile DPAPI wrapper: {0}" -f $_)
        exit 1
    }
}

# Create folder(s)
foreach ($p in @($installFolder, $requestsFolder)) {
    if (-not (Test-Path $p)) {
        try { New-Item -Path $p -ItemType Directory -Force | Out-Null } catch { Write-Error ("Failed to create folder {0}: {1}" -f $p, $_); exit 1 }
    }
}

# Preset admin user and password (plain text)
#$adminUser = ".\administrator"
#$plainPassword = "kuchbhihoga"

# Prompt for admin username & password
Write-Host "Enter admin account to store (examples: DOMAIN\Administrator or .\Administrator)."
$adminUser = Read-Host "Admin user"
if ([string]::IsNullOrWhiteSpace($adminUser)) {
    Write-Error "Admin user cannot be empty. Aborting."
    exit 1
}

function Read-Password([string]$prompt) {
    while ($true) {
        $p1 = Read-Host $prompt -AsSecureString
        if ($p1.Length -eq 0) {
            Write-Host "Empty password not allowed. Try again"
            continue
        }
        return $p1
    }
}
# Convert plain text password to SecureString
#$securePass = ConvertTo-SecureString $plainPassword -AsPlainText -Force
$securePass = Read-Password "Enter password"

# Convert to plain (briefly)
$ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($securePass)
try { $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }

# Protect
$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
try {
    $protectedBytes = [DPAPIWrapper]::Protect($plainBytes)
} catch {
    Write-Error ("DPAPI protect failed: {0}" -f $_)
    exit 1
}
$enc = [System.Convert]::ToBase64String($protectedBytes)

# Save
$json = @{ User = $adminUser; Password = $enc } | ConvertTo-Json
try { Set-Content -Path $credFile -Value $json -Encoding UTF8 -Force } catch { Write-Error ("Failed to write credential file {0}: {1}" -f $credFile, $_); exit 1 }
Write-Host ("Stored encrypted credential to {0}" -f $credFile)

# Write launcher to System32
$launcherScript = @'
<#
ADMPASS.ps1
Launch a program using stored admin credentials.

Usage examples:
  ADMPASS.ps1 "C:\Path\To\App.exe" arg1 arg2
  ADMPASS.ps1 "C:\Path\To\App.exe" arg1 --hidden

If the last argument is --hidden the launcher will attempt to start the process with a hidden window.
#>

param(
    [Parameter(Mandatory=$true, Position=0)] [string] $FilePath,
    [Parameter(ValueFromRemainingArguments=$true)] [string[]] $RemainingArgs
)

# Load DPAPIWrapper type if not already loaded (same definition as used by installer)
if (-not ([System.Management.Automation.PSTypeName]'DPAPIWrapper').Type) {
    $dpApiCs = @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class DPAPIWrapper
{
    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        string szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        System.Text.StringBuilder pszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut);

    private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

    public static byte[] Protect(byte[] plainBytes)
    {
        DATA_BLOB inBlob = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        inBlob.cbData = plainBytes.Length;
        inBlob.pbData = Marshal.AllocHGlobal(plainBytes.Length);
        Marshal.Copy(plainBytes, 0, inBlob.pbData, plainBytes.Length);

        bool success = CryptProtectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref outBlob);
        Marshal.FreeHGlobal(inBlob.pbData);
        if (!success) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        byte[] outBytes = new byte[outBlob.cbData];
        Marshal.Copy(outBlob.pbData, outBytes, 0, outBlob.cbData);
        Marshal.FreeHGlobal(outBlob.pbData);
        return outBytes;
    }

    public static byte[] Unprotect(byte[] cipherBytes)
    {
        DATA_BLOB inBlob = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        inBlob.cbData = cipherBytes.Length;
        inBlob.pbData = Marshal.AllocHGlobal(cipherBytes.Length);
        Marshal.Copy(cipherBytes, 0, inBlob.pbData, cipherBytes.Length);

        StringBuilder descr = new StringBuilder();
        bool success = CryptUnprotectData(ref inBlob, descr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref outBlob);
        Marshal.FreeHGlobal(inBlob.pbData);
        if (!success) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        byte[] outBytes = new byte[outBlob.cbData];
        Marshal.Copy(outBlob.pbData, outBytes, 0, outBlob.cbData);
        Marshal.FreeHGlobal(outBlob.pbData);
        return outBytes;
    }
}
"@
    try { Add-Type -TypeDefinition $dpApiCs -Language CSharp -ErrorAction Stop } catch { Write-Error ("Failed to load DPAPI wrapper: {0}" -f $_); exit 1 }
}

$installFolder = 'C:\ProgramData\AdminLauncher'
$credFile = Join-Path $installFolder 'cred.dat'

if (-not (Test-Path $credFile)) {
    Write-Error "Credential file not found. Ask admin to run installer."
    exit 1
}

try {
    $json = Get-Content -Path $credFile -Raw | ConvertFrom-Json
} catch {
    Write-Error ("Failed to read credential file: {0}" -f $_)
    exit 1
}

if (-not $json.Password) {
    Write-Error "Credential file missing password field."
    exit 1
}

# Decrypt password
try {
    $cipher = [System.Convert]::FromBase64String($json.Password)
    $plainBytes = [DPAPIWrapper]::Unprotect($cipher)
    $plain = [System.Text.Encoding]::UTF8.GetString($plainBytes)
} catch {
    Write-Error ("Failed to decrypt stored password: {0}" -f $_)
    exit 1
}

# Build credential
$secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($json.User, $secure)

# Handle --hidden flag (if present as the last argument)
$hidden = $false
if ($RemainingArgs -and $RemainingArgs.Count -gt 0) {
    if ($RemainingArgs[-1] -eq '--hidden') {
        $hidden = $true
        if ($RemainingArgs.Count -gt 1) {
            $RemainingArgs = $RemainingArgs[0..($RemainingArgs.Count - 2)]
        } else {
            $RemainingArgs = @()
        }
    }
}

# Clean up remaining args (remove null/empty)
$cleanArgs = @()
if ($null -ne $RemainingArgs) {
    $cleanArgs = $RemainingArgs | Where-Object { $_ -ne $null -and $_.Trim().Length -gt 0 }
}

# Determine Start-Process parameters
try {
    if ($hidden) {
        # When hidden, pass -WindowStyle Hidden. Some apps ignore this; for true background tasks consider scheduled task approach.
        if ($cleanArgs -and $cleanArgs.Count -gt 0) {
            Start-Process -FilePath $FilePath -ArgumentList $cleanArgs -Credential $cred -WorkingDirectory (Split-Path $FilePath -Parent) -WindowStyle Hidden
        } else {
            Start-Process -FilePath $FilePath -Credential $cred -WorkingDirectory (Split-Path $FilePath -Parent) -WindowStyle Hidden
        }
    } else {
        if ($cleanArgs -and $cleanArgs.Count -gt 0) {
            Start-Process -FilePath $FilePath -ArgumentList $cleanArgs -Credential $cred -WorkingDirectory (Split-Path $FilePath -Parent)
        } else {
            Start-Process -FilePath $FilePath -Credential $cred -WorkingDirectory (Split-Path $FilePath -Parent)
        }
    }
} catch {
    Write-Error ("Failed to start process as stored admin: {0}" -f $_)
    exit 1
}
'@

try {
    Set-Content -Path $launcherPath -Value $launcherScript -Encoding UTF8 -Force
} catch {
    Write-Error ("Failed to write launcher to {0}: {1}" -f $launcherPath, $_)
    exit 1
}

# Ensure Requests folder exists
if (-not (Test-Path $requestsFolder)) {
    try { New-Item -Path $requestsFolder -ItemType Directory -Force | Out-Null } catch { Write-Warning ("Failed to create requests folder {0}: {1}" -f $requestsFolder, $_) }
}

# Write ADMPASS.vbs (hidden host wrapper) into System32
$vbs = @'
Option Explicit
Dim args, i, cmd, shell
Set args = WScript.Arguments

' Build powershell command line, quoting each argument
cmd = "powershell -NoProfile -ExecutionPolicy Bypass -File " & Chr(34) & "C:\Windows\System32\ADMPASS.ps1" & Chr(34)
For i = 0 To args.Count - 1
    cmd = cmd & " " & Chr(34) & Replace(args(i), Chr(34), "\" & Chr(34)) & Chr(34)
Next

Set shell = CreateObject("WScript.Shell")
' Run hidden (0), don't wait (False)
On Error Resume Next
shell.Run cmd, 0, False
If Err.Number <> 0 Then
    WScript.Echo "Failed to run: " & Err.Description
End If
'@

try { Set-Content -Path $vbsWrapperPath -Value $vbs -Encoding ASCII -Force } catch { Write-Warning ("Failed to write ADMPASS.vbs: {0}" -f $_) }

# Set ACLs for cred file: Users read, Admins & SYSTEM full control
try {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $ruleUsers = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadAndExecute,Read","Allow")
    $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")
    $ruleSys = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","Allow")
    $acl.AddAccessRule($ruleUsers); $acl.AddAccessRule($ruleAdmin); $acl.AddAccessRule($ruleSys)
    Set-Acl -Path $credFile -AclObject $acl
} catch {
    Write-Warning ("Warning: failed to set ACL on cred file: {0}" -f $_)
}

# Set ACLs for launcher: Everyone read & execute
try {
    $aclL = New-Object System.Security.AccessControl.FileSecurity
    $aclL.SetAccessRuleProtection($true, $false)
    $aclL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","ReadAndExecute","Allow")))
    $aclL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")))
    $aclL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","Allow")))
    Set-Acl -Path $launcherPath -AclObject $aclL
} catch {
    Write-Warning ("Warning: failed to set ACL on launcher: {0}" -f $_)
}

# Set ACLs for cred file: Users read, Admins & SYSTEM full control
try{
	# Run as Administrator (one-liner)
	$credFile = 'C:\ProgramData\AdminLauncher\cred.dat'
	$acl = Get-Acl $credFile
	$acl.SetAccessRuleProtection($true,$false)
	# remove existing rules if you prefer to reset
	$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
	$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadAndExecute,Read","Allow")))
	$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")))
	$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","Allow")))
	Set-Acl -Path $credFile -AclObject $acl
	Write-Host "Updated ACL: Users can read $credFile"
} catch {
    Write-Warning ("Warning: failed to set ACL on cred file: {0}" -f $_)
}

Write-Host ""
Write-Host ("Install complete.`n - Credential store: {0}`n - Launcher: {1}`n - Request wrapper: {2}`n - Hidden wrapper: {3}" -f $credFile, $launcherPath, $requestVbsPath, $vbsWrapperPath)
Write-Host ""
Write-Host "Example usage (no elevation needed):"
Write-Host "  $launcherPath `"C:\Windows\System32\notepad.exe`""
Write-Host "  $launcherPath `"C:\Program Files\MyApp\app.exe`" /silent /install"
Write-Host ""
Write-Host "To use the request runner (silent run via scheduled task trigger):"
Write-Host "  $requestVbsPath `"C:\Path\To\App.exe`" arg1 arg2"
