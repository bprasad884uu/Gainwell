# Requires: Windows 10/11
# Purpose: Set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner
#          to the current logged-in user's Full Name (Domain or Local).

# --- Helpers ---
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-CurrentLogonDomainAndSam {
    # Prefer WMI-reported interactive user
    $u = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
    if ([string]::IsNullOrWhiteSpace($u)) {
        # Fallback to environment
        if ($env:USERDOMAIN -and $env:USERNAME) { $u = "$($env:USERDOMAIN)\$($env:USERNAME)" }
    }

    if ($u -and $u -like "*\*") {
        $parts = $u.Split('\',2)
        [PSCustomObject]@{
            Domain = $parts[0]
            Sam    = $parts[1]
            Raw    = $u
        }
    } else {
        # Last fallback: local machine context
        [PSCustomObject]@{
            Domain = $env:COMPUTERNAME
            Sam    = $env:USERNAME
            Raw    = $u
        }
    }
}

function Try-GetFullNameFromUserPrincipal($Domain, $Sam) {
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ctxType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ctxType, $Domain)
        $user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $Sam)
        if ($user -and $user.DisplayName) { return $user.DisplayName }
    } catch {}
    return $null
}

function Try-GetFullNameFromADModule($Sam) {
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
            $adUser = Get-ADUser -Identity $Sam -Properties DisplayName -ErrorAction Stop
            if ($adUser -and $adUser.DisplayName) { return $adUser.DisplayName }
        }
    } catch {}
    return $null
}

function Try-GetFullNameFromWMI($Domain, $Sam) {
    try {
        $q = "SELECT * FROM Win32_UserAccount WHERE Domain='$Domain' AND Name='$Sam'"
        $acct = Get-CimInstance -Query $q -ErrorAction Stop
        if ($acct -and $acct.FullName) { return $acct.FullName }
    } catch {}
    return $null
}

function Try-GetFullNameFromLocal($Sam) {
    try {
        $lu = Get-LocalUser -Name $Sam -ErrorAction Stop
        if ($lu -and $lu.FullName) { return $lu.FullName }
    } catch {}
    return $null
}

function Try-GetFullNameFromPrimaryOwner {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.PrimaryOwnerName -and
            $cs.PrimaryOwnerName -notmatch '\\' -and
            $cs.PrimaryOwnerName -ne $cs.Name) {

            return $cs.PrimaryOwnerName
        }
    } catch {}
    return $null
}

function Resolve-FullName {
    param(
        [string]$Domain,
        [string]$Sam
    )

    # 1) Domain without AD module
    $name = Try-GetFullNameFromUserPrincipal -Domain $Domain -Sam $Sam
    if ($name) { return $name }

    # 2) AD module
    $name = Try-GetFullNameFromADModule -Sam $Sam
    if ($name) { return $name }

    # 3) WMI UserAccount
    $name = Try-GetFullNameFromWMI -Domain $Domain -Sam $Sam
    if ($name) { return $name }

    # 4) Local user
    $name = Try-GetFullNameFromLocal -Sam $Sam
    if ($name) { return $name }

    # 5) PrimaryOwnerName (device owner)
    $name = Try-GetFullNameFromPrimaryOwner
    if ($name) { return $name }

    # 6) Final fallback
    return $Sam
}

# --- Main ---
if (-not (Test-Admin)) {
    Write-Host "Please run this script in an elevated PowerShell window (Run as Administrator)." -ForegroundColor Yellow
    return
}

$u = Get-CurrentLogonDomainAndSam
$Domain = $u.Domain
$Sam    = $u.Sam
$Raw    = $u.Raw

if (-not $Sam) {
    Write-Host "Could not detect a currently logged-in user." -ForegroundColor Yellow
    return
}

$fullName = Resolve-FullName -Domain $Domain -Sam $Sam

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
try {
    Set-ItemProperty -Path $regPath -Name "RegisteredOwner" -Value $fullName -Force
    Write-Host "RegisteredOwner set to: $fullName (from $Domain\$Sam)" -ForegroundColor Green
} catch {
    Write-Host "Failed to set RegisteredOwner: $($_.Exception.Message)" -ForegroundColor Red
}
