# Checking Windows Compatibility
$OSType = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($OSType -ne 1) {
    Write-Host "Incompatible Windows Version. Exiting script."
    exit
}

$AdminUser = "Administrator"
$WinOSAdmin = "gcpladmusr"

# Find the current Administrator account name
$currentAdmin = Get-LocalUser -Name $AdminUser -ErrorAction SilentlyContinue

# If original "Administrator" not found, then it's already renamed.
if (-not $currentAdmin) {
    # Find renamed Administrator (SID ending in 500)
    $currentAdmin = Get-LocalUser | Where-Object { $_.SID.Value.Split('-')[-1] -eq '500' }
}

$currentName = $currentAdmin.Name

# Run activation + rename only if not already renamed
if ($currentName -ne $WinOSAdmin) {

    # Enable account
    Enable-LocalUser -Name $currentName -ErrorAction SilentlyContinue

    # Set Full Name
    Set-LocalUser -Name $currentName -FullName "Gainwell Administrator" -ErrorAction SilentlyContinue

    # Rename only if target name not in use
    $exists = Get-LocalUser -Name $WinOSAdmin -ErrorAction SilentlyContinue
    if (-not $exists) {
        Rename-LocalUser -Name $currentName -NewName $WinOSAdmin -ErrorAction SilentlyContinue
        $currentName = $WinOSAdmin
    }
    Write-Host "Administrator Account Activated."
}

# Prompt user for a secure password
$pass = Read-Host 'Enter Password' -AsSecureString
#$Password = ConvertTo-SecureString $pass -AsPlainText -Force

# Convert the SecureString to BSTR and then to a plain text string
#$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
#$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Set the new password for the Administrator account
Set-LocalUser -Name $WinOSAdmin -Password $pass -ErrorAction Stop
#net user $WinOSAdmin $PlainPassword
#Set-LocalUser -Name '$AdminUser' -Password '$ecure@2k24'
Write-Host "Password has been reset for Administrator account."

# Exclusions (names + SID patterns)
$ExcludeList = @($WinOSAdmin, 'Administrator', 'DefaultAccount', 'DefaultUser0', 'Guest', 'WDAGUtilityAccount', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'corpadmin', 'Domain Admins')

$excludeSidPrefixes = @('S-1-5-18','S-1-5-19','S-1-5-20')   # system SIDs
$excludeSidEndings  = @('-500','-501','-503','-504')         # built-in account RIDs

$computer = $env:COMPUTERNAME
$adminGroup = [ADSI]"WinNT://$computer/Administrators,group"
$usersGroup = [ADSI]"WinNT://$computer/Users,group"
$members = @($adminGroup.Invoke("Members"))

$stats = [pscustomobject]@{ Total = $members.Count; Moved = 0; Skipped = 0; RemovedSIDs = 0; Errors = 0 }

foreach ($m in $members) {
    $name    = $m.GetType().InvokeMember("Name", 'GetProperty', $null, $m, $null)
    $adsPath = $m.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $m, $null)

    # Extract SID from ADsPath if present (e.g. WinNT://S-1-5-21-...)
    $sid = $null
    if ($adsPath -match 'S-1-5-[\d\-]+') { $sid = $matches[0] }

    # Skip by name (case-insensitive)
    if ($ExcludeList -contains $name) {
        #Write-Host "Skipping excluded: $name"
        $stats.Skipped++
        continue
    }

    # Skip by SID prefix (system accounts)
    $skipBySid = $false
    if ($sid) {
        foreach ($pref in $excludeSidPrefixes) {
            if ($sid.StartsWith($pref)) { $skipBySid = $true; break }
        }
        foreach ($ending in $excludeSidEndings) {
            if ($sid.EndsWith($ending)) { $skipBySid = $true; break }
        }
    }
    if ($skipBySid) {
        Write-Host "Skipping system account (by SID): $name ($sid)"
        $stats.Skipped++
        continue
    }

    try {
        # If unresolved SID entry (local unresolved user), remove it from Administrators only
        if ($adsPath -match 'WinNT://S-1-5-21') {
            Write-Host "Removing unresolved SID entry: $adsPath"
            $adminGroup.Remove($adsPath)
            $stats.RemovedSIDs++
            continue
        }

        Write-Host "Processing: $name  (ADsPath: $adsPath)"
        # Remove from Administrators
        $adminGroup.Remove($adsPath)
        Write-Host "  Removed from Administrators."

        # Add to Users (may throw if already member — catch and continue)
        try {
            $usersGroup.Add($adsPath)
            Write-Host "  Added to Users."
        } catch {
            Write-Warning "  Could not add to Users (maybe already present): $name"
        }

        $stats.Moved++
    } catch {
        Write-Warning "Failed to move $name : $_"
        $stats.Errors++
    }
}

Write-Host "`n--- Summary ---"
Write-Host "Total inspected: $($stats.Total)"
Write-Host "Moved:           $($stats.Moved)"
Write-Host "Skipped:         $($stats.Skipped)"
Write-Host "Removed SIDs:    $($stats.RemovedSIDs)"
Write-Host "Errors:          $($stats.Errors)"
Write-Host "-----------------"

# Show all members of local Users group
$usersList = @($usersGroup.Invoke("Members")) |
    ForEach-Object { $_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null) }

Write-Host "`nMembers of local 'Users' group:"
foreach ($usr in $usersList) {
    Write-Host " - $usr"
}

# -------------------------
# Remove unresolved SIDs from local Users group
# -------------------------
# Reuse $usersGroup that is already declared earlier
$usersMembersRaw = @($usersGroup.Invoke("Members"))

$removedSids = 0
foreach ($m in $usersMembersRaw) {
    $adsPath = $m.GetType().InvokeMember("ADsPath",'GetProperty',$null,$m,$null)

    if ($adsPath -match 'S-1-5-21') {
        try {
            $usersGroup.Remove($adsPath)
            Write-Output "Removed unresolved SID entry from Users group: $adsPath"
            $removedSids++
        } catch {
            Write-Warning "Failed to remove unresolved SID $adsPath : $_"
        }
    }
}

if ($removedSids -eq 0) {
    Write-Output "No unresolved SIDs found in Users group."
} else {
    Write-Output "Total unresolved SIDs removed: $removedSids"
}

# -------------------------
# Ensure local users require password and must change at next logon (fixed)
# -------------------------
# Assumes $WinOSAdmin is already defined earlier in the script

# Exclude lists (names + SID patterns) — reuse your existing lists if present
$excludeNames = @(
    $WinOSAdmin,
    'Administrator',
    'DefaultAccount',
    'DefaultUser0',
    'Guest',
    'WDAGUtilityAccount',
    'SYSTEM',
    'LOCAL SERVICE',
    'NETWORK SERVICE',
    'corpadmin',
    'Domain Admins'
)
$excludeSidPrefixes = @('S-1-5-18','S-1-5-19','S-1-5-20')
$excludeSidEndings  = @('-500','-501','-503','-504')

$fixedCount = 0
$errorCount = 0

Get-LocalUser |
    Where-Object {
        $name = $_.Name
        $sid  = if ($_.SID) { $_.SID.Value } else { '' }

        # Exclude by name
        if ($excludeNames -contains $name) { return $false }

        # Exclude by SID prefix (system accounts)
        foreach ($pref in $excludeSidPrefixes) { if ($sid.StartsWith($pref)) { return $false } }

        # Exclude by SID endings
        foreach ($end in $excludeSidEndings) { if ($sid.EndsWith($end)) { return $false } }

        return $true
    } |
    ForEach-Object {
        $user = $_.Name

        try {
            # Prefer Set-LocalUser to clear PasswordNeverExpires
            try {
                Set-LocalUser -Name $user -PasswordNeverExpires $false -ErrorAction Stop
            } catch {
                # Fallback: older systems may not support PasswordNeverExpires via Set-LocalUser.
                # Try WMI fallback only if Set-LocalUser fails.
                $accWmi = Get-WmiObject -Class Win32_UserAccount -Filter "Name='$user' AND LocalAccount=True" -ErrorAction SilentlyContinue
                if ($accWmi) {
                    $accWmi.PasswordExpires = $true
                    $accWmi.Put() | Out-Null
                } else {
                    throw "Neither Set-LocalUser nor WMI fallback available for $user"
                }
            }

            # Force user must change password at next logon (net user targets local accounts)
            # Note: net user exit codes are not thrown as exceptions, so silence stdout
            net user $user /LOGONPASSWORDCHG:yes > $null 2>&1

            Write-Host "Fixing password settings for local user: $user"
            $fixedCount++
        } catch {
            Write-Warning "Failed to update password settings for $user : $_"
            $errorCount++
        }
    }

Write-Host "`n--- Password fix summary ---"
Write-Host "Accounts modified: $fixedCount"
Write-Host "Errors:            $errorCount"
Write-Host "-------------------------------"

# -----------------------
# Delete inactive local accounts + profiles
# -----------------------

$inactiveDays = 60
Write-Host "Deleting inactive local accounts older than $inactiveDays days..."

# Helper: detect recent PIN/Fingerprint interactive logon
function Has-RecentInteractiveLogon {
    param(
        [string]$AccountName,
        [string]$AccountSid,
        [int]$DaysThreshold
    )

    $startTime = (Get-Date).AddDays(-$DaysThreshold)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=4624
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        if (-not $events) { return $false }

        foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $data[$d.Name] = $d.'#text'
            }

            # LogonType 2 = Interactive (PIN/Fingerprint included)
            if ($data['LogonType'] -ne '2') { continue }

            # Match SID first (best)
            if ($AccountSid -and $data['TargetSid'] -eq $AccountSid) {
                return $true
            }

            # Fallback username match
            if ($AccountName -and ($data['TargetUserName'] -eq $AccountName)) {
                return $true
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

# Exclude list
$WinOSAdmin = 'gcpladmusr'
# Safe exclusion list for system + admin accounts
$excludeNames = @(
    $WinOSAdmin,
    'Administrator',
    'DefaultAccount',
    'DefaultUser0',
    'Guest',
    'WDAGUtilityAccount',
    'SYSTEM',
    'LOCAL SERVICE',
    'NETWORK SERVICE',
    'corpadmin',
    'Domain Admins'
)

# Exclude by SID for safety
$excludeSidEndings = @(
    '-500',  # Built-in Administrator
    '-501',  # Guest
    '-503',  # DefaultAccount
    '-504'   # WDAGUtilityAccount
)

# Exclude well-known SYSTEM SIDs
$excludeSidPrefixes = @(
    'S-1-5-18', # Local System
    'S-1-5-19', # Local Service
    'S-1-5-20'  # Network Service
)

# Get all local accounts
$localAccounts = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True"
$profiles = Get-CimInstance -ClassName Win32_UserProfile

# Map profiles by SID
$profileBySid = @{}
foreach ($p in $profiles) { if ($p.SID) { $profileBySid[$p.SID] = $p } }

$now = Get-Date

foreach ($acct in $localAccounts) {
    $name = $acct.Name
    $sid  = $acct.SID

    # Skip by name
    if ($excludeNames -contains $name) { continue }

    # Skip by SID prefix (SYSTEM accounts)
    foreach ($prefix in $excludeSidPrefixes) {
        if ($sid.StartsWith($prefix)) { continue }
    }

    # Skip by SID endings
    foreach ($ending in $excludeSidEndings) {
        if ($sid.EndsWith($ending)) { continue }
    }

    $profile = $null
    $lastUse = $null

    if ($profileBySid.ContainsKey($sid)) {
        $profile = $profileBySid[$sid]
        if ($profile.LastUseTime -is [datetime]) {
            $lastUse = $profile.LastUseTime
        }
    }

    # If profile LastUseTime exists, use it
    if ($lastUse) {
        $days = ($now - $lastUse).Days
        if ($days -lt $inactiveDays) {
            continue
        }

        Write-Host "`nProcessing $name (Inactive $days days)"
    }
    else {
        # If no LastUseTime → check fingerprint/PIN logon
        $recent = Has-RecentInteractiveLogon -AccountName $name -AccountSid $sid -DaysThreshold $inactiveDays
        if ($recent) {
            Write-Host "Skipping $name (recent PIN/Fingerprint login found)"
            continue
        }

        Write-Host "`nProcessing $name (no profile activity + no interactive logon)"
    }

    # -------------------------------
    # DELETE ACCOUNT + PROFILE
    # -------------------------------
    Write-Host "Deleting account: $name"

    # Remove from local groups
    try {
        $groups = Get-LocalGroup | ForEach-Object {
            try {
                if (Get-LocalGroupMember -Group $_.Name -Member $name -ErrorAction SilentlyContinue) { $_.Name }
            } catch { $null }
        } | Where-Object { $_ }

        foreach ($g in $groups) {
            try {
                Remove-LocalGroupMember -Group $g -Member $name -ErrorAction Stop
                Write-Host "  Removed from $g"
            } catch {}
        }
    } catch {}

    # Delete local user
    try {
        Remove-LocalUser -Name $name -ErrorAction Stop
        Write-Host "  Account deleted."
    } catch {
        Write-Warning "  Failed to delete account: $_"
    }

    # Delete profile (WMI)
    if ($profile) {
        try {
            Remove-CimInstance -InputObject $profile -ErrorAction Stop
            Write-Host "  Deleted profile object."
        } catch {
            Write-Warning "  Failed to delete profile object for $name"
        }
    }

    # Delete profile folder
    if ($profile -and $profile.LocalPath) {
        $pf = $profile.LocalPath
        if (Test-Path $pf) {
            try {
                Takeown.exe /F $pf /A /R | Out-Null
                icacls.exe $pf /grant Administrators:`(F`) /T | Out-Null
                Remove-Item $pf -Recurse -Force
                Write-Host "  Deleted profile folder: $pf"
            } catch {
                Write-Warning "  Failed to delete folder: $pf"
            }
        }
    }
}

Write-Host "`nCompleted processing inactive local accounts."

Write-Host "Applying Security policy ....."

# Export
secedit /export /cfg .\secpol.cfg > $null 2>&1

# Read + modify
$secpolContent = Get-Content .\secpol.cfg -ErrorAction SilentlyContinue
$secpolContent = $secpolContent -replace 'LockoutBadCount = 0', 'LockoutBadCount = 3' `
 -replace 'AllowAdministratorLockout = 1', 'AllowAdministratorLockout = 0' `
 -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' `
 -replace 'MinimumPasswordAge = 0', 'MinimumPasswordAge = 1' `
 -replace 'MaximumPasswordAge = .*', 'MaximumPasswordAge = 90' `
 -replace 'MinimumPasswordLength = .*', 'MinimumPasswordLength = 8' `
 -replace 'PasswordHistorySize = .*', 'PasswordHistorySize = 5' `
 -replace 'ResetLockoutCount = .*', 'ResetLockoutCount = 10' `
 -replace 'LockoutDuration = .*', 'LockoutDuration = 10' `
 -replace 'AllowAdministratorLockout = .*', 'AllowAdministratorLockout = 0'

$secpolContent | Out-File .\secpol.cfg -Force > $null 2>&1

# Apply security policy silently
secedit /configure /db $env:SystemDrive\Windows\security\local.sdb /cfg .\secpol.cfg /areas SECURITYPOLICY > $null 2>&1

# Remove temp file silently
Remove-Item -Path .\secpol.cfg -Force -Confirm:$false > $null 2>&1

Write-Host "Security policy applied successfully."
Write-Host "================================================="

# End of script
