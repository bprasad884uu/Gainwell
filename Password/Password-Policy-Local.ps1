try {
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Set-ExecutionPolicy Bypass -Scope Process -Force
} catch {
    # Do nothing; suppress the error
}

# Checking Windows Compatibility
$OSType = (Get-WmiObject Win32_OperatingSystem).ProductType
if ($OSType -eq 2 -or $OSType -eq 3) {
    Write-Host "Incompatible Windows Version. Exiting script."
    exit
}

# Activate the Administrator account
Enable-LocalUser -Name Administrator
Set-LocalUser -Name "Administrator" -FullName "Gainwell Administrator"
Write-Host "Administrator Account Activated."

# Prompt user for a secure password
$pass = Read-Host 'Enter Password' -AsSecureString
$Password = ConvertTo-SecureString $pass -AsPlainText -Force

# Convert the SecureString to BSTR and then to a plain text string
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Set the new password for the Administrator account
#Set-LocalUser -Name 'Administrator' -Password '$PlainPassword'
net user Administrator $PlainPassword
#Set-LocalUser -Name 'Administrator' -Password '$ecure@2k24'
Write-Host "Password has been reset for Administrator account."

$group = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
$members = @($group.Invoke("Members"))
$members | ForEach-Object {
    $name = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
    $adsPath = $_.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $_, $null)
    
    # Skip the specified accounts
    if ($name -ne "Administrator" -and $name -ne "Domain Admins" -and $name -ne "corpadmin") {
        # Get the user object
        $user = [ADSI]$adsPath
        # Remove from Administrators group
        $group.Remove($user.Path)
        
        # Add to Users group
        $usersGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Users,group"
        $usersGroup.Add($user.Path)
    }
}

Write-Host "All local users have been moved to the Users group and removed from the Administrators group."

# Get all users in the local 'Users' group
$group = [ADSI]"WinNT://./Users,group"
$members = $group.psbase.Invoke("Members") | %{$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}

# Print all users
Write-Output "All users in the 'Users' group:"
$members

# Remove unresolved SIDs
$unresolvedSIDFound = $false
foreach ($member in $members) {
    if ($member.StartsWith("S-1-5-21")) {
        $unresolvedSIDFound = $true
        try {
            $group.Remove("WinNT://$member")
            Write-Output "Removed unresolved SID: $member"
        } catch {
            Write-Output "Failed to remove unresolved SID: $member"
        }
    }
}

if ($unresolvedSIDFound -eq $false) {
    Write-Output "No unresolved SIDs found."
}

# Save and change execution policy (if necessary)
$originalExecutionPolicy = Get-ExecutionPolicy -Scope Process -ErrorAction SilentlyContinue
if ($originalExecutionPolicy -ne 'Bypass' -and $originalExecutionPolicy -ne 'Undefined') {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Write-Host "Execution policy changed to 'Bypass' for the duration of the script."
}

# Checking local users for Password. If Password is not enabled then Enables Password for the same
Get-LocalUser | Where-Object { $_.Name -ne 'Administrator' -and $_.Name -ne 'Guest' } | ForEach-Object {
    $user = $_.Name
    $passwordRequired = (Get-WmiObject Win32_UserAccount | Where-Object { $_.Name -eq $user }).PasswordRequired

    if (-not $passwordRequired) {
        # Disable "Password Never Expires" option
        $userAccount = Get-WmiObject Win32_UserAccount -Filter "Name='$user'"
        $userAccount.PasswordExpires = $true
        $userAccount.Put()

        # Enable 'User must change password at next login' option
		Write-Host "Enable 'User must change password at next login' option for $user."
		net user $user /logonpasswordchg:yes
		net user $user /passwordchg:yes
		net user $user /passwordreq:yes
    }
}

Write-Host "Password Never Expires option has been disabled for all users."
Write-Host "User must change password at the next login option has been enabled for all users."

# Define the number of days for inactivity
$inactiveDays = 60

# Get the current date
$currentDate = Get-Date

# Get a list of user accounts, excluding system accounts
$userAccounts = Get-WmiObject -Class Win32_UserProfile | Where-Object {
    $_.Special -eq $false -and $_.LocalPath -notmatch "C:\\Users\\(Administrator|Default User|Default|Public)"
}

# Initialize a flag to track if any accounts were deleted
$accountsDeleted = $false

# Loop through each user account
foreach ($user in $userAccounts) {
    # Retrieve the last logon time
    $lastLogonDate = $user.LastUseTime
    
    # Check if the LastUseTime is valid
    if ($lastLogonDate -is [System.DateTime]) {
        # Calculate the number of inactive days
        $daysInactive = ($currentDate - $lastLogonDate).Days

        # Delete accounts inactive for more than the threshold
        if ($daysInactive -gt $inactiveDays) {
            # Attempt to delete the user account
            try {
                Remove-WmiObject -InputObject $user -ErrorAction Stop
                Write-Host "Deleted user account $($user.LocalPath) due to inactivity ($daysInactive days)."
                $accountsDeleted = $true
            } catch {
                Write-Host "Failed to delete user account $($user.LocalPath): $_"
            }
        }
    } else {
        Write-Host "Account $($user.LocalPath) has no valid LastUseTime and was skipped."
    }
}

# Show summary message only if any accounts were deleted
if ($accountsDeleted) {
    Write-Host "Inactive accounts for more than $inactiveDays days and accounts that have never logged in have been processed."
}

Write-Host "Applying Security policy ....."
secedit /export /cfg .\secpol.cfg
$secpolContent = Get-Content .\secpol.cfg
$secpolContent = $secpolContent -replace 'LockoutBadCount = 0', 'LockoutBadCount = 3' -replace 'AllowAdministratorLockout = 1', 'AllowAdministratorLockout = 0' -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' -replace 'MinimumPasswordAge = 0', 'MinimumPasswordAge = 1' -replace 'MaximumPasswordAge = .*', 'MaximumPasswordAge = 90' -replace 'MinimumPasswordLength = .*', 'MinimumPasswordLength = 8' -replace 'PasswordHistorySize = .*', 'PasswordHistorySize = 5' -replace 'ResetLockoutCount = .*', 'ResetLockoutCount = 10' -replace 'LockoutDuration = .*', 'LockoutDuration = 10' -replace 'AllowAdministratorLockout = .*', 'AllowAdministratorLockout = 0'
$secpolContent | Out-File .\secpol.cfg -Force

secedit /configure /db $env:SystemDrive\windows\security\local.sdb /cfg .\secpol.cfg /areas SECURITYPOLICY
Remove-Item -Path .\secpol.cfg -Force -Confirm:$false

Write-Host "Security policy applied successfully."
Write-Host "================================================="

# Reset execution policy RemoteSigned at the Process scope to its original state
Set-ExecutionPolicy $originalExecutionPolicy -Scope Process -Force

# Reset execution policy RemoteSigned at the LocalMachine scope to its original state
Set-ExecutionPolicy $originalExecutionPolicy -Scope LocalMachine -Force

# End of script
