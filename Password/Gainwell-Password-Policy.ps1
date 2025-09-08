Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
Set-ExecutionPolicy Bypass -Scope Process -Force

# Checking Windows Compatibility
$OSType = (Get-WmiObject -Class Win32_OperatingSystem).OperatingSystemSKU
if ($OSType -eq 7) {
    Write-Host "Incompatible Windows Version. Exiting script."
    exit
}

$excludedUsers = @("gcpladmusr", "Domain Admins", "corpadmin")
$administratorsGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"

foreach ($user in $administratorsGroup.Invoke("Members")) {
    $userName = $user.GetType().InvokeMember("Name", 'GetProperty', $null, $user, $null)
    if ($excludedUsers -notcontains $userName) {
        try {
            # Add to Users group
            $null = net localgroup Users $userName /add
            
            # Remove from Administrators group
            $null = net localgroup Administrators $userName /delete
            Write-Host "$userName moved to Users group."
        } catch {
            Write-Host "An error occurred: $_"
        }
    } else {
        Write-Host "No User moved"
    }
}

# Save and change execution policy (if necessary)
$originalExecutionPolicy = Get-ExecutionPolicy -Scope Process -ErrorAction SilentlyContinue
if ($originalExecutionPolicy -ne 'Bypass' -and $originalExecutionPolicy -ne 'Undefined') {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Write-Host "Execution policy changed to 'Bypass' for the duration of the script."
}

# Get all enabled local users except 'Administrator' and 'Guest'
Get-LocalUser | Where-Object { $_.Name -ne 'gcpladmusr' -and $_.Name -ne 'Guest' -and $_.Enabled -eq $true } | ForEach-Object {
    $user = $_.Name
	# Get the time when the password was last set
    $passwordLastSet = (Get-LocalUser -Name $user).PasswordLastSet
	
    if ($passwordLastSet -ne $null) {
		# Calculate the password age in days
        $passwordAge = (New-TimeSpan -Start $passwordLastSet -End (Get-Date)).Days
		
		# Calculate the seconds until the password expires
		$passwordExpiresInSeconds = ($user.PasswordExpires - (Get-Date)).TotalSeconds -as [int]

        if ($passwordExpiresInSeconds -le 0 -or $passwordAge -gt 60) {
            # Disable "Password Never Expires" option
            $userAccount = Get-WmiObject Win32_UserAccount -Filter "Name='$user'"
            $userAccount.PasswordExpires = $true
            $null = $userAccount.Put()

            # Enable 'User must change password at next login' option
            Write-Host "Password for $user must change at next login."
            $null = net user $user /logonpasswordchg:yes
			$null = net user $user /passwordchg:yes
			$null = net user $user /passwordreq:yes
        } elseif ($passwordExpiresInSeconds -gt 0 -and $passwordAge -le 60) {
            Write-Host "Password for $user was changed recently. No need to change it."
			$null = net user $user /logonpasswordchg:no
        }
    } else {
        Write-Host "No password set for $user. User must set password at next login."
        $null = net user $user /logonpasswordchg:yes
        $null = net user $user /passwordchg:yes
        $null = net user $user /passwordreq:yes
    }
}

# Define the time span of inactivity
$inactiveDays = 60
$cutOffDate = (Get-Date).AddDays(-$inactiveDays)

# Get all local user accounts
$localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

# Check each local user against the "Users" group
foreach ($user in $localUsers) {
    $groups = Get-LocalGroup | Where-Object { $_.Name -eq "Users" }
    foreach ($group in $groups) {
        $groupMembers = Get-LocalGroupMember -Group $group.Name | Select-Object -ExpandProperty Name
        if ($user.Name -in $groupMembers) {
            # Check the last login date
            $lastLogin = $user.LastLogon
            if ($lastLogin -and ((New-TimeSpan -Start $lastLogin -End (Get-Date)).Days -ge $inactiveDays)) {
                # Calculate the number of inactive days
                $inactivePeriod = (New-TimeSpan -Start $lastLogin -End (Get-Date)).Days
                
                # Remove the user profile
                Remove-LocalUser -Name $user.Name
                Write-Host "Removed inactive local user: $($user.Name) after $inactivePeriod days of inactivity"
            }
        }
    }
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

function Clean-AdministratorGroup {
    $administrators = @(
        ([ADSI]"WinNT://./Administrators").psbase.Invoke('Members') |
        ForEach-Object { 
            $_.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $($_), $null) 
        }
    ) -match '^WinNT';
        
    $administrators = $administrators -replace 'WinNT://', ''
        
    $administrators | ForEach-Object {   
        if ($_ -like "$env:COMPUTERNAME/*" -or $_ -like "AzureAd/*") {
            continue;
        }
        Remove-LocalGroupMember -group 'Administrators' -member $_
    }
}
Clean-AdministratorGroup

# Reset execution policy RemoteSigned at the Process scope to its original state
Set-ExecutionPolicy $originalExecutionPolicy -Scope Process -Force

# Reset execution policy RemoteSigned at the LocalMachine scope to its original state
Set-ExecutionPolicy $originalExecutionPolicy -Scope LocalMachine -Force

# End of script
