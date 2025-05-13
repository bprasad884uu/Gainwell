# Get all users in the Administrators group
$administratorsMembers = Get-LocalGroupMember -Group "Administrators" | Where-Object {
    $_.Name -notmatch "Administrator" -and
    $_.Name -notmatch "Domain Admins" -and
	$_.Name -notmatch "corpadmin"
}

# Filter out special accounts and delete users with invalid SIDs
foreach ($user in $administratorsMembers) {
    $userName = $user.Name

    # Check if the SID is valid
    $sidIsValid = $true
    try {
        $null = New-Object System.Security.Principal.SecurityIdentifier $user.SID
    } catch {
        $sidIsValid = $false
    }

    if ($sidIsValid) {
            # Move the user to the Users group
            $null = Add-LocalGroupMember -Group "Users" -Member $user.Name -ErrorAction SilentlyContinue
            $null = Remove-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction SilentlyContinue
            Write-Host "Moved user '$userName' to Users group."
    } elseif (!$sidIsValid -and $userName -ne "Administrator") {
        # Delete user with invalid SID
        $null = Remove-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction SilentlyContinue
        Write-Host "Deleted user '$userName' with invalid SID."
    }
}

Write-Host "All users moved to Users group."