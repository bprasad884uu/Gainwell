# Function to resolve SID to username
function Get-UsernameFromSID {
    param (
        [string]$SID
    )

    try {
        $securityIdentifier = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $account = $securityIdentifier.Translate([System.Security.Principal.NTAccount])
        return $account.Value.Split('\')[-1]  # Extracts only the username part
    } catch {
        return $null
    }
}

# List all keys under HKEY_USERS excluding specified keys and those ending with _Classes
$Registry = Get-ChildItem -Path Registry::HKEY_USERS | Where-Object {
    $_.Name -notmatch '\.DEFAULT$|S-1-5-18$|S-1-5-19$|S-1-5-20$|_Classes$'
} | Select-Object -ExpandProperty PSChildName

# Iterate through each key under HKEY_USERS
foreach ($user in $Registry) {
    # Resolve SID to username
    $username = Get-UsernameFromSID -SID $user

    if ($username) {
        # Define the registry path for Outlook search settings
        $RegistryPath = "Registry::HKEY_USERS\$user\Software\Microsoft\Office\16.0\Outlook\Search"

        # Check if the registry path exists
        if (Test-Path $RegistryPath) {
            # Set the DisableServerAssistedSearch value to 1
            Set-ItemProperty -Path $RegistryPath -Name "DisableServerAssistedSearch" -Value 1
            Write-Host "Disabled Server Assisted Search for $username."
        } else {
            Write-Host "Path not found: $RegistryPath for $username"
        }
    } else {
        Write-Host "Could not resolve SID: $user"
    }
}
