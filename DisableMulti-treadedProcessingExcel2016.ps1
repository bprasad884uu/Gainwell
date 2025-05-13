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
        # Disable Hardware Graphics Acceleration in Excel 16.0
        $ExcelRegistryPath = "Registry::HKEY_USERS\$user\Software\Microsoft\Office\16.0\Excel\Options"

        # Create the registry path if it doesn’t exist
        if (-not (Test-Path $ExcelRegistryPath)) {
            New-Item -Path $ExcelRegistryPath -Force | Out-Null
        }

        # Set DisableHardwareAcceleration to 1
        Set-ItemProperty -Path $ExcelRegistryPath -Name "EnableMTP" -Value 0 -Type DWord
        Write-Host "Disabled Multi-threaded Processing in Excel 16.0 for $username."
    } else {
        Write-Host "Could not resolve SID: $user"
    }
}
