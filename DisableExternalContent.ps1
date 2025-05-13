# Function to resolve SID to username
function Get-UsernameFromSID {
    param ([string]$SID)
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $account = $sidObj.Translate([System.Security.Principal.NTAccount])
        return $account.Value.Split('\')[-1]
    } catch {
        return $null
    }
}

# Get all valid user SIDs under HKEY_USERS
$RegistrySIDs = Get-ChildItem -Path Registry::HKEY_USERS | Where-Object {
    $_.Name -notmatch '\.DEFAULT$|S-1-5-18$|S-1-5-19$|S-1-5-20$|_Classes$'
} | Select-Object -ExpandProperty PSChildName

foreach ($sid in $RegistrySIDs) {
    $username = Get-UsernameFromSID -SID $sid

    if ($username) {
        Write-Host "Applying settings for user: $username ($sid)"

        # Define base paths
        $baseExcelPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Office\16.0\Excel\Security"
        $externalContentPath = "$baseExcelPath\ExternalContent"
        $intelServicePath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Office\16.0\Common"
        $ecsOverridePath = "$intelServicePath\ExperimentEcs\Overrides"

        # Ensure ExternalContent key exists
        if (-not (Test-Path $externalContentPath)) {
            New-Item -Path $externalContentPath -Force | Out-Null
        }

        # Set registry values safely
        try {
            Set-ItemProperty -Path $externalContentPath -Name "DataConnectionWarnings" -Value 3 -Type DWord
            Set-ItemProperty -Path $externalContentPath -Name "WorkbookLinkWarnings" -Value 3 -Type DWord

            if (-not (Test-Path $ecsOverridePath)) {
                New-Item -Path $ecsOverridePath -Force | Out-Null
            }

            Set-ItemProperty -Path $ecsOverridePath -Name "LinkedDataTypeDisabled" -Value 1 -Type DWord
            Set-ItemProperty -Path $intelServicePath -Name "ServiceEnabled" -Value 0 -Type DWord
			
			Write-Host ""
            Write-Host "✔ Excel 2016 external content restrictions applied for $username."
        } catch {
            Write-Warning "⚠ Failed to apply settings for $username ($sid): $_"
        }
    } else {
        Write-Warning "⚠ Could not resolve SID: $sid"
    }
}
