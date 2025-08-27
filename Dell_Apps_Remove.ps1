# Get all Dell app registry keys except Dell Command
$DellAppKeys = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" ,
                             "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
    Where-Object {
        $displayName = (Get-ItemProperty $_.PSPath).DisplayName
        $displayName -like "Dell*" -and $displayName -notlike "Dell Command*"
    }

foreach ($key in $DellAppKeys) {
    $appProps = Get-ItemProperty $key.PSPath
    $displayName = $appProps.DisplayName
    $guid = $key.PSChildName
    $uninstallString = $appProps.UninstallString

    Write-Host "Processing $displayName..."

    try {
        if ($uninstallString) {
            # Use the uninstall string if available
            Write-Host "Running uninstall string for $displayName..."
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$uninstallString /S`"" -Wait
        } else {
            # Fall back to MSI GUID
            Write-Host "Uninstall string not found. Using MSI GUID for $displayName..."
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $guid /qn /norestart" -Wait
        }
        Write-Host "$displayName removed."
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Warning "Failed to uninstall", $displayName, ":", $errorMessage
    }
}
