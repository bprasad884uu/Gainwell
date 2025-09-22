# Stop and disable all Dell services by DisplayName
Get-Service | Where-Object { $_.DisplayName -match '(?i)dell' } | ForEach-Object {
    $svcName    = $_.Name
    $svcDisplay = $_.DisplayName

    try {
        if ($_.Status -eq 'Running') {
            Stop-Service -Name $svcName -Force -ErrorAction Stop
            Write-Output "Stopped $svcName ($svcDisplay)"
        }

        Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
        Write-Output "Disabled $svcName ($svcDisplay)"
    }
    catch {
        Write-Output "Could not act on $svcName ($svcDisplay): $($_.Exception.Message)"
    }
}
