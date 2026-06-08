# Run as Administrator

Write-Host "Checking SMB shares for 'Everyone' permissions..." -ForegroundColor Cyan

$Shares = Get-SmbShare | Where-Object {
    $_.Name -notin @('IPC$')
}

foreach ($Share in $Shares) {

    try {
        $AccessEntries = Get-SmbShareAccess -Name $Share.Name -ErrorAction Stop

        $EveryoneEntries = $AccessEntries | Where-Object {
            $_.AccountName -match '^Everyone$'
        }

        if ($EveryoneEntries) {

            Write-Host "Found 'Everyone' permission on share: $($Share.Name)" -ForegroundColor Yellow

            Revoke-SmbShareAccess `
                -Name $Share.Name `
                -AccountName "Everyone" `
                -Force `
                -ErrorAction Stop

            Write-Host "Removed 'Everyone' permission from share: $($Share.Name)" -ForegroundColor Green
        }
        else {
            Write-Host "No 'Everyone' permission found on share: $($Share.Name)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Failed to process share '$($Share.Name)': $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "Completed." -ForegroundColor Cyan