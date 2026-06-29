# Run as Administrator

Write-Host "Auditing and correcting SMB share permissions..." -ForegroundColor Cyan

$Shares = Get-SmbShare | Where-Object {
    $_.Name -notin @('IPC$') -and $_.Name -notlike "*$"
}

foreach ($Share in $Shares) {

    try {
        Write-Host "`nProcessing share: $($Share.Name)" -ForegroundColor Blue

        $AccessEntries = Get-SmbShareAccess -Name $Share.Name -ErrorAction Stop

        foreach ($entry in $AccessEntries) {

            # Remove Everyone
            if ($entry.AccountName -eq "Everyone") {
                Write-Host "Removing 'Everyone'..." -ForegroundColor Yellow
                Revoke-SmbShareAccess -Name $Share.Name -AccountName "Everyone" -Force
            }

            # Fix Domain Users → Read only
            if ($entry.AccountName -like "*Domain Users" -and $entry.AccessRight -ne "Read") {
                Write-Host "Fixing Domain Users permission..." -ForegroundColor Yellow
                Revoke-SmbShareAccess -Name $Share.Name -AccountName $entry.AccountName -Force
            }

            # Fix BUILTIN\Users → Read only
            if ($entry.AccountName -eq "BUILTIN\Users" -and $entry.AccessRight -ne "Read") {
                Write-Host "Fixing BUILTIN\Users permission..." -ForegroundColor Yellow
                Revoke-SmbShareAccess -Name $Share.Name -AccountName "BUILTIN\Users" -Force
            }

            # Fix Domain Admins → Full
            if ($entry.AccountName -like "*Domain Admins" -and $entry.AccessRight -ne "Full") {
                Write-Host "Fixing Domain Admins permission..." -ForegroundColor Yellow
                Revoke-SmbShareAccess -Name $Share.Name -AccountName $entry.AccountName -Force
            }
        }

        # Enforce correct permissions

        Grant-SmbShareAccess `
            -Name $Share.Name `
            -AccountName "BUILTIN\Administrators" `
            -AccessRight Full `
            -Force

        Grant-SmbShareAccess `
            -Name $Share.Name `
            -AccountName "Domain Admins" `
            -AccessRight Full `
            -Force

        Grant-SmbShareAccess `
            -Name $Share.Name `
            -AccountName "Domain Users" `
            -AccessRight Read `
            -Force

        Grant-SmbShareAccess `
            -Name $Share.Name `
            -AccountName "BUILTIN\Users" `
            -AccessRight Read `
            -Force

        Write-Host "Permissions corrected for: $($Share.Name)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed on share '$($Share.Name)': $($_.Exception.Message)"
    }
}

& "C:\Program Files (x86)\ManageEngine\UEMS_Agent\bin\dcpatchscan.exe" *> $null
& "C:\Program Files (x86)\ManageEngine\UEMS_Agent\bin\dcinventory.exe" *> $null
& "C:\Program Files (x86)\ManageEngine\UEMS_Agent\bin\cfgUpdate.exe" *> $null

Write-Host "`nCompleted." -ForegroundColor Cyan