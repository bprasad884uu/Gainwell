# Run as Administrator
# Encrypt all fixed drives and backup recovery keys to Azure AD

# Check if TPM is available
$TPM = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
if (-not $TPM -or -not $TPM.IsActivated().IsActivated -or -not $TPM.IsEnabled().IsEnabled) {
    Write-Host "TPM is not enabled or not present. BitLocker cannot be enabled." -ForegroundColor Red
    exit 1
}

# Get all fixed drives
$fixedDrives = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "Fixed Data" -or $_.VolumeType -eq "Operating System" }

foreach ($drive in $fixedDrives) {
    $mountPoint = $drive.MountPoint
    $status = $drive.ProtectionStatus

    if ($status -eq 1) {
        Write-Host "BitLocker already enabled on $mountPoint." -ForegroundColor Green
        continue
    }

    Write-Host "`nEnabling BitLocker on $mountPoint..." -ForegroundColor Cyan

    # Choose protector based on volume type
    if ($drive.VolumeType -eq "Operating System") {
        Enable-BitLocker -MountPoint $mountPoint -EncryptionMethod XtsAes256 -TpmProtector
    }
    else {
        Enable-BitLocker -MountPoint $mountPoint -EncryptionMethod XtsAes256 -TpmProtector -UsedSpaceOnly
    }

    # Backup recovery key to Azure AD
    try {
        BackupToAAD-BitLockerKeyProtector -MountPoint $mountPoint -ErrorAction Stop
        Write-Host "Recovery key backed up to Azure AD for $mountPoint." -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Failed to back up recovery key for $mountPoint. Error: $_"
    }

    # Start encryption
    Resume-BitLocker -MountPoint $mountPoint
    Start-Sleep -Seconds 2
}

# Summary
Write-Host "`nEncryption status summary:" -ForegroundColor Magenta
Get-BitLockerVolume | Select-Object MountPoint, VolumeType, ProtectionStatus, EncryptionPercentage | Format-Table -AutoSize
