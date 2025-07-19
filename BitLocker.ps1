# Get the status of all drives
$drives = Get-BitLockerVolume

foreach ($drive in $drives) {
    if ($drive.VolumeStatus -eq 'FullyEncrypted' -or $drive.VolumeStatus -eq 'EncryptionInProgress') {
        Write-Output "`nDisabling BitLocker on drive $($drive.MountPoint)..."
        Disable-BitLocker -MountPoint $drive.MountPoint

        # Monitor the decryption progress in real-time
        do {
            Start-Sleep -Seconds 5
            $updatedDrive = Get-BitLockerVolume -MountPoint $drive.MountPoint
            $percentage = $updatedDrive.EncryptionPercentage

            if ($null -ne $percentage) {
                Write-Host "`rProgress: $percentage% " -NoNewline
            }
        } while ($updatedDrive.VolumeStatus -ne 'FullyDecrypted')

        Write-Host "`rProgress: 100% - Drive $($drive.MountPoint) fully decrypted.`n"
    } else {
        Write-Host "`nBitLocker is not enabled on drive $($drive.MountPoint)`n"
    }
}
