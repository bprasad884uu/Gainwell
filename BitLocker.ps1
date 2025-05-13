# Get the status of all drives
$drives = Get-BitLockerVolume

foreach ($drive in $drives) {
    if ($drive.VolumeStatus -eq 'FullyEncrypted' -or $drive.VolumeStatus -eq 'EncryptionInProgress') {
        Write-Output "Disabling BitLocker on drive $($drive.MountPoint)"
        Disable-BitLocker -MountPoint $drive.MountPoint
    } else {
        Write-Output "BitLocker is not enabled on drive $($drive.MountPoint)"
    }
}
