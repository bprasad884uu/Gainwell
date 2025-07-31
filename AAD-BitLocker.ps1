# Run as admin check
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Run as Administrator!" -ForegroundColor Red
    Exit
}

function Get-TPMStatus {
    try {
        $tpm = Get-WmiObject -Namespace "Root\CIMV2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
        return @{
            Present = $true
            Enabled = $tpm.IsEnabled_InitialValue
            Activated = $tpm.IsActivated_InitialValue
        }
    }
    catch {
        return @{
            Present = $false
            Enabled = $false
            Activated = $false
        }
    }
}

$tpmStatus = Get-TPMStatus
Write-Host "TPM Present: $($tpmStatus.Present) | Enabled: $($tpmStatus.Enabled) | Activated: $($tpmStatus.Activated)"

# If no TPM → enable policy to bypass requirement
if (-not ($tpmStatus.Present -and $tpmStatus.Enabled -and $tpmStatus.Activated)) {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPM /t REG_DWORD /d 0 /f >$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKey /t REG_DWORD /d 0 /f >$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKeyPIN /t REG_DWORD /d 0 /f >$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EnableBDEWithNoTPM /t REG_DWORD /d 1 /f >$null
    Write-Host "Applied No-TPM policy. Refreshing group policy..."
    gpupdate /target:computer /force | Out-Null
}

# Encrypt all drives
$drives = Get-BitLockerVolume | Where-Object { $_.VolumeType -in @('OperatingSystem','Data') }

foreach ($drive in $drives) {
    if ($drive.ProtectionStatus -eq 'On') {
        Write-Host "$($drive.MountPoint) already encrypted."
        continue
    }

    # Add correct protector
    if ($drive.VolumeType -eq 'OperatingSystem') {
        if ($tpmStatus.Present -and $tpmStatus.Enabled -and $tpmStatus.Activated) {
            Write-Host "Enabling BitLocker with TPM on OS drive $($drive.MountPoint)..."
            Enable-BitLocker -MountPoint $drive.MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly:$false -TpmProtector
        }
        else {
            Write-Host "Enabling BitLocker without TPM (Recovery Password) on OS drive $($drive.MountPoint)..."
            $RecoveryPass = Add-BitLockerKeyProtector -MountPoint $drive.MountPoint -RecoveryPasswordProtector
            Write-Host "Recovery Password: $($RecoveryPass.RecoveryPassword)"
            Enable-BitLocker -MountPoint $drive.MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly:$false -RecoveryPasswordProtector
        }
    }
    else {
        Write-Host "Enabling BitLocker with Recovery Password on data drive $($drive.MountPoint)..."
        $RecoveryPass = Add-BitLockerKeyProtector -MountPoint $drive.MountPoint -RecoveryPasswordProtector
        Write-Host "Recovery Password: $($RecoveryPass.RecoveryPassword)"
        Enable-BitLocker -MountPoint $drive.MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly:$false -RecoveryPasswordProtector
    }

    # Show progress until fully encrypted
    Write-Host "Encrypting $($drive.MountPoint)..."
    do {
        Start-Sleep -Seconds 10
        $status = Get-BitLockerVolume -MountPoint $drive.MountPoint
        $percent = [math]::Round($status.EncryptionPercentage,2)
        Write-Host ("  Status: {0}% ({1})" -f $percent, $status.VolumeStatus)
    } until ($status.VolumeStatus -eq 'FullyEncrypted')

    Write-Host "$($drive.MountPoint) encryption completed!" -ForegroundColor Green

    # Backup to Azure AD after full encryption
    try {
        BackupToAAD-BitLockerKeyProtector -MountPoint $drive.MountPoint -ErrorAction Stop
        Write-Host "Recovery key backed up to Azure AD." -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to back up to Azure AD: $_" -ForegroundColor Red
    }
}

Write-Host "BitLocker encryption process completed for all drives." -ForegroundColor Green
