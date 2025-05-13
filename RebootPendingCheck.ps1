# Function to check pending reboots and their reasons
function Get-PendingRebootStatus {
    $rebootReasons = @()

    # Check Windows Update Reboot Requirement
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $rebootReasons += "Windows Update requires a reboot."
    }

    # Check Component-Based Servicing (CBS) Reboot Requirement
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $rebootReasons += "Component-Based Servicing (CBS) requires a reboot."
    }

    # Check Pending File Rename Operations
    $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($pendingFileRename) {
        $rebootReasons += "Pending File Rename Operations require a reboot."
    }

    # Check Windows Installer Pending Restart
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress") {
        $rebootReasons += "Windows Installer has pending installations requiring a reboot."
    }

    # Check System Center Configuration Manager (SCCM) Reboot
    $sccmReboot = Get-WmiObject -Query "SELECT RebootRequired FROM Win32_ComputerSystem" -Namespace "root\ccm\clientSDK" -ErrorAction SilentlyContinue
    if ($sccmReboot.RebootRequired) {
        $rebootReasons += "System Center Configuration Manager (SCCM) requires a reboot."
    }

    # Output results
    if ($rebootReasons.Count -gt 0) {
        Write-Host "A reboot is pending due to the following reasons:"
        $rebootReasons | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "No reboot is required."
    }
}

# Run the function
Get-PendingRebootStatus
