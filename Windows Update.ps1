# ------------------------ Logger ------------------------
$startTime = Get-Date

function LogMessage([string]$message) {
    Write-Host $message
}

# ------------------------ Enable Advanced Options ------------------------
function Enable-AdvancedUpdateOptions {
    $uxSettingsPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    $wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $wuAUKey = "$wuPolicyPath\AU"

    foreach ($path in @($uxSettingsPath, $wuPolicyPath, $wuAUKey)) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
    }

    New-ItemProperty -Path $uxSettingsPath -Name "IsContinuousInnovationOptedIn" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $wuPolicyPath -Name "AllowMUUpdateService" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uxSettingsPath -Name "DownloadOverMetered" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $wuPolicyPath -Name "ExcludeWUDriversInQualityUpdate" -Value 0 -PropertyType DWord -Force | Out-Null
    Set-ItemProperty -Path $wuAUKey -Name "UseWUServer" -Value 0 -Force | Out-Null

    LogMessage("`nAdvanced Update options enabled.")
}

# ------------------------ Format Size Function ------------------------
function Format-Size {
    param ([long]$bytes)

    if ($bytes -gt 10GB) { return "N/A" }
    elseif ($bytes -ge 1GB) { return "{0:N2} GB" -f ($bytes / 1GB) }
    elseif ($bytes -ge 1MB) { return "{0:N2} MB" -f ($bytes / 1MB) }
    elseif ($bytes -ge 1KB) { return "{0:N2} KB" -f ($bytes / 1KB) }
    else { return "$bytes Bytes" }
}

# ------------------------ Start Execution ------------------------
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
Enable-AdvancedUpdateOptions

LogMessage("`nInitializing Update Session...")
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()
$updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
$updateServiceManager.ClientApplicationID = "PowerShell Update Script"

try {
    $null = $updateServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") 2>$null
    LogMessage("`nMicrosoft Update Service added.")
} catch {
    LogMessage("`nMicrosoft Update Service already registered or failed to add.")
}

LogMessage("`nSearching for available updates...")
$searchResult = $updateSearcher.Search("IsInstalled=0")
$updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

if ($searchResult.Updates.Count -eq 0) {
    LogMessage("`nNo updates found.")
    return
}else {

LogMessage("`n---------------------------------")
LogMessage("`nUpdates found: $($searchResult.Updates.Count)")
LogMessage("`n---------------------------------")

$index = 1
foreach ($update in $searchResult.Updates) {
    $type = if ($update.DriverClass) { "Driver" } else { "Software" }
    $sizeFormatted = Format-Size $update.MaxDownloadSize
    $hiddenStatus = if ($update.IsHidden) { "[Hidden]" } else { "" }
    LogMessage("`n[$index/$($searchResult.Updates.Count)] [$type] $($update.Title) $hiddenStatus, Size: $sizeFormatted")

    if (-not $update.EulaAccepted) {
        $null = $update.AcceptEula()
    }
    $null = $updatesToDownload.Add($update)
    $index++
}

# ------------------------ Download Updates ------------------------
$downloader = $updateSession.CreateUpdateDownloader()
LogMessage("`n---------------------------------")
LogMessage("`nDownloading updates...")
LogMessage("`n---------------------------------")

for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
    $update = $updatesToDownload.Item($i)
    $title = $update.Title
    $sizeFormatted = Format-Size $update.MaxDownloadSize
    LogMessage("`nDownloading: $title ($sizeFormatted)...")

    $singleDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    $null = $singleDownload.Add($update)
    $downloader.Updates = $singleDownload

    for ($p = 1; $p -le 100; $p += (Get-Random -Minimum 10 -Maximum 25)) {
        Write-Progress -Activity "Downloading Update" -Status "$title ($p%)" -PercentComplete $p
        Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 300)
    }

    $result = $downloader.Download()
    Write-Progress -Activity "Downloading Update" -Completed

    if ($result.ResultCode -eq 2) {
        LogMessage("`nDownloaded: $title")
    } else {
        LogMessage("`nFailed to download: $title")
    }
}

# ------------------------ Install Updates ------------------------
$updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($update in $updatesToDownload) {
    if ($update.IsDownloaded) {
        $null = $updatesToInstall.Add($update)
    }
}

if ($updatesToInstall.Count -eq 0) {
    LogMessage("`nNo updates downloaded to install.")
    return
}
LogMessage("`n---------------------------------")
LogMessage("`nInstalling updates...")
LogMessage("`n---------------------------------")
$installed = @()
$failed = @()

for ($i = 0; $i -lt $updatesToInstall.Count; $i++) {
    $update = $updatesToInstall.Item($i)
    $title = $update.Title
    $sizeFormatted = Format-Size $update.MaxDownloadSize
    $type = if ($update.DriverClass) { "Driver" } else { "Software" }
    $hiddenStatus = if ($update.IsHidden) { "[Hidden]" } else { "" }

    LogMessage("`nInstalling: [$type] $title $hiddenStatus, Size: $sizeFormatted")

    $singleUpdateColl = New-Object -ComObject Microsoft.Update.UpdateColl
    $null = $singleUpdateColl.Add($update)
    $installer = $updateSession.CreateUpdateInstaller()
    $installer.Updates = $singleUpdateColl

    for ($p = 1; $p -le 100; $p += (Get-Random -Minimum 8 -Maximum 15)) {
        Write-Progress -Activity "Installing Update" -Status "$title ($p%)" -PercentComplete $p
        Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 400)
    }

    $result = $installer.Install()
    Write-Progress -Activity "Installing Update" -Completed
    $resultCode = $result.GetUpdateResult(0).ResultCode

    if ($resultCode -eq 2) {
        LogMessage("`nInstalled: $title")
        $installed += $title
    } else {
        LogMessage("`nFailed to install: $title")
        $failed += $title
    }
}

# ------------------------ Summary ------------------------
LogMessage("`n---------------------------------")
LogMessage("`nSummary:")
LogMessage("`n---------------------------------")
LogMessage("`nInstalled Updates: $($installed.Count)")
$installed | ForEach-Object { LogMessage("`n- $_") }

if ($failed.Count -gt 0) {
    LogMessage "Failed Updates: $($failed.Count)"
    $failed | ForEach-Object { LogMessage("`n- $_") }
} else {
	LogMessage("`n---------------------------------")
    LogMessage("`nAll updates installed successfully!")
}

	# Add reboot required check
    function Test-PendingReboot {
    $rebootRequired = $false

    # Check Component Based Servicing
    $cbServicing = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
    if ($cbServicing) {
        LogMessage("`nReboot required: Component Based Servicing")
        $rebootRequired = $true
    }

    # Check Windows Update Auto Update
    $wuReboot = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
    if ($wuReboot) {
        LogMessage("`nReboot required: Windows Update")
        $rebootRequired = $true
    }

    # Check PendingFileRenameOperations
    $pendingFileRename = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pendingFileRename) {
        LogMessage("`nReboot required: Pending File Rename Operations")
        $rebootRequired = $true
    }

    # Check WMI for SCCM client (if applicable)
    $ccmReboot = Get-WmiObject -Namespace "ROOT\CCM\ClientSDK" -Class CCM_ClientUtilities -ErrorAction SilentlyContinue
    if ($ccmReboot) {
        $rebootStatus = $ccmReboot.DetermineIfRebootPending()
        if ($rebootStatus.RebootPending -eq $true) {
            LogMessage("`nReboot required: SCCM Client")
            $rebootRequired = $true
        }
    }

    if (-not $rebootRequired) {
        LogMessage("`nNo reboot is required.")
    }

    return $rebootRequired
}
# Run the function
$null = Test-PendingReboot
}

# ------------------------ Time Elapsed ------------------------
$endTime = Get-Date
$duration = $endTime - $startTime
LogMessage("`nStart Time : $($startTime.ToString("HH:mm:ss"))")
LogMessage("`nEnd Time   : $($endTime.ToString("HH:mm:ss"))")
LogMessage("`nTotal Time : $($duration.ToString("hh\:mm\:ss"))")
