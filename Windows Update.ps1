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

    LogMessage "Advanced Update options enabled."
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

LogMessage "Initializing Update Session..."
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()
$updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
$updateServiceManager.ClientApplicationID = "PowerShell Update Script"

try {
    $null = $updateServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") 2>$null
	LogMessage("")
    LogMessage "Microsoft Update Service added."
} catch {
	LogMessage("")
    LogMessage "Microsoft Update Service already registered or failed to add."
}

LogMessage "Searching for available updates..."
$searchResult = $updateSearcher.Search("IsInstalled=0")
$updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

if ($searchResult.Updates.Count -eq 0) {
	LogMessage("")
    LogMessage "No updates found."
    return
}else {
	
LogMessage("")
LogMessage "---------------------------------"
LogMessage("")
LogMessage "Updates found: $($searchResult.Updates.Count)"
LogMessage("")
LogMessage "---------------------------------"

$index = 1
foreach ($update in $searchResult.Updates) {
    $type = if ($update.DriverClass) { "Driver" } else { "Software" }
    $sizeFormatted = Format-Size $update.MaxDownloadSize
    $hiddenStatus = if ($update.IsHidden) { "[Hidden]" } else { "" }
    LogMessage "[$index/$($searchResult.Updates.Count)] [$type] $($update.Title) $hiddenStatus, Size: $sizeFormatted"

    if (-not $update.EulaAccepted) {
        $null = $update.AcceptEula()
    }
    $null = $updatesToDownload.Add($update)
    $index++
}

# ------------------------ Download Updates ------------------------
$downloader = $updateSession.CreateUpdateDownloader()
LogMessage("")
LogMessage "---------------------------------"
LogMessage("")
LogMessage "Downloading updates..."
LogMessage("")
LogMessage "---------------------------------"

for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
    $update = $updatesToDownload.Item($i)
    $title = $update.Title
    $sizeFormatted = Format-Size $update.MaxDownloadSize
	LogMessage("")
    LogMessage "Downloading: $title ($sizeFormatted)..."

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
        LogMessage "Downloaded: $title"
		LogMessage("")
    } else {
        LogMessage "Failed to download: $title"
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
	LogMessage("")
    LogMessage "No updates downloaded to install."
    return
}

LogMessage "---------------------------------"
LogMessage "Installing updates..."
LogMessage "---------------------------------"
$installed = @()
$failed = @()

for ($i = 0; $i -lt $updatesToInstall.Count; $i++) {
    $update = $updatesToInstall.Item($i)
    $title = $update.Title
    $sizeFormatted = Format-Size $update.MaxDownloadSize
    $type = if ($update.DriverClass) { "Driver" } else { "Software" }
    $hiddenStatus = if ($update.IsHidden) { "[Hidden]" } else { "" }

	LogMessage("")
    LogMessage "Installing: [$type] $title $hiddenStatus, Size: $sizeFormatted"

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
		LogMessage("")
        LogMessage "Installed: $title"
        $installed += $title
    } else {
		LogMessage("")
        LogMessage "Failed to install: $title"
        $failed += $title
    }
}

# ------------------------ Summary ------------------------
LogMessage "---------------------------------"
LogMessage "Summary:"
LogMessage "---------------------------------"
LogMessage "Installed Updates: $($installed.Count)"
$installed | ForEach-Object { LogMessage "- $_" }

if ($failed.Count -gt 0) {
	LogMessage("")
    LogMessage "Failed Updates: $($failed.Count)"
    $failed | ForEach-Object { LogMessage "- $_" }
} else {
	LogMessage("")
	LogMessage "---------------------------------"
    LogMessage "All updates installed successfully!"
}
}

# ------------------------ Time Elapsed ------------------------
$endTime = Get-Date
$duration = $endTime - $startTime
LogMessage("")
LogMessage "Start Time : $($startTime.ToString("HH:mm:ss"))"
LogMessage("")
LogMessage "End Time   : $($endTime.ToString("HH:mm:ss"))"
LogMessage("")
LogMessage "Total Time : $($duration.ToString("hh\:mm\:ss"))"
