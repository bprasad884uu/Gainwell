# Function to log messages
function LogMessage([string]$message) {
    Write-Host $message
}

# Function to extract numbers from a string
function ExtractNumbers([string]$str) {
    $cleanString = $str -replace "[^0-9]"
    return [long]$cleanString
}

# Capture start time
$startTime = [DateTime]::Now
LogMessage("Start time: $startTime")
# Enable "Receive updates for other Microsoft products" (default behavior)
$null = (New-Object -com "Microsoft.Update.ServiceManager").AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")
# Optionally, you can disable "Receive updates for other Microsoft products" by uncommenting the following line:
# $null = (New-Object -com "Microsoft.Update.ServiceManager").RemoveService("7971f918-a847-4430-9279-4a52d1efe18d")

LogMessage("")
# Log the message indicating that the feature has been enabled
LogMessage("Enabled - Receive updates for other Microsoft products")

# 1️⃣ Enable Delivery Optimization
# Ensure the Delivery Optimization Config registry path exists
$DOConfigPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
if (!(Test-Path $DOConfigPath)) {
    New-Item -Path $DOConfigPath -Force | Out-Null
}
Set-ItemProperty -Path $DOConfigPath -Name "DODownloadMode" -Value 3
LogMessage("Delivery Optimization Enabled.")

# 2️⃣ Force Windows to Download Directly from Microsoft Servers
$DOPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if (!(Test-Path $DOPolicyPath)) {
    New-Item -Path $DOPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $DOPolicyPath -Name "DODownloadMode" -Value 0
LogMessage("Windows Update will now download directly from Microsoft servers.")

# 3️⃣ Increase Concurrent Downloads
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "DownloadPreference" -Value "2"
LogMessage("Concurrent downloads increased.")

# 4️⃣ Restart Windows Update Service Before Downloading
#Stop-Service wuauserv -Force
#Start-Service wuauserv -Force
#LogMessage("Windows Update service restarted.")

# Create an instance of the COM object
$updateSession = New-Object -ComObject Microsoft.Update.Session

# Create an update searcher
$updateSearcher = $updateSession.CreateUpdateSearcher()

# Search for updates
$updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
$searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' or Type='Driver' and IsHidden=0")
LogMessage("")
# Check if there are updates to install
if ($searchResult.Updates.Count -eq 0) {
	LogMessage("")
	LogMessage("No updates to install.")
} else {
	LogMessage("")
	LogMessage("Updates available:")

	# List updates and add them to download
	for ($i = 0; $i -lt $searchResult.Updates.Count; $i++) {
		$update = $searchResult.Updates.Item($i)
		$size = $update.MaxDownloadSize / 1MB # Convert size to MB
		LogMessage("{0}. {1}, Size: {2:N2} MB" -f ($i + 1), $update.Title, $size)
		$updatesToDownload.Add($update) | Out-Null
	}

	# Download updates
    LogMessage("")
    LogMessage("Downloading Updates...")
    $downloader = $updateSession.CreateUpdateDownloader()
    $downloader.Updates = $updatesToDownload

    # Indicate which updates are being downloaded with their index and total count
    for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
        LogMessage("({0}/{1}) Downloading: {2}" -f ($i + 1), $updatesToDownload.Count, $updatesToDownload.Item($i).Title)
    }

    $downloader.Download()
    LogMessage("Download complete.")	

	# Initialize counters for successful and failed updates
	$successfulUpdates = 0
	$failedUpdates = 0
	
	# Install updates
	LogMessage("")
	LogMessage("Installing Updates...")
	$installer = $updateSession.CreateUpdateInstaller()
	
	# Loop through each update to install
	for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
		$installer.Updates = $updatesToDownload
		$installationResult = $installer.Install()

		# Output result
		if ($installationResult.GetUpdateResult($i).ResultCode -eq 2) {
			LogMessage("")
			LogMessage("{0}. Update: {1} installed successfully." -f ($i + 1), $updatesToDownload.Item($i).Title)
			$successfulUpdates++
		} else {
			LogMessage("")
			LogMessage("Failed to install update : {0}." -f $updatesToDownload.Item($i).Title)
			$failedUpdates++
		}
	}
	LogMessage("")
	LogMessage("Installation finished. {0} updates installed successfully, {1} updates failed to install." -f $successfulUpdates, $failedUpdates)
	
	# Add reboot required check
    function Test-PendingReboot {
    $rebootRequired = $false

    # Check Component Based Servicing
    $cbServicing = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
    if ($cbServicing) {
        LogMessage("Reboot required: Component Based Servicing")
        $rebootRequired = $true
    }

    # Check Windows Update Auto Update
    $wuReboot = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
    if ($wuReboot) {
        LogMessage("Reboot required: Windows Update")
        $rebootRequired = $true
    }

    # Check PendingFileRenameOperations
    $pendingFileRename = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pendingFileRename) {
        LogMessage("Reboot required: Pending File Rename Operations")
        $rebootRequired = $true
    }

    # Check WMI for SCCM client (if applicable)
    $ccmReboot = Get-WmiObject -Namespace "ROOT\CCM\ClientSDK" -Class CCM_ClientUtilities -ErrorAction SilentlyContinue
    if ($ccmReboot) {
        $rebootStatus = $ccmReboot.DetermineIfRebootPending()
        if ($rebootStatus.RebootPending -eq $true) {
            LogMessage("Reboot required: SCCM Client")
            $rebootRequired = $true
        }
    }

    if (-not $rebootRequired) {
        LogMessage("No reboot is required.")
    }

    return $rebootRequired
}
# Run the function
Test-PendingReboot
}
LogMessage("")
# Capture end time
$endTime = [DateTime]::Now
LogMessage("End time: $endTime")
LogMessage("")
# Calculate and log elapsed time
$elapsedTime = $endTime - $startTime
LogMessage("Time Elapsed: $($elapsedTime.Hours) hours, $($elapsedTime.Minutes) minutes, $($elapsedTime.Seconds) seconds")
LogMessage("")
LogMessage("Successfully completed the operation")
