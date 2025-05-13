# Get the Windows version
$WindowsVersion = [System.Environment]::OSVersion.Version.Build

# Check if the Windows version is 11
if ($WindowsVersion -eq "22631" -or $WindowsVersion -eq "22621" -or $WindowsVersion -eq "22000") {
    # Check if KB5035853 is installed
    $KB5035853 = Get-HotFix -Id KB5035853 -ErrorAction SilentlyContinue
    if ($KB5035853) {
        # KB5035853 is installed, do nothing
        Write-Host "KB5035853 is already installed."
    }
    else {
        # Patch is not installed, download and install it
        # Map a network drive
		$NetworkDrive = "Z"
		$NetworkPath = "\\10.131.76.6\Software\WindowsPatch"
		$SecurePassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
		$Credential = New-Object System.Management.Automation.PSCredential("it", $SecurePassword)
		New-PSDrive -Name $NetworkDrive -PSProvider FileSystem -Root $NetworkPath -Credential $Credential -Persist

		# Now copy the file from the mapped drive
		$DownloadPath = Join-Path -Path "${NetworkDrive}:" -ChildPath "KB5035853.msu"
		$TempPath = Join-Path -Path $env:TEMP -ChildPath "KB5035853.msu"
		Write-Host "Copying..."
		Copy-Item -Path $DownloadPath -Destination $TempPath

		# Remove the mapped drive
		Remove-PSDrive -Name $NetworkDrive

		# Install the update using wusa.exe
		Write-Host "Updating..."
		Start-Process -FilePath "wusa.exe" -ArgumentList "$TempPath /quiet /norestart" -Wait

		# Delete the downloaded file
		Remove-Item -Path $TempPath
    }
}

# Check if the Windows version is 10
elseif ($WindowsVersion -eq "19045" -or $WindowsVersion -eq "19044" -or $WindowsVersion -eq "19043") {
    # Check if KB5035845 is installed
    $KB5035845 = Get-HotFix -Id KB5035845 -ErrorAction SilentlyContinue
    if ($KB5035845) {
        # KB5035845 is installed, do nothing
        Write-Host "KB5035845 is already installed."
    }
    else {
        Write-Host "Windows 10 - KB5035845 is not installed, downloading and installing it..."
		# Map a network drive
		$NetworkDrive = "Z"
		$NetworkPath = "\\10.131.76.6\Software\WindowsPatch"
		$SecurePassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
		$Credential = New-Object System.Management.Automation.PSCredential("it", $SecurePassword)
		New-PSDrive -Name $NetworkDrive -PSProvider FileSystem -Root $NetworkPath -Credential $Credential -Persist

		# Now copy the file from the mapped drive
		$DownloadPath = Join-Path -Path "${NetworkDrive}:" -ChildPath "KB5035845.msu"
		$TempPath = Join-Path -Path $env:TEMP -ChildPath "KB5035845.msu"
		Write-Host "Copying..."
		Copy-Item -Path $DownloadPath -Destination $TempPath

		# Remove the mapped drive
		Remove-PSDrive -Name $NetworkDrive

		# Install the update using wusa.exe
		Write-Host "Updating..."
		Start-Process -FilePath "wusa.exe" -ArgumentList "$TempPath /quiet /norestart" -Wait

		# Delete the downloaded file
		Remove-Item -Path $TempPath
    }
}
else {
    # The Windows version is not 10 or 11, do nothing
    Write-Host "The Windows version is not 10 or 11."
}