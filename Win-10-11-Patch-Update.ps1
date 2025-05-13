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
        # KB5035853 is not installed, download and install it
        Write-Host "KB5035853 is not installed, downloading and installing it..."
		[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        # Download the update from the provided URL to the %temp% location
        $DownloadUrl = "https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/594b22d5-84c3-4665-bdc7-3167c91759b9/public/windows11.0-kb5035853-x64_8ca1a9a646dbe25c071a8057f249633a61929efa.msu"
        $DownloadPath = Join-Path -Path $env:TEMP -ChildPath "KB5035853.msu"
        # Invoke the web request to download the file
        Write-Host "Downloading..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath
        # Install the update using wusa.exe
		Write-Host "Installing..."
        Start-Process -FilePath "wusa.exe" -ArgumentList "$DownloadPath /quiet /norestart" -Wait
        # Delete the downloaded file
        Remove-Item -Path $DownloadPath
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
        # KB5035845 is not installed, download and install it
        Write-Host "KB5035845 is not installed, downloading and installing it..."
		[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        # Download the update from the provided URL to the %temp% location
        $DownloadUrl = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/03/windows10.0-kb5035845-x64_b4c28c9c57c35bac9226cde51685e41c281e40eb.msu"
        $DownloadPath = Join-Path -Path $env:TEMP -ChildPath "KB5035845.msu"
        # Invoke the web request to download the file
		Write-Host "Downloading..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath
        # Install the update using wusa.exe
		Write-Host "Installing..."
        Start-Process -FilePath "wusa.exe" -ArgumentList "$DownloadPath /quiet /norestart" -Wait
        # Delete the downloaded file
        Remove-Item -Path $DownloadPath
    }
}
# Check if the Windows version is 10 - 1607
elseif ($WindowsVersion -eq "14393") {
    # Check if KB5035855 is installed
    $KB5035855 = Get-HotFix -Id KB5035855 -ErrorAction SilentlyContinue
    if ($KB5035855) {
        # KB5035855 is installed, do nothing
        Write-Host "KB5035855 is already installed."
    }
    else {
        # KB5035855 is not installed, download and install it
        Write-Host "KB5035855 is not installed, downloading and installing it..."
		[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        # Download the update from the provided URL to the %temp% location
        $DownloadUrl = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/03/windows10.0-kb5035855-x64_e8a751d90de714d200f1a1491d4d098323e4c2db.msu"
        $DownloadPath = Join-Path -Path $env:TEMP -ChildPath "KB5035855.msu"
        # Invoke the web request to download the file
		Write-Host "Downloading..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath
        # Install the update using wusa.exe
		Write-Host "Installing..."
        Start-Process -FilePath "wusa.exe" -ArgumentList "$DownloadPath /quiet /norestart" -Wait
        # Delete the downloaded file
        Remove-Item -Path $DownloadPath
    }
}
# Check if the Windows version is 10 - 1809
elseif ($WindowsVersion -eq "17763") {
    # Check if KB5035849 is installed
    $KB5035849 = Get-HotFix -Id KB5035849 -ErrorAction SilentlyContinue
    if ($KB5035849) {
        # KB5035849 is installed, do nothing
        Write-Host "KB5035849 is already installed."
    }
    else {
        # KB5035849 is not installed, download and install it
        Write-Host "KB5035849 is not installed, downloading and installing it..."
		[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        # Download the update from the provided URL to the %temp% location
        $DownloadUrl = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/03/windows10.0-kb5035849-x64_eb960a140cd0ba04dd175df1b3268295295bfefa.msu"
        $DownloadPath = Join-Path -Path $env:TEMP -ChildPath "KB5035849.msu"
        # Invoke the web request to download the file
		Write-Host "Downloading..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath
        # Install the update using wusa.exe
		Write-Host "Installing..."
        Start-Process -FilePath "wusa.exe" -ArgumentList "$DownloadPath /quiet /norestart" -Wait
        # Delete the downloaded file
        Remove-Item -Path $DownloadPath
    }
}
# Check if the Windows version is Server 2016
elseif ($WindowsVersion -eq "14393") {
	# Check if KB5035855 is installed
    $KB5035855 = Get-HotFix -Id KB5035855 -ErrorAction SilentlyContinue
    if ($KB5035855) {
        # KB5035855 is installed, do nothing
        Write-Host "KB5035855 is already installed."
    }
    else {
        # KB5035855 is not installed, download and install it
        Write-Host "KB5035855 is not installed, downloading and installing it..."
		[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        # Download the update from the provided URL to the %temp% location
        $DownloadUrl = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/03/windows10.0-kb5035855-x64_e8a751d90de714d200f1a1491d4d098323e4c2db.msu"
        $DownloadPath = Join-Path -Path $env:TEMP -ChildPath "KB5035855.msu"
        # Invoke the web request to download the file
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath
        # Install the update using wusa.exe
        Start-Process -FilePath "wusa.exe" -ArgumentList "$DownloadPath /quiet /norestart" -Wait
        # Delete the downloaded file
        Remove-Item -Path $DownloadPath
    }
}
# Check if the Windows version is Server 2019
elseif ($WindowsVersion -eq "17763") {
	# Check if KB5035849 is installed
    $KB5035849 = Get-HotFix -Id KB5035849 -ErrorAction SilentlyContinue
    if ($KB5035849) {
        # KB5035849 is installed, do nothing
        Write-Host "KB5035849 is already installed."
    }
    else {
        # KB5035849 is not installed, download and install it
        Write-Host "KB5035849 is not installed, downloading and installing it..."
		[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        # Download the update from the provided URL to the %temp% location
        $DownloadUrl = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/03/windows10.0-kb5035849-x64_eb960a140cd0ba04dd175df1b3268295295bfefa.msu"
        $DownloadPath = Join-Path -Path $env:TEMP -ChildPath "KB5035849.msu"
        # Invoke the web request to download the file
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath
        # Install the update using wusa.exe
        Start-Process -FilePath "wusa.exe" -ArgumentList "$DownloadPath /quiet /norestart" -Wait
        # Delete the downloaded file
        Remove-Item -Path $DownloadPath
    }
}
# Check if the Windows version is Server 2022
elseif ($WindowsVersion -eq "20348") {
	# Check if KB5035857 is installed
    $KB5035857 = Get-HotFix -Id KB5035857 -ErrorAction SilentlyContinue
    if ($KB5035857) {
        # KB5035857 is installed, do nothing
        Write-Host "KB5035857 is already installed."
    }
    else {
        # KB5035857 is not installed, download and install it
        Write-Host "KB5035857 is not installed, downloading and installing it..."
		[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        # Download the update from the provided URL to the %temp% location
        $DownloadUrl = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/03/windows10.0-kb5035857-x64_f699534e61e7e8e750a7f751f6a1ff4d03bd3ebb.msu"
        $DownloadPath = Join-Path -Path $env:TEMP -ChildPath "KB5035857.msu"
        # Invoke the web request to download the file
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath
        # Install the update using wusa.exe
        Start-Process -FilePath "wusa.exe" -ArgumentList "$DownloadPath /quiet /norestart" -Wait
        # Delete the downloaded file
        Remove-Item -Path $DownloadPath
    }
}
else {
    # The Windows version is not 10 or 11, do nothing
    Write-Host "The Windows version is not supported"
}