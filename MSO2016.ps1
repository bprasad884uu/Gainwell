# Define the command and its arguments
$office = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*Microsoft Office Standard 2019*" } | Select-Object -Property DisplayName, UninstallString
$UnistallArgs = "$($office.UninstallString) DisplayLevel=False /force /uninstall /silent"

# Start the Uninstallation process
Start-Process cmd -ArgumentList $UnistallArgs -NoNewWindow -Wait

# Define the network location and credentials
$NetworkDrive = "Z"
$NetworkPath = "\\10.131.76.6\Software\Office 2016\SW_DVD5_Office_2016_64Bit_English_MLF_X20-42479"
$SecurePassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential("it", $SecurePassword)

# Map the network drive
New-PSDrive -Name $NetworkDrive -PSProvider FileSystem -Root $NetworkPath -Credential $Credential -Persist	

# Copy contents to a temporary location and run Setup.bat
$TempLocation = "C:\Temp"
Copy-Item -Path "$($NetworkDrive):\*" -Destination $TempLocation -Recurse -Force
cd $TempLocation
.\Setup.bat

# Navigate to the directory containing the update script and Run the update script
$UpdatePath = Join-Path "$TempLocation" "AllUpdates\Install-OSDUpdatePackages.ps1"
cd (Split-Path -Parent $UpdatePath)
Invoke-Expression $UpdatePath

# After Setup.bat completes, remove the contents
cd "C:\"
Remove-Item -Path $TempLocation -Recurse -Force

#Unmount Network Drive
Remove-PSDrive -Name $NetworkDrive -Force