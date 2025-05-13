# Create a unique task name
$taskNamePolicy = "Google Chrome Update Policy"

# Define the VBScript script path
$vbsPathPolicy = Join-Path "C:\Windows\System32" "ChromePolicy.vbs"

# Define the action to execute the VBScript script
$actionPolicy = New-ScheduledTaskAction -Execute "wscript.exe" -Argument `"$vbsPathPolicy`"

# Create the time-based trigger
$timeTriggerPolicy = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(20)

# Create the logon-based trigger
$logonTriggerPolicy = New-ScheduledTaskTrigger -AtLogOn

# Define the task settings
$taskSettingsPolicy = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -WakeToRun -StartWhenAvailable
$taskSettingsPolicy.Hidden = $true
$taskSettingsPolicy.DisallowStartIfOnBatteries = $false
$taskSettingsPolicy.Priority = 7
$taskSettingsPolicy.ExecutionTimeLimit = "PT0S"

# Store all triggers in an array
$triggersPolicy = @($timeTriggerPolicy, $logonTriggerPolicy)

# Define the task principal
$taskPrincipalPolicy = New-ScheduledTaskPrincipal -GroupId "NT AUTHORITY\INTERACTIVE" -RunLevel Highest

# Register the scheduled task
$null = Register-ScheduledTask -Action $actionPolicy -Trigger $triggersPolicy -TaskName $taskNamePolicy -Settings $taskSettingsPolicy -Principal $taskPrincipalPolicy -Force

# Create a VBScript file for updating Google Chrome
$vbsContentPolicy = @"
' Create a temporary file name for the powershell script
Dim fso, tempFolder, tempFile
Set fso = CreateObject("Scripting.FileSystemObject")
Set tempFolder = fso.GetSpecialFolder(2) ' Temporary folder
tempFile = tempFolder.Path & "\" & fso.GetTempName & ".ps1"

' Write the powershell script to the temporary file
Dim stream
Set stream = fso.CreateTextFile(tempFile, True)
stream.WriteLine "# Set security protocol"
stream.WriteLine "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
stream.WriteLine ""
stream.WriteLine "`$updateUrl = ""https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1"""
stream.WriteLine ""
stream.WriteLine "# Function to check if Chrome is installed"
stream.WriteLine "function Test-ChromeInstalled {"
stream.WriteLine "    try {"
stream.WriteLine "        `$chromePath = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -Name '(default)' -ErrorAction SilentlyContinue"
stream.WriteLine "        return `$chromePath"
stream.WriteLine "    } catch {"
stream.WriteLine "        return `$null"
stream.WriteLine "    }"
stream.WriteLine "}"
stream.WriteLine ""
stream.WriteLine "# Main script execution"
stream.WriteLine "try {"
stream.WriteLine "    # Check if Chrome is installed"
stream.WriteLine "    `$chromePath = Test-ChromeInstalled"
stream.WriteLine "    if (`$chromePath) {"
stream.WriteLine "        Write-Host ""Chrome is installed at """"`$chromePath"""""""
stream.WriteLine ""
stream.WriteLine "        # Download data using Invoke-WebRequest"
stream.WriteLine "        `$json = Invoke-RestMethod -Uri `$updateUrl"
stream.WriteLine ""        
stream.WriteLine "        # Parse JSON response (assuming successful download)"
stream.WriteLine "        `$chromeVersion = `$json.version"
stream.WriteLine ""        
stream.WriteLine "       # Get current installed Chrome version"
stream.WriteLine "       `$installedVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(`$chromePath).FileVersion"
stream.WriteLine ""        
stream.WriteLine "        # Check if update is available"
stream.WriteLine "        if (`$chromeVersion -ne `$installedVersion) {"
stream.WriteLine "            Write-Host ""Update available: `$chromeVersion"""
stream.WriteLine ""            
stream.WriteLine "            # Run update script if version mismatched"
stream.WriteLine "            Write-Host ""Current Version - `$installedVersion"""
stream.WriteLine "             [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
stream.WriteLine "             `$Path = `$env:TEMP"
stream.WriteLine "             `$Installer = ""chrome_installer.exe"""
stream.WriteLine "             Invoke-WebRequest ""https://dl.google.com/chrome/install/latest/chrome_installer.exe"" -OutFile ""$Path\$Installer"""
stream.WriteLine "             Start-Process -FilePath ""`$Path\$Installer"" -Args ""/silent /install"" -Verb RunAs -Wait"
stream.WriteLine "             Remove-Item ""`$Path\$Installer"""
stream.WriteLine " 			Write-Host ""Updated Version - `$installedVersion"""
stream.WriteLine "         } else {"
stream.WriteLine " 			Write-Host """""
stream.WriteLine "             Write-Host ""Installed version: $installedVersion."""
stream.WriteLine " 			Write-Host ""Chrome is up to date, no need to update."""
stream.WriteLine "         }"
stream.WriteLine "     } else {"
stream.WriteLine "        Write-Host ""Google Chrome is not installed on this system."""
stream.WriteLine "    }"
stream.WriteLine "} catch {"
stream.WriteLine "    Write-Host ""Error retrieving data: `$(`$_.Exception.Message)"""
stream.WriteLine " }"
stream.Close

' Run the powershell script from the temporary file
Dim shell
Set shell = CreateObject("Wscript.Shell")
shell.Run "powershell -windowstyle hidden -executionpolicy bypass -noninteractive -File " & tempFile, 0, True

' Delete the temporary file
fso.DeleteFile tempFile
"@

# Save the combined script to the file
$null = Set-Content -Path $vbsPathPolicy -Value $vbsContentPolicy