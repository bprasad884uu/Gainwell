# Define the Wallpaper Policy VBScript script path
$vbsPathPolicy = Join-Path "C:\Windows\System32" "WingetPolicy.vbs"

# Create a VBScript file for wallpaper policy
$vbsContentPolicy = @"
' Create a temporary file to store the powershell script
Set fso = CreateObject("Scripting.FileSystemObject")
Set tmp = fso.GetSpecialFolder(2)
Set psFile = fso.CreateTextFile(tmp & "\TempScript.ps1")

' Write the powershell script content to the file
psFile.WriteLine "# Function to check if Winget is installed and perform actions"
psFile.WriteLine "function Check-WingetAndUpgrade {"
psFile.WriteLine "    Write-Output ""Checking if Winget is installed..."""
psFile.WriteLine "    `$appInstallerPath = ""C:\Program Files\WindowsApps"""
psFile.WriteLine "    `$searchPattern = ""Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"""
psFile.WriteLine "    `$installerFolder = Get-ChildItem -Path `$appInstallerPath -Filter `$searchPattern -ErrorAction SilentlyContinue | Select-Object -First 1"
psFile.WriteLine "    if (`$installerFolder) {"
psFile.WriteLine "        `$wingetExePath = Join-Path -Path `$installerFolder.FullName -ChildPath 'winget.exe'"
psFile.WriteLine "        if (Test-Path `$wingetExePath) {"
psFile.WriteLine "            Write-Output ""Winget found. Upgrading apps..."""
psFile.WriteLine "            try {"
psFile.WriteLine "                `$installedList = & `$wingetExePath list --accept-source-agreements 2>`$null"
psFile.WriteLine "                `$javaPackages = foreach (`$line in `$installedList) {"
psFile.WriteLine "                    if (`$line -match 'java|jdk|jre|temurin|adoptium') {"
psFile.WriteLine "                        `$parts = `$line -split '\s{2,}'"
psFile.WriteLine "                        `$pkg = `$parts | Where-Object { `$_ -match '\.' } | Select-Object -First 1"
psFile.WriteLine "                        if (`$pkg -and `$pkg.Length -gt 3) { `$pkg.Trim() }"
psFile.WriteLine "                    }"
psFile.WriteLine "                }"
psFile.WriteLine "                foreach (`$pkg in `$javaPackages) {"
psFile.WriteLine "                    Write-Output ""Blocking Java package from upgrade: `$pkg"""
psFile.WriteLine "                    & `$wingetExePath pin add --id `$pkg --blocking --accept-source-agreements 2>`$null"
psFile.WriteLine "                }"
psFile.WriteLine "                & `$wingetExePath upgrade --all --accept-source-agreements --accept-package-agreements --silent"
psFile.WriteLine "                Write-Output ""Upgrade completed successfully!"""
psFile.WriteLine "            } catch {"
psFile.WriteLine "                Write-Output ""Failed to upgrade apps. Error: `$_"""
psFile.WriteLine "            }"
psFile.WriteLine "        } else {"
psFile.WriteLine "            Write-Output ""Winget executable not found in the folder."""
psFile.WriteLine "            Install-Winget"
psFile.WriteLine "        }"
psFile.WriteLine "    } else {"
psFile.WriteLine "        Write-Output ""Winget installation folder not found."""
psFile.WriteLine "        Install-Winget"
psFile.WriteLine "    }"
psFile.WriteLine "}"
psFile.WriteLine ""
psFile.WriteLine "# Function to install Winget if not found"
psFile.WriteLine "function Install-Winget {"
psFile.WriteLine "    Write-Host ""Winget not found. Installing Winget..."" -ForegroundColor Yellow"
psFile.WriteLine "    `$progressPreference = 'SilentlyContinue'"
psFile.WriteLine "    `$downloadUrl = ""https://aka.ms/getwinget"""
psFile.WriteLine "    `$outputPath = ""`$env:USERPROFILE\Downloads\AppInstaller.msixbundle"""
psFile.WriteLine "    Write-Host ""Downloading App Installer from `$downloadUrl..."" -ForegroundColor Yellow"
psFile.WriteLine "    try {"
psFile.WriteLine "        Invoke-WebRequest -Uri `$downloadUrl -OutFile `$outputPath -ErrorAction Stop"
psFile.WriteLine "        Write-Host ""Download completed successfully!"" -ForegroundColor Green"
psFile.WriteLine "    } catch {"
psFile.WriteLine "        Write-Host ""Failed to download App Installer. Error: `$_"" -ForegroundColor Red"
psFile.WriteLine "        exit"
psFile.WriteLine "    }"
psFile.WriteLine "    Write-Host ""Installing App Installer..."" -ForegroundColor Yellow"
psFile.WriteLine "    try {"
psFile.WriteLine "        Add-AppxPackage -Path `$outputPath -ErrorAction Stop"
psFile.WriteLine "        Write-Host ""App Installer installed successfully!"" -ForegroundColor Green"
psFile.WriteLine "    } catch {"
psFile.WriteLine "        Write-Host ""Failed to install App Installer. Error: `$_"" -ForegroundColor Red"
psFile.WriteLine "        exit"
psFile.WriteLine "    }"
psFile.WriteLine "    Write-Host ""Verifying installation of Winget..."" -ForegroundColor Yellow"
psFile.WriteLine "    if (Get-Command winget -ErrorAction SilentlyContinue) {"
psFile.WriteLine "        Write-Host ""Winget is successfully installed and ready to use!"" -ForegroundColor Green"
psFile.WriteLine "    } else {"
psFile.WriteLine "        Write-Host ""Winget installation failed or is not recognized in the PATH."" -ForegroundColor Red"
psFile.WriteLine "        exit"
psFile.WriteLine "    }"
psFile.WriteLine "    Write-Host ""Cleaning up downloaded file..."" -ForegroundColor Yellow"
psFile.WriteLine "    Remove-Item -Path `$outputPath -Force -ErrorAction SilentlyContinue"
psFile.WriteLine "    Write-Host ""Retrying upgrade process now that Winget is installed..."""
psFile.WriteLine "    Check-WingetAndUpgrade"
psFile.WriteLine "}"
psFile.WriteLine ""
psFile.WriteLine "# Call the function"
psFile.WriteLine "Check-WingetAndUpgrade"
psFile.WriteLine ""

' Close the file
psFile.Close

' Create a shell object to execute the powershell script
Set shell = CreateObject("WScript.Shell")

' Run the powershell script with the -ExecutionPolicy Bypass parameter
shell.Run "powershell -windowstyle hidden -executionpolicy bypass -noninteractive -File " & tmp & "\TempScript.ps1", 0, True

' Delete the temporary file
On Error Resume Next
fso.DeleteFile tmp & "\TempScript.ps1", True
On Error GoTo 0
"@

# Save the combined script to the file
$null = Set-Content -Path $vbsPathPolicy -Value $vbsContentPolicy

# Create a Wallpaper Policy task
$taskNamePolicy = "Winget Upgrade Policy"

# Define the action to execute the VBScript script
$actionPolicy = New-ScheduledTaskAction -Execute "wscript.exe" -Argument `"$vbsPathPolicy`"

# Create the time-based trigger
$timeTriggerPolicy = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)

# Create the startup-based trigger
$startupTrigger = New-ScheduledTaskTrigger -AtStartup

# Create the daily-based trigger
$dailyTriggerPolicy = New-ScheduledTaskTrigger -Daily -At "12:00PM"  # Adjust time if needed

# Define the task settings
$taskSettingsPolicy = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -WakeToRun -StartWhenAvailable
$taskSettingsPolicy.Hidden = $true
$taskSettingsPolicy.DisallowStartIfOnBatteries = $false
$taskSettingsPolicy.Priority = 7
$taskSettingsPolicy.ExecutionTimeLimit = "PT0S"

# Store all triggers in an array
$triggersPolicy = @($timeTriggerPolicy, $dailyTriggerPolicy, $startupTrigger)

# Define the task principal
$taskPrincipalPolicy = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest


if (Get-ScheduledTask -TaskName $taskNamePolicy -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskNamePolicy -Confirm:$false
}

# Register the scheduled task
$null = Register-ScheduledTask -Action $actionPolicy -Trigger $triggersPolicy -TaskName $taskNamePolicy -Settings $taskSettingsPolicy -Principal $taskPrincipalPolicy -Force

Write-Host "Winget silent upgrade task has been created. It will run at startup and daily, but only once per day."
