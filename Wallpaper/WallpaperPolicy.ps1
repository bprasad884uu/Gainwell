# Script created and registered by Bishnu Prasad Panigrahi
# All rights reserved. Unauthorized copying, distribution, or modification of this script is prohibited.

# Description:
# This script installs the Avamar Client, creates necessary configuration files, runs the avagent service,
# executes the avscc.exe command with the '--log' flag, and creates an 'AVBackup' directory on all available drives,
# including the C: drive. It ensures that the necessary directories and files exist before performing actions.
# It is specifically designed for environments using Avamar backup software.

# Set All file paths
$filePath = "C:\Windows\Web\Wallpaper\Windows\Wallpaper.jpg"
$batchFilePath = "C:\Windows\System32\ForcedWallpaperUpdate.bat"
$powershellPath = "C:\Windows\System32\ForcedWallpaperUpdate.ps1"
$triggerInterval = 5

# Get the current logged-in username from the registry
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
$lastLoggedOnSAMUser = (Get-ItemProperty -Path $registryPath -Name LastLoggedOnSAMUser).LastLoggedOnSAMUser
$domain, $username = $lastLoggedOnSAMUser -split '\\', 2

# Check if the batch file exists before attempting to delete
if (Test-Path $batchFilePath -PathType Leaf) {
    Remove-Item -Path $batchFilePath -Force
    Write-Host "Batch file '$batchFilePath' deleted successfully."
}
# Check if the Powershell file exists before attempting to delete
if (Test-Path $powershellPath -PathType Leaf) {
    Remove-Item -Path $powershellPath -Force
    Write-Host "Powershell file '$powershellPath' deleted successfully."
}

# Define the Wallpaper Policy VBScript script path
$vbsPathPolicy = Join-Path "C:\Windows\System32" "WallpaperPolicy.vbs"

# Define the Wallpaper Apply VBScript script path
$vbsPath  = Join-Path "C:\Windows\System32" "SetWallpaper.vbs"

# Create a VBScript file for wallpaper policy
$vbsContentPolicy = @"
' Create a temporary file to store the powershell script
Set fso = CreateObject("Scripting.FileSystemObject")
Set tmp = fso.GetSpecialFolder(2)
Set psFile = fso.CreateTextFile(tmp & "\TempScript.ps1")

' Write the powershell script content to the file
psFile.WriteLine "Set-ExecutionPolicy unrestricted -Force"
psFile.WriteLine "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"
psFile.WriteLine "# Set the path to the wallpaper image"
psFile.WriteLine "`$wallpaper = ""C:\Windows\Web\Wallpaper\Windows\Wallpaper.jpg"""
psFile.WriteLine ""
psFile.WriteLine "# Function to create registry key if it doesn't exist"
psFile.WriteLine "function Ensure-RegistryKey {"
psFile.WriteLine "    param ("
psFile.WriteLine "        [string]`$Path"
psFile.WriteLine "    )"
psFile.WriteLine ""
psFile.WriteLine "    if (-not (Test-Path `$Path)) {"
psFile.WriteLine "        New-Item -Path `$Path -Force"
psFile.WriteLine "    }"
psFile.WriteLine "}"
psFile.WriteLine ""
psFile.WriteLine "# Specify the registry path"
psFile.WriteLine "`$registryPath = ""Registry::HKEY_USERS"""
psFile.WriteLine ""
psFile.WriteLine "# Get all keys under the specified path"
psFile.WriteLine "`$keys = Get-ChildItem -Path `$registryPath"
psFile.WriteLine ""
psFile.WriteLine "# Filter out .DEFAULT and _Classes keys"
psFile.WriteLine "`$filteredKeys = `$keys | Where-Object { `$_.PSChildName -notlike ""*_Classes"" }"
psFile.WriteLine ""
psFile.WriteLine "# Set wallpaper for each user profile that exists"
psFile.WriteLine "foreach (`$key in `$filteredKeys) {"
psFile.WriteLine "    `$subKey = ""Registry::\HKEY_USERS\`$(`$key.PSChildName)"""
psFile.WriteLine ""
psFile.WriteLine "    # Check if the registry path exists before setting values"
psFile.WriteLine "    if (Test-Path `$subKey) {"
psFile.WriteLine "        `$desktopPath = ""`$subKey\Control Panel\Desktop"""
psFile.WriteLine ""
psFile.WriteLine "            # Ensure registry keys exist"
psFile.WriteLine "            Ensure-RegistryKey -Path ""`$desktopPath"""
psFile.WriteLine "            Ensure-RegistryKey -Path ""`$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System"""
psFile.WriteLine "            Ensure-RegistryKey -Path ""`$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"""
psFile.WriteLine ""
psFile.WriteLine "            # Set wallpaper values"
psFile.WriteLine "            Set-ItemProperty -Path ""`$desktopPath"" -Name Wallpaper -Value `$wallpaper -Force"
psFile.WriteLine "            Set-ItemProperty -Path ""`$desktopPath"" -Name WallpaperStyle -Value 2 -Force"
psFile.WriteLine "            Set-ItemProperty -Path ""`$desktopPath"" -Name TileWallpaper -Value 0 -Force"
psFile.WriteLine "            Set-ItemProperty -Path ""`$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System"" -Name Wallpaper -Value `$wallpaper -Force"
psFile.WriteLine "            Set-ItemProperty -Path ""`$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System"" -Name WallpaperStyle -Value 2 -Force"
psFile.WriteLine "            Set-ItemProperty -Path ""`$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System"" -Name NoDispBackgroundPage -Value 1 -Force"
psFile.WriteLine "            Set-ItemProperty -Path ""`$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"" -Name NoChangingWallPaper -Value 1 -Force"
psFile.WriteLine "    }"
psFile.WriteLine "}"
psFile.WriteLine ""
psFile.WriteLine "# Create registry path if it doesn't exist"
psFile.WriteLine "Ensure-RegistryKey -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"""
psFile.WriteLine ""
psFile.WriteLine "# Set wallpaper for all users on the machine"
psFile.WriteLine "Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"" -Name DesktopImagePath -Value `$wallpaper -Force"
psFile.WriteLine "Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"" -Name DesktopImageUrl -Value `$wallpaper -Force"
psFile.WriteLine "New-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"" -Name DesktopImageStatus -Value 1 -PropertyType DWORD -Force"
psFile.WriteLine "# Set LockScreen for all users on the machine"
psFile.WriteLine "Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"" -Name LockScreenImagePath -Value `$wallpaper -Force"
psFile.WriteLine "Set-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"" -Name LockScreenImageUrl -Value `$wallpaper -Force"
psFile.WriteLine "New-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"" -Name LockScreenImageStatus -Value 1 -PropertyType DWORD -Force"
psFile.WriteLine "Remove-Item ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"" -Force -ErrorAction SilentlyContinue"
psFile.WriteLine ""
psFile.WriteLine "# Refresh the group policy"
psFile.WriteLine "gpupdate /force"

' Close the file
psFile.Close

' Create a shell object to execute the powershell script
Set shell = CreateObject("WScript.Shell")

' Run the powershell script with the -ExecutionPolicy Bypass parameter
shell.Run "powershell -windowstyle hidden -executionpolicy bypass -noninteractive -File " & tmp & "\TempScript.ps1", 0, True

' Delete the temporary file
fso.DeleteFile tmp & "\TempScript.ps1"
"@

# Save the combined script to the file
$null = Set-Content -Path $vbsPathPolicy -Value $vbsContentPolicy

# Create a VBScript file for updating wallpaper
$vbsContent = @"
' Create a temporary file name for the powershell script
Dim fso, tempFolder, tempFile
Set fso = CreateObject("Scripting.FileSystemObject")
Set tempFolder = fso.GetSpecialFolder(2) ' Temporary folder
tempFile = tempFolder.Path & "\" & fso.GetTempName & ".ps1"

' Write the powershell script to the temporary file
Dim stream
Set stream = fso.CreateTextFile(tempFile, True)
stream.WriteLine "if (-not ([System.Management.Automation.PSTypeName]'Wallpaper').Type) {"
stream.WriteLine "Add-Type -TypeDefinition @"""
stream.WriteLine "using System;"
stream.WriteLine "using System.Runtime.InteropServices;"
stream.WriteLine ""
stream.WriteLine "public class Wallpaper {"
stream.WriteLine "    [DllImport(""user32.dll"", CharSet = CharSet.Auto)]"
stream.WriteLine "    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);"
stream.WriteLine "}"
stream.WriteLine """@"
stream.WriteLine "}"
stream.WriteLine ""
stream.WriteLine "# Default wallpaper path"
stream.WriteLine "`$wallpaper = ""C:\Windows\Web\Wallpaper\Windows\Wallpaper.jpg"""
stream.WriteLine "`$SPI_SETDESKWALLPAPER = 0x0014"
stream.WriteLine "`$UpdateIniFile = 0x01"
stream.WriteLine "`$SendChangeEvent = 0x02"
stream.WriteLine ""
stream.WriteLine "# Set the desktop wallpaper"
stream.WriteLine "`$null = [Wallpaper]::SystemParametersInfo(`$SPI_SETDESKWALLPAPER, 0, `$wallpaper, `$UpdateIniFile -bor `$SendChangeEvent)"
stream.WriteLine ""
stream.WriteLine "Write-Host ""Desktop wallpaper set successfully."""
stream.Close

' Run the powershell script from the temporary file
Dim shell
Set shell = CreateObject("Wscript.Shell")
shell.Run "powershell -windowstyle hidden -executionpolicy bypass -noninteractive -File " & tempFile, 0, True

' Delete the temporary file
fso.DeleteFile tempFile
"@

# Save the combined script to the file
$null = Set-Content -Path $vbsPath -Value $vbsContent


#-------------------------------------------#
# 		Wallpaper TaskScheduler Task		#
#-------------------------------------------#

# Create a Wallpaper Update Schedule task
$taskName = "Wallpaper Update Schedule"

# Define the action to execute the VBScript script
$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument `"$vbsPath`"

# Create the time-based trigger
$timeTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes $triggerInterval)

# Create the logon-based trigger
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn
# Assign the repetition settings from the one-time trigger to the logon trigger
$logonTrigger.Repetition = $timeTrigger.Repetition

# Create the session state change trigger
$StateChangeTrigger = Get-CimClass -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskSessionStateChangeTrigger
$onUnlockTrigger = New-CimInstance -CimClass $StateChangeTrigger -Property @{StateChange = 8} -ClientOnly
$onUnlockTrigger.Repetition = New-CimInstance -CimClass (Get-CimClass -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskRepetitionPattern) -Property @{Interval = 'PT5M'} -ClientOnly
	
# Store all triggers in an array
$triggers = @($timeTrigger, $logonTrigger, $onUnlockTrigger)

# Define the task settings
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -WakeToRun -StartWhenAvailable
$taskSettings.Hidden = $true
$taskSettings.DisallowStartIfOnBatteries = $false
$taskSettings.Priority = 7
$taskSettings.ExecutionTimeLimit = "PT0S"

# Define the task principal
$taskPrincipal = New-ScheduledTaskPrincipal -GroupId "NT AUTHORITY\INTERACTIVE" -RunLevel Highest

# Register the scheduled task
$null = Register-ScheduledTask -Action $action -Trigger $triggers -TaskName $taskName -Settings $taskSettings -Principal $taskPrincipal -Force

# Check if the task exists
#$Task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

#if ($Task -ne $null) {
#    Write-Host "Scheduled task '$taskName' created successfully."
#}

# Create a Wallpaper Policy task
$taskNamePolicy = "Wallpaper Policy"

# Define the action to execute the VBScript script
$actionPolicy = New-ScheduledTaskAction -Execute "wscript.exe" -Argument `"$vbsPathPolicy`"

# Create the time-based trigger
$timeTriggerPolicy = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)

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

Write-Host "Wallpaper Policy Updated"