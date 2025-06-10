# Define paths
$psScriptPath = "C:\Windows\Block-Anydesk.ps1"
$vbsScriptPath = "C:\Windows\RunHidden.vbs"

# PowerShell script content
$psScriptContent = @'
Add-Type -AssemblyName System.Windows.Forms
$blockMessage = "Your Administrator Blocked AnyDesk for security reason."

function Block-AnyDesk {
    $processes = Get-Process | Where-Object {
        try {
            ($_.MainModule.FileVersionInfo.ProductName -eq "AnyDesk")
        } catch {
            $false
        }
    }

    foreach ($proc in $processes) {
        try {
            Stop-Process -Id $proc.Id -Force
            [System.Windows.Forms.MessageBox]::Show($blockMessage, "Anydesk!", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        } catch {
            Write-Host "Failed to stop process $($proc.Name): $_"
        }
    }
}

while ($true) {
    Block-AnyDesk
    Start-Sleep -Seconds 5
}
'@

# VBScript content
$vbsScriptContent = @'
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File ""C:\Windows\Block-Anydesk.ps1""", 0
'@

# Write the scripts
Set-Content -Path $psScriptPath -Value $psScriptContent -Force
Set-Content -Path $vbsScriptPath -Value $vbsScriptContent -Force

# Create a Wallpaper Policy task
$taskNamePolicy = "BlockAnyDeskTask Policy"

# Define the action to execute the VBScript script
$actionPolicy = New-ScheduledTaskAction -Execute "wscript.exe" -Argument `"$vbsScriptPath`"

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

Write-Host "Anydesk Policy Updated"