# Function to remove MRT scheduled task if it exists
function Remove-MRTTask {
    $taskName = "Microsoft\Windows\MRT\MRT_HB"
    
    # Check if the scheduled task exists
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        # Disable the task
        Disable-ScheduledTask -TaskName $taskName
        
        # Remove the task
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "MRT scheduled task removed."
    } else {
        Write-Host "MRT scheduled task not found."
    }
}

# Function to remove MRT executable and logs
function Remove-MRTFiles {
    $mrtPath = "C:\Windows\System32\MRT.exe"
    $mrtLogPath = "C:\Windows\Debug\MRT.log"
    $mpCmdRunLogPath = "C:\Windows\Debug\MpCmdRun.log"
    
    # Remove MRT executable
    if (Test-Path $mrtPath) {
        Remove-Item -Path $mrtPath -Force
        Write-Host "MRT executable removed."
    } else {
        Write-Host "MRT executable not found."
    }

    # Remove MRT log files
    if (Test-Path $mrtLogPath) {
        Remove-Item -Path $mrtLogPath -Force
        Write-Host "MRT log file removed."
    } else {
        Write-Host "MRT log file not found."
    }

    if (Test-Path $mpCmdRunLogPath) {
        Remove-Item -Path $mpCmdRunLogPath -Force
        Write-Host "MpCmdRun log file removed."
    } else {
        Write-Host "MpCmdRun log file not found."
    }
}

# Function to remove MRT-related registry entries
function Remove-MRTRegistryEntries {
    $mrtRegPath = "HKLM:\SOFTWARE\Microsoft\RemovalTools\MRT"

    # Remove MRT registry key
    if (Test-Path $mrtRegPath) {
        Remove-Item -Path $mrtRegPath -Recurse -Force
        Write-Host "MRT registry entries removed."
    } else {
        Write-Host "MRT registry entries not found."
    }
}

# Main Script Execution
Remove-MRTTask
Remove-MRTFiles
Remove-MRTRegistryEntries

Write-Host "MRT removal complete."
