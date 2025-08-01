# Define task name
$taskNamePolicy = "BlockAnyDeskTask Policy"

# Disable the task
Write-Host "Disabling scheduled task: $taskNamePolicy" -ForegroundColor Yellow
Disable-ScheduledTask -TaskName $taskNamePolicy -ErrorAction SilentlyContinue

# Wait 1 hour
Write-Host "Task disabled. Waiting for 1 hour..." -ForegroundColor Cyan
Start-Sleep -Seconds 3600

# Re-enable the task
Write-Host "Re-enabling scheduled task: $taskNamePolicy" -ForegroundColor Yellow
Enable-ScheduledTask -TaskName $taskNamePolicy -ErrorAction SilentlyContinue

Write-Host "Task has been re-enabled." -ForegroundColor Green
