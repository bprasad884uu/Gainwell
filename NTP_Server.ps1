# NTP Setup Script for Server 2019 (PDC Emulator)
$logPath = "C:\Temp\NTP_Setup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ntpServers = "0.in.pool.ntp.org 1.in.pool.ntp.org 2.in.pool.ntp.org"

# Ensure C:\Temp exists
New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null

# Log function
function Log {
    param ([string]$msg)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $msg" | Tee-Object -FilePath $logPath -Append
}

Log "Starting NTP setup on Server 10.131.76.5..."

# Step 1: Configure NTP
Log "Configuring manual NTP peers: $ntpServers"
w32tm /config /manualpeerlist:"$ntpServers" /syncfromflags:manual /reliable:yes /update | Out-Null

# Step 2: Restart time service
Log "Restarting Windows Time service..."
Restart-Service w32time -Force
Start-Sleep -Seconds 5

# Step 3: Force resync
Log "Forcing time resync..."
w32tm /resync | Out-Null

# Step 4: Output current source and status
$source = w32tm /query /source
$status = w32tm /query /status

Log "Current time source: $source"
Log "Current status:`n$status"

Log "NTP setup completed successfully."

# Output final message
Write-Output "`nNTP configuration complete. Log saved to: $logPath"
