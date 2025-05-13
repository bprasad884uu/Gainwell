$ntpServer = "10.131.76.5"

try {
    Write-Host "Configuring NTP time sync with $ntpServer..." -ForegroundColor Cyan

    # Set NTP server and configure sync settings
    w32tm /config /manualpeerlist:$ntpServer /syncfromflags:manual /reliable:no /update | Out-Null

    # Restart time service
    net stop w32time /y | Out-Null
    net start w32time | Out-Null

    # Force time sync
    w32tm /resync | Out-Null

    # Output current NTP source
    $source = w32tm /query /source
    Write-Host "Time source is now: $source" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to configure NTP sync: $_"
}
