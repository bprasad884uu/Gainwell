# Uninstall_FortiClient.ps1
# Uninstall FortiClient VPN
# Author: Bishnu

$DidUninstall = $false
$DidInstall   = $false
$downloadSuccess = $false

Write-Host "`n=== Checking for FortiClient VPN ==="

# Always initialize as empty array
$FortiClient = @()

# Detect installed FortiClient VPN from registry (64-bit)
$FortiClient += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
    Where-Object { $_.DisplayName -like "*FortiClient*" -or $_.DisplayName -like "*Fortinet*" }

# Detect installed FortiClient VPN from registry (32-bit on 64-bit OS)
$FortiClient += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
    Where-Object { $_.DisplayName -like "*FortiClient*" -or $_.DisplayName -like "*Fortinet*" }

if ($FortiClient.Count -gt 0) {
    foreach ($App in $FortiClient) {
        Write-Host "`nFound: $($App.DisplayName) - Uninstalling..."
        if ($App.UninstallString) {
            if ($App.UninstallString -match "msiexec") {
                Start-Process "msiexec.exe" -ArgumentList "/x $($App.PSChildName) /qn /norestart" -Wait
            } else {
                $UninstallCmd = $App.UninstallString -replace '"',''
                Start-Process "cmd.exe" -ArgumentList "/c `"$UninstallCmd /quiet /norestart`"" -Wait
            }
            Write-Host "`n$($App.DisplayName) removed."
            $DidUninstall = $true
        }
    }
} else {
    Write-Host "`nNo FortiClient VPN detected."
}

Write-Host "`n=== Script Finished ==="
