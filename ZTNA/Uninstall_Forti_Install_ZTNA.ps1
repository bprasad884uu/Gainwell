# Uninstall_Forti_Install_ZTNA.ps1
# Uninstall FortiClient VPN and Install ZTNA
# Author: Bishnu's Helper

$DidUninstall = $false
$DidInstall   = $false

Write-Host "=== Checking for FortiClient VPN ==="

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
        Write-Host "Found: $($App.DisplayName) - Uninstalling..."
        if ($App.UninstallString) {
            if ($App.UninstallString -match "msiexec") {
                Start-Process "msiexec.exe" -ArgumentList "/x $($App.PSChildName) /qn /norestart" -Wait
            } else {
                $UninstallCmd = $App.UninstallString -replace '"',''
                Start-Process "cmd.exe" -ArgumentList "/c `"$UninstallCmd /quiet /norestart`"" -Wait
            }
            Write-Host "$($App.DisplayName) removed."
            $DidUninstall = $true
        }
    }
} else {
    Write-Host "No FortiClient VPN detected."
}

Write-Host "`n=== Checking and Installing ZTNA (Zscaler) ==="

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$Installer = Join-Path $ScriptDir "Zscaler-windows-4.7.0.61-installer-x64.msi"

# Check if ZTNA already installed
$ZTNAInstalled = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
    Where-Object { $_.DisplayName -like "*Zscaler*" }

$ZTNAInstalled += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
    Where-Object { $_.DisplayName -like "*Zscaler*" }

if ($ZTNAInstalled.Count -gt 0) {
    Write-Host "ZTNA (Zscaler) is already installed. Skipping installation."
} elseif (Test-Path $Installer) {
    Write-Host "Installing ZTNA from: $Installer"
    Start-Process "msiexec.exe" -ArgumentList "/i `"$Installer`" /qn /norestart" -Wait
    Write-Host "ZTNA installation completed."
    $DidInstall = $true
} else {
    Write-Host "ERROR: Installer not found at $Installer"
}

Write-Host "`n=== Summary ==="
if ($DidUninstall) {
    Write-Host "✔ FortiClient VPN was uninstalled."
} else {
    Write-Host "ℹ No FortiClient VPN uninstalled."
}

if ($DidInstall) {
    Write-Host "✔ ZTNA (Zscaler) was installed."
	Write-Host "Stopping ZTNA processes..."
    $ProcessesToKill = @("ZSAService", "ZSATray", "ZSATrayManager")
    foreach ($proc in $ProcessesToKill) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force
    }
    Write-Host "ZTNA processes stopped. They will start on next system boot or user login."
} else {
    Write-Host "ℹ No ZTNA installation performed."
}

Write-Host "`n=== Script Finished ==="
