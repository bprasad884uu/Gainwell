# Uninstall_ZTNA.ps1
# Silent uninstall for ZTNA (Zscaler Client Connector)
# Author: Bishnu's Helper

Write-Host "`n=== Checking ZTNA (Zscaler) for Uninstall ==="

# ---------------- Functions ----------------
function Get-ZscalerUninstallEntries {
    $entries = @()

    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        try {
            $entries += Get-ItemProperty $path -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -like "*Zscaler*" }
        } catch {}
    }

    return $entries
}

function Stop-ZscalerProcesses {
    Write-Host "`nStopping ZTNA processes..."
    $processes = @("ZSAService", "ZSATray", "ZSATrayManager")
    foreach ($p in $processes) {
        Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force
    }
}

# ---------------- 1) Detect ----------------
$ztnaEntries = Get-ZscalerUninstallEntries

if (-not $ztnaEntries -or $ztnaEntries.Count -eq 0) {
    Write-Host "`nZTNA (Zscaler) is not installed. Nothing to uninstall."
    Write-Host "`n=== Script Finished ==="
    exit 0
}

# ---------------- 2) Uninstall ----------------
foreach ($app in $ztnaEntries) {

    Write-Host "`nFound:"
    Write-Host "Name : $($app.DisplayName)"
    Write-Host "Version : $($app.DisplayVersion)"

    Stop-ZscalerProcesses

    if ($app.PSChildName -match '^\{.*\}$') {
        # MSI ProductCode based uninstall
        $productCode = $app.PSChildName
        Write-Host "`nUninstalling using ProductCode: $productCode"

        $proc = Start-Process "msiexec.exe" `
            -ArgumentList "/x $productCode /qn /norestart" `
            -Wait -PassThru

        if ($proc.ExitCode -eq 0) {
            Write-Host "ZTNA uninstalled successfully."
        } else {
            Write-Host "ERROR: Uninstall failed. Exit Code: $($proc.ExitCode)" -ForegroundColor Red
        }
    }
    elseif ($app.UninstallString) {
        # Fallback for non-standard uninstall strings
        Write-Host "`nUninstalling using UninstallString..."

        $cmd = $app.UninstallString
        if ($cmd -notmatch "/qn") {
            $cmd += " /qn /norestart"
        }

        Start-Process "cmd.exe" -ArgumentList "/c $cmd" -Wait
        Write-Host "ZTNA uninstall command executed."
    }
}

Write-Host "`n=== Script Finished ==="
