# Uninstall_ZTNA.ps1
# Silent uninstall for ZTNA (Zscaler Client Connector)

Write-Host "`n=== Checking ZTNA (Zscaler) for Uninstall ==="

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

$ZscalerPassword = 'Indian#2552#Z'

# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

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
                Where-Object {
                    $_.DisplayName -like "*Zscaler*"
                }
        }
        catch {
        }
    }

    return $entries
}


function Stop-ZscalerProcesses {

    Write-Host "`nStopping ZTNA processes..."

    $processes = @(
        "ZSAService",
        "ZSATray",
        "ZSATrayManager"
    )

    foreach ($p in $processes) {

        Get-Process -Name $p -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 2
}


function Find-ZscalerUninstaller {

    $possiblePaths = @(
        "$env:ProgramFiles\Zscaler\ZSAInstaller\uninstall.exe",
        "${env:ProgramFiles(x86)}\Zscaler\ZSAInstaller\uninstall.exe"
    )

    foreach ($path in $possiblePaths) {

        if (Test-Path $path) {
            return $path
        }
    }

    return $null
}


# ------------------------------------------------------------
# 1) Detect
# ------------------------------------------------------------

$ztnaEntries = @(Get-ZscalerUninstallEntries)

if ($ztnaEntries.Count -eq 0) {

    Write-Host "`nZTNA (Zscaler) is not installed. Nothing to uninstall."
    Write-Host "`n=== Script Finished ==="

    exit 0
}


# ------------------------------------------------------------
# 2) Stop Zscaler
# ------------------------------------------------------------

Stop-ZscalerProcesses


# ------------------------------------------------------------
# 3) Find official Zscaler uninstaller
# ------------------------------------------------------------

$uninstaller = Find-ZscalerUninstaller


if ($uninstaller) {

    Write-Host "`nFound Zscaler uninstaller:"
    Write-Host $uninstaller

    Write-Host "`nStarting silent Zscaler uninstall..."

    # Zscaler officially supports ZSCALER_PASSWORD
    # together with --mode unattended.
    [Environment]::SetEnvironmentVariable(
        'ZSCALER_PASSWORD',
        $ZscalerPassword,
        'Process'
    )

    try {

        $proc = Start-Process `
            -FilePath $uninstaller `
            -ArgumentList "--mode unattended" `
            -Wait `
            -PassThru `
            -WindowStyle Hidden

        Write-Host "`nUninstaller Exit Code: $($proc.ExitCode)"

        if ($proc.ExitCode -eq 0) {

            Write-Host "ZTNA (Zscaler) uninstalled successfully." `
                -ForegroundColor Green
        }
        else {

            Write-Host "ERROR: Zscaler uninstall failed." `
                -ForegroundColor Red

            Write-Host "Exit Code: $($proc.ExitCode)" `
                -ForegroundColor Red

            exit $proc.ExitCode
        }
    }
    finally {

        # Remove password from current process environment
        [Environment]::SetEnvironmentVariable(
            'ZSCALER_PASSWORD',
            $null,
            'Process'
        )
    }
}


# ------------------------------------------------------------
# 4) MSI fallback
# ------------------------------------------------------------

else {

    Write-Host "`nOfficial Zscaler uninstaller not found."
    Write-Host "Trying MSI uninstall..."


    foreach ($app in $ztnaEntries) {

        Write-Host "`nFound:"
        Write-Host "Name    : $($app.DisplayName)"
        Write-Host "Version : $($app.DisplayVersion)"


        if ($app.PSChildName -match '^\{.*\}$') {

            $productCode = $app.PSChildName

            Write-Host "`nUninstalling using ProductCode:"
            Write-Host $productCode


            $arguments = @(
                "/x"
                $productCode
                "/qn"
                "/norestart"
                "UNINSTALLPASSWORD=$ZscalerPassword"
            )


            $proc = Start-Process `
                -FilePath "msiexec.exe" `
                -ArgumentList $arguments `
                -Wait `
                -PassThru `
                -WindowStyle Hidden


            Write-Host "`nMSI Exit Code: $($proc.ExitCode)"


            if ($proc.ExitCode -eq 0) {

                Write-Host "ZTNA uninstalled successfully." `
                    -ForegroundColor Green
            }
            else {

                Write-Host "ERROR: Uninstall failed." `
                    -ForegroundColor Red

                Write-Host "Exit Code: $($proc.ExitCode)" `
                    -ForegroundColor Red

                exit $proc.ExitCode
            }
        }

        elseif ($app.UninstallString) {

            Write-Host "`nUsing fallback UninstallString..."

            $cmd = $app.UninstallString

            if ($cmd -notmatch "/qn") {
                $cmd += " /qn /norestart"
            }

            Start-Process `
                -FilePath "cmd.exe" `
                -ArgumentList "/c $cmd" `
                -Wait `
                -WindowStyle Hidden

            Write-Host "Uninstall command executed."
        }
    }
}


# ------------------------------------------------------------
# 5) Verify
# ------------------------------------------------------------

Start-Sleep -Seconds 3

$remaining = @(Get-ZscalerUninstallEntries)

if ($remaining.Count -eq 0) {

    Write-Host "`nVerification: Zscaler is no longer installed." `
        -ForegroundColor Green
}
else {

    Write-Host "`nWARNING: Zscaler still appears to be installed." `
        -ForegroundColor Yellow

    foreach ($item in $remaining) {
        Write-Host " - $($item.DisplayName)"
    }
}


Write-Host "`n=== Script Finished ==="