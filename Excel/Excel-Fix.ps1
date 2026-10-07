$Url  = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/Excel/excel-x-none_KB5002665.msp"
$File = Join-Path $env:TEMP "excel-x-none_KB5002665.msp"

Write-Output "=============================================="
Write-Output "Excel 2016 KB5002665 Installation"
Write-Output "=============================================="

# ============================================================
# Check and Close Excel
# ============================================================

Write-Output "Checking if Microsoft Excel is running..."

$ExcelProcess = Get-Process -Name "EXCEL" -ErrorAction SilentlyContinue

if ($ExcelProcess) {

    Write-Output "Microsoft Excel is running."
    Write-Output "Closing Excel forcefully..."

    $ExcelProcess | Stop-Process -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2

    $ExcelProcessCheck = Get-Process -Name "EXCEL" -ErrorAction SilentlyContinue

    if ($ExcelProcessCheck) {
        Write-Output "WARNING: Excel is still running."
    }
    else {
        Write-Output "Excel closed successfully."
    }

}
else {

    Write-Output "Microsoft Excel is not running."
}

# ============================================================
# Check for Office 2016 MSI-based installation
# ============================================================

Write-Output "Checking for Office 2016 MSI-based installation..."

$OfficeMSI = $false

$UninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($Path in $UninstallPaths) {

    $Apps = Get-ItemProperty $Path -ErrorAction SilentlyContinue

    foreach ($App in $Apps) {

        if (
            $App.DisplayName -match "Microsoft Office.*2016" -and
            $App.Publisher -match "Microsoft"
        ) {

            $OfficeMSI = $true

            Write-Output "Office 2016 MSI detected:"
            Write-Output $App.DisplayName

            break
        }
    }

    if ($OfficeMSI) {
        break
    }
}

# ============================================================
# Check Click-to-Run
# ============================================================

$C2RPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

if (Test-Path $C2RPath) {

    Write-Output "Microsoft Office Click-to-Run installation detected."
    Write-Output "Click-to-Run installation is not supported by this script."

    $OfficeMSI = $false
}

# ============================================================
# Stop if Office 2016 MSI is not found
# ============================================================

if (-not $OfficeMSI) {

    Write-Output "Office 2016 MSI-based installation not found."
    Write-Output "Nothing to install."
    Write-Output "Script completed."

}
else {

    Write-Output "Office 2016 MSI-based installation confirmed."

    # ========================================================
    # Download Excel 2016 KB5002665 MSI
    # ========================================================

    Write-Output "Downloading Excel 2016 KB5002665 MSI..."

    try {

        Invoke-WebRequest `
            -Uri $Url `
            -OutFile $File `
            -UseBasicParsing `
            -ErrorAction Stop

        Write-Output "Download completed: $File"

    }
    catch {

        Write-Output "Download failed: $($_.Exception.Message)"

    }

    # ========================================================
    # Verify downloaded MSI
    # ========================================================

    if (Test-Path $File) {

        Write-Output "MSI installer found."
        Write-Output "Starting Excel 2016 KB5002665 installation..."

        # ====================================================
        # Install MSI
        # /passive = Progress UI, no user interaction
        # /norestart = Do not restart automatically
        # ====================================================

        $Process = Start-Process `
            -FilePath "msiexec.exe" `
            -ArgumentList "/i `"$File`" /passive /norestart" `
            -Wait `
            -PassThru

        Write-Output "MSI installer exit code: $($Process.ExitCode)"

        # ====================================================
        # Installation Result
        # ====================================================

        if ($Process.ExitCode -eq 0) {

            Write-Output "Excel 2016 KB5002665 installed successfully."

        }
        elseif ($Process.ExitCode -eq 3010) {

            Write-Output "Excel 2016 KB5002665 installed successfully."
            Write-Output "Restart required."

        }
        elseif ($Process.ExitCode -eq 1641) {

            Write-Output "Excel 2016 KB5002665 installed successfully."
            Write-Output "Restart initiated by Windows Installer."

        }
        elseif ($Process.ExitCode -eq 1605) {

            Write-Output "The product is not installed on this system."

        }
        elseif ($Process.ExitCode -eq 1618) {

            Write-Output "Another MSI installation is already in progress."

        }
        else {

            Write-Output "Installation returned exit code: $($Process.ExitCode)"

        }

        # ====================================================
        # Cleanup
        # ====================================================

        Write-Output "Removing downloaded MSI..."

        Remove-Item $File -Force -ErrorAction SilentlyContinue

        Write-Output "Cleanup completed."

    }
    else {

        Write-Output "MSI installer was not downloaded."
        Write-Output "Installation skipped."
    }
}

# ============================================================
# ENABLE MICROSOFT OFFICE 2016 AUTOMATIC UPDATES
# Office 2016 MSI
# ============================================================

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate"

Write-Output "Checking Microsoft Office 2016 automatic update policy..."

if (Test-Path $RegPath) {

    Remove-ItemProperty `
        -Path $RegPath `
        -Name "EnableAutomaticUpdates" `
        -Force `
        -ErrorAction SilentlyContinue

    Write-Output "EnableAutomaticUpdates policy removed."

    # Check remaining policy values
    $Properties = Get-ItemProperty `
        -Path $RegPath `
        -ErrorAction SilentlyContinue

    if ($Properties) {

        $RemainingProperties = @(
            $Properties.PSObject.Properties |
            Where-Object {
                $_.Name -notmatch "^PS"
            }
        )

        if ($RemainingProperties.Count -eq 0) {

            Remove-Item `
                -Path $RegPath `
                -Force `
                -ErrorAction SilentlyContinue

            Write-Output "OfficeUpdate policy key removed."
        }
    }

}
else {

    Write-Output "Office automatic update blocking policy not found."
}

Write-Output "Microsoft Office 2016 automatic updates: ENABLED / NOT BLOCKED"

Write-Output "=============================================="
Write-Output "Script execution completed."
Write-Output "=============================================="