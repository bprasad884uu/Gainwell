$Url  = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/Excel/excel-x-none_KB5002665.msp"
$File = Join-Path $env:TEMP "excel-x-none_KB5002665.msp"

Write-Output "=============================================="
Write-Output "Excel 2016 KB5002665 Installation"
Write-Output "=============================================="

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
    # Check and Close Excel
    # ========================================================

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

    # ========================================================
    # Download Excel 2016 KB5002665 MSP
    # ========================================================

    Write-Output "Downloading Excel 2016 KB5002665 MSP..."

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
    # Verify downloaded MSP
    # ========================================================

    if (Test-Path $File) {

        $FileSize = (Get-Item $File).Length

        Write-Output "MSP installer found."
        Write-Output "File size: $([math]::Round($FileSize / 1MB, 2)) MB"

        # ====================================================
        # Install MSP Patch
        # ====================================================

        Write-Output "Starting Excel 2016 KB5002665 installation..."

        $Process = Start-Process `
            -FilePath "msiexec.exe" `
            -ArgumentList "/update `"$File`" /passive /norestart" `
            -Wait `
            -PassThru

        Write-Output "MSP installer exit code: $($Process.ExitCode)"

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
        elseif ($Process.ExitCode -eq 1603) {

            Write-Output "Installation failed with error 1603."

        }
        elseif ($Process.ExitCode -eq 1618) {

            Write-Output "Another MSI installation is already in progress."

        }
        elseif ($Process.ExitCode -eq 1642) {

            Write-Output "This update is not applicable to this system."

        }
        else {

            Write-Output "Installation returned exit code: $($Process.ExitCode)"

        }

        # ====================================================
        # Cleanup
        # ====================================================

        Write-Output "Removing downloaded MSP..."

        Remove-Item $File -Force -ErrorAction SilentlyContinue

        Write-Output "Cleanup completed."

    }
    else {

        Write-Output "MSP installer was not downloaded."
        Write-Output "Installation skipped."
    }

    # ========================================================
    # ENABLE MICROSOFT OFFICE 2016 AUTOMATIC UPDATES
    # ========================================================

    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate"

    Write-Output "Checking Microsoft Office 2016 automatic update policy..."

    if (Test-Path $RegPath) {

        $UpdatePolicy = Get-ItemProperty `
            -Path $RegPath `
            -Name "EnableAutomaticUpdates" `
            -ErrorAction SilentlyContinue

        if ($null -ne $UpdatePolicy) {

            Remove-ItemProperty `
                -Path $RegPath `
                -Name "EnableAutomaticUpdates" `
                -Force `
                -ErrorAction SilentlyContinue

            Write-Output "EnableAutomaticUpdates policy removed."
            Write-Output "Microsoft Office 2016 automatic updates: ENABLED / NOT BLOCKED"

        }
        else {

            Write-Output "Automatic update blocking policy not present."
        }

    }
    else {

        Write-Output "Office automatic update blocking policy not found."
        Write-Output "Microsoft Office 2016 automatic updates: NOT BLOCKED"
    }
}

Write-Output "=============================================="
Write-Output "Script execution completed."
Write-Output "=============================================="