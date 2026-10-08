#requires -version 5.1

<#
.SYNOPSIS
    Install Microsoft Excel 2016 KB5002665 MSP update.

.DESCRIPTION
    - Detects Office 2016 MSI-based installation
    - Excludes Click-to-Run installations
    - Checks whether KB5002665 is already installed
    - Downloads MSP using multiple fallback methods
    - Validates downloaded file
    - Force closes Excel if running (just before install)
    - Installs MSP silently
    - Cleans up downloaded file
    - Removes Office automatic update blocking policy
    - Designed for ManageEngine Endpoint Central / UEMS SYSTEM context
    - Does NOT use exit statements

.AUTHOR
    Bishnu's Helper

.NOTES
    Target:
        Microsoft Office 2016 MSI
        Excel 2016 KB5002665

    ManageEngine:
        SYSTEM context
        Non-interactive
        No Task Scheduler
        No forced script termination
#>

# ============================================================
# INITIALIZATION
# ============================================================

$ErrorActionPreference = "Continue"

$KBNumber = "KB5002665"

# Direct raw.githubusercontent.com URL avoids GitHub redirect
$Url = "https://raw.githubusercontent.com/bprasad884uu/Gainwell/main/Excel/excel-x-none_KB5002665.msp"

$TempFolder = Join-Path $env:TEMP "Excel-KB5002665"

$File = Join-Path `
    $TempFolder `
    "excel-x-none_KB5002665.msp"

$MinimumFileSize = 1MB

$InstallationAttempted = $false
$InstallationSuccess  = $false
$DownloadSuccess      = $false
$AlreadyInstalled     = $false

# ============================================================
# HEADER
# ============================================================

Write-Output ""
Write-Output "=============================================="
Write-Output "Excel 2016 $KBNumber Installation"
Write-Output "=============================================="
Write-Output "Computer Name : $env:COMPUTERNAME"
Write-Output "User Context  : $env:USERNAME"
Write-Output "PowerShell    : $($PSVersionTable.PSVersion)"
Write-Output "Architecture  : $env:PROCESSOR_ARCHITECTURE"
Write-Output "=============================================="
Write-Output ""

# ============================================================
# TLS 1.2
# ============================================================

Write-Output "Configuring TLS 1.2..."

try {

    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12

    Write-Output "TLS 1.2 configured successfully."

}
catch {

    Write-Output "WARNING: Unable to explicitly configure TLS 1.2."
    Write-Output "Error: $($_.Exception.Message)"
}

# ============================================================
# CREATE TEMP DIRECTORY
# ============================================================

if (-not (Test-Path $TempFolder)) {

    try {

        New-Item `
            -Path $TempFolder `
            -ItemType Directory `
            -Force `
            -ErrorAction Stop | Out-Null

        Write-Output "Temporary folder created:"
        Write-Output "$TempFolder"

    }
    catch {

        Write-Output "WARNING: Unable to create temporary folder."
        Write-Output "Error: $($_.Exception.Message)"

        $TempFolder = $env:TEMP

        $File = Join-Path `
            $TempFolder `
            "excel-x-none_KB5002665.msp"

        Write-Output "Using system TEMP folder instead:"
        Write-Output "$TempFolder"
    }

}
else {

    Write-Output "Temporary folder already exists:"
    Write-Output "$TempFolder"
}

# ============================================================
# OFFICE 2016 MSI DETECTION
# ============================================================

Write-Output ""
Write-Output "=============================================="
Write-Output "Checking for Office 2016 MSI-based installation"
Write-Output "=============================================="

$OfficeMSI = $false
$OfficeProductName = $null

$UninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($Path in $UninstallPaths) {

    try {

        $Apps = Get-ItemProperty `
            -Path $Path `
            -ErrorAction SilentlyContinue

        foreach ($App in $Apps) {

            if ([string]::IsNullOrWhiteSpace($App.DisplayName)) {
                continue
            }

            $DisplayName = [string]$App.DisplayName
            $Publisher   = [string]$App.Publisher

            # Office 2016 MSI products
            if (
                $DisplayName -match "^Microsoft Office .*2016" -and
                $Publisher -match "Microsoft"
            ) {

                # Exclude Click-to-Run entries
                if (
                    $DisplayName -notmatch "Click-to-Run" -and
                    $DisplayName -notmatch "Office 365"
                ) {

                    $OfficeMSI = $true
                    $OfficeProductName = $DisplayName

                    Write-Output "Office 2016 MSI detected:"
                    Write-Output "Product: $DisplayName"

                    break
                }
            }
        }

    }
    catch {

        Write-Output "WARNING: Error while checking registry path:"
        Write-Output "$Path"
        Write-Output "Error: $($_.Exception.Message)"
    }

    if ($OfficeMSI) {
        break
    }
}

# ============================================================
# CLICK-TO-RUN DETECTION
# ============================================================

$C2RPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration"
)

$ClickToRunDetected = $false

foreach ($C2RPath in $C2RPaths) {

    if (Test-Path $C2RPath) {

        $ClickToRunDetected = $true

        Write-Output ""
        Write-Output "Microsoft Office Click-to-Run installation detected."
        Write-Output "Click-to-Run installation is NOT supported by this script."

        break
    }
}

if ($ClickToRunDetected) {

    $OfficeMSI = $false
}

# ============================================================
# OFFICE NOT FOUND
# ============================================================

if (-not $OfficeMSI) {

    Write-Output ""
    Write-Output "Office 2016 MSI-based installation not found."
    Write-Output "Nothing to install."

}
else {

    Write-Output ""
    Write-Output "Office 2016 MSI-based installation confirmed."
    Write-Output "Product: $OfficeProductName"

    # ========================================================
    # CHECK KB5002665 ALREADY INSTALLED
    # ========================================================

    Write-Output ""
    Write-Output "=============================================="
    Write-Output "Checking whether $KBNumber is already installed"
    Write-Output "=============================================="

    $KBInstalled = $false

    # --------------------------------------------------------
    # Method 1 - Registry uninstall entries
    # --------------------------------------------------------

    foreach ($Path in $UninstallPaths) {

        try {

            $Updates = Get-ItemProperty `
                -Path $Path `
                -ErrorAction SilentlyContinue

            foreach ($Update in $Updates) {

                if (
                    $Update.DisplayName -and
                    $Update.DisplayName -match $KBNumber
                ) {

                    $KBInstalled = $true

                    Write-Output "$KBNumber detected in installed updates."
                    Write-Output "Update: $($Update.DisplayName)"

                    break
                }
            }

        }
        catch {
        }

        if ($KBInstalled) {
            break
        }
    }

    # --------------------------------------------------------
    # Method 2 - Office update registry locations
    # --------------------------------------------------------

    if (-not $KBInstalled) {

        $OfficeUpdatePaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        foreach ($BasePath in $OfficeUpdatePaths) {

            try {

                $SubKeys = Get-ChildItem `
                    -Path $BasePath `
                    -ErrorAction SilentlyContinue

                foreach ($SubKey in $SubKeys) {

                    try {

                        $Properties = Get-ItemProperty `
                            -Path $SubKey.PSPath `
                            -ErrorAction SilentlyContinue

                        $CombinedText = @(
                            $Properties.DisplayName
                            $Properties.DisplayVersion
                            $Properties.InstallLocation
                            $SubKey.PSChildName
                        ) -join " "

                        if ($CombinedText -match $KBNumber) {

                            $KBInstalled = $true

                            Write-Output "$KBNumber detected in Office update registry."

                            break
                        }

                    }
                    catch {
                    }
                }

            }
            catch {
            }

            if ($KBInstalled) {
                break
            }
        }
    }

    # --------------------------------------------------------
    # Already Installed
    # --------------------------------------------------------

    if ($KBInstalled) {

        $AlreadyInstalled = $true

        Write-Output ""
        Write-Output "$KBNumber is already installed."
        Write-Output "Installation is not required."

    }
    else {

        Write-Output "$KBNumber is NOT currently detected."
        Write-Output "Installation is required."

        # ====================================================
        # REMOVE OLD MSP
        # ====================================================

        if (Test-Path $File) {

            Write-Output ""
            Write-Output "Removing previous MSP file..."

            try {

                Remove-Item `
                    -Path $File `
                    -Force `
                    -ErrorAction Stop

                Write-Output "Previous MSP removed."

            }
            catch {

                Write-Output "WARNING: Unable to remove previous MSP."
                Write-Output "Error: $($_.Exception.Message)"
            }
        }

        # ====================================================
        # DOWNLOAD
        # ====================================================

        Write-Output ""
        Write-Output "=============================================="
        Write-Output "Downloading Excel 2016 $KBNumber MSP"
        Write-Output "=============================================="

        Write-Output "Download URL:"
        Write-Output $Url

        $DownloadSuccess = $false

        # ====================================================
        # DOWNLOAD METHOD 1 - BITS
        # ====================================================

        Write-Output ""
        Write-Output "Download Method 1: BITS"

        try {

            $BitsAvailable = $null

            try {

                $BitsAvailable = Get-Command `
                    Start-BitsTransfer `
                    -ErrorAction SilentlyContinue

            }
            catch {
            }

            if ($BitsAvailable) {

                Write-Output "BITS service/cmdlet available."
                Write-Output "Starting BITS download..."

                Start-BitsTransfer `
                    -Source $Url `
                    -Destination $File `
                    -DisplayName "Excel 2016 $KBNumber" `
                    -Description "Downloading Excel 2016 $KBNumber MSP" `
                    -RetryInterval 15 `
                    -ErrorAction Stop

                if (Test-Path $File) {

                    $FileSize = (Get-Item $File).Length

                    if ($FileSize -ge $MinimumFileSize) {

                        Write-Output "BITS download completed."
                        Write-Output "Downloaded size: $([math]::Round($FileSize / 1MB, 2)) MB"

                        $DownloadSuccess = $true

                    }
                    else {

                        Write-Output "BITS downloaded file is too small."
                        Write-Output "Size: $FileSize bytes"

                        Remove-Item `
                            -Path $File `
                            -Force `
                            -ErrorAction SilentlyContinue
                    }
                }

            }
            else {

                Write-Output "BITS cmdlet is not available."
            }

        }
        catch {

            Write-Output "BITS download failed."
            Write-Output "Error: $($_.Exception.Message)"

            if (Test-Path $File) {

                Remove-Item `
                    -Path $File `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }

        # ====================================================
        # DOWNLOAD METHOD 2 - CURL
        # ====================================================

        if (-not $DownloadSuccess) {

            Write-Output ""
            Write-Output "Download Method 2: curl.exe"

            $CurlPath = Join-Path `
                $env:SystemRoot `
                "System32\curl.exe"

            if (Test-Path $CurlPath) {

                Write-Output "curl.exe found:"
                Write-Output $CurlPath

                if (Test-Path $File) {

                    Remove-Item `
                        -Path $File `
                        -Force `
                        -ErrorAction SilentlyContinue
                }

                try {

                    Write-Output "Starting curl.exe download..."

                    & $CurlPath `
                        --fail `
                        --location `
                        --tlsv1.2 `
                        --retry 3 `
                        --retry-delay 5 `
                        --connect-timeout 30 `
                        --max-time 900 `
                        --silent `
                        --show-error `
                        --output $File `
                        $Url

                    $CurlExitCode = $LASTEXITCODE

                    Write-Output "curl.exe exit code: $CurlExitCode"

                    if (
                        $CurlExitCode -eq 0 -and
                        (Test-Path $File)
                    ) {

                        $FileSize = (Get-Item $File).Length

                        if ($FileSize -ge $MinimumFileSize) {

                            Write-Output "curl.exe download completed."
                            Write-Output "Downloaded size: $([math]::Round($FileSize / 1MB, 2)) MB"

                            $DownloadSuccess = $true

                        }
                        else {

                            Write-Output "curl.exe downloaded file is too small."
                            Write-Output "Size: $FileSize bytes"

                            Remove-Item `
                                -Path $File `
                                -Force `
                                -ErrorAction SilentlyContinue
                        }
                    }

                }
                catch {

                    Write-Output "curl.exe download failed."
                    Write-Output "Error: $($_.Exception.Message)"
                }

            }
            else {

                Write-Output "curl.exe was not found."
            }
        }

        # ====================================================
        # DOWNLOAD METHOD 3 - INVOKE-WEBREQUEST
        # ====================================================

        if (-not $DownloadSuccess) {

            Write-Output ""
            Write-Output "Download Method 3: Invoke-WebRequest"

            if (Test-Path $File) {

                Remove-Item `
                    -Path $File `
                    -Force `
                    -ErrorAction SilentlyContinue
            }

            try {

                [Net.ServicePointManager]::SecurityProtocol = `
                    [Net.SecurityProtocolType]::Tls12

                Write-Output "Starting Invoke-WebRequest..."

                Invoke-WebRequest `
                    -Uri $Url `
                    -OutFile $File `
                    -UseBasicParsing `
                    -Headers @{
                        "User-Agent" = "Mozilla/5.0"
                    } `
                    -ErrorAction Stop

                if (Test-Path $File) {

                    $FileSize = (Get-Item $File).Length

                    if ($FileSize -ge $MinimumFileSize) {

                        Write-Output "Invoke-WebRequest download completed."
                        Write-Output "Downloaded size: $([math]::Round($FileSize / 1MB, 2)) MB"

                        $DownloadSuccess = $true

                    }
                    else {

                        Write-Output "Downloaded file is too small."
                        Write-Output "Size: $FileSize bytes"

                        Remove-Item `
                            -Path $File `
                            -Force `
                            -ErrorAction SilentlyContinue
                    }
                }

            }
            catch {

                Write-Output "Invoke-WebRequest download failed."
                Write-Output "Error: $($_.Exception.Message)"
            }
        }

        # ====================================================
        # VERIFY DOWNLOAD
        # ====================================================

        Write-Output ""
        Write-Output "=============================================="
        Write-Output "MSP Download Verification"
        Write-Output "=============================================="

        if ($DownloadSuccess -and (Test-Path $File)) {

            $FileSize = (Get-Item $File).Length

            Write-Output "MSP file exists."
            Write-Output "Path: $File"
            Write-Output "Size: $([math]::Round($FileSize / 1MB, 2)) MB"

            # ------------------------------------------------
            # Authenticode signature verification
            # ------------------------------------------------

            Write-Output ""
            Write-Output "Checking MSP digital signature..."

            try {

                $Signature = Get-AuthenticodeSignature `
                    -FilePath $File `
                    -ErrorAction Stop

                Write-Output "Signature Status: $($Signature.Status)"

                if ($Signature.SignerCertificate) {

                    Write-Output "Signer:"
                    Write-Output $Signature.SignerCertificate.Subject
                }

                if ($Signature.Status -eq "Valid") {

                    Write-Output "Digital signature is valid."

                }
                else {

                    Write-Output "WARNING: Digital signature status is not Valid."
                    Write-Output "Continuing with installation because the file was downloaded from the configured repository."
                }

            }
            catch {

                Write-Output "WARNING: Unable to verify digital signature."
                Write-Output "Error: $($_.Exception.Message)"
            }

            # ------------------------------------------------
            # SHA-256
            # ------------------------------------------------

            Write-Output ""
            Write-Output "Calculating SHA-256 hash..."

            try {

                $Hash = Get-FileHash `
                    -Path $File `
                    -Algorithm SHA256 `
                    -ErrorAction Stop

                Write-Output "SHA-256:"
                Write-Output $Hash.Hash

            }
            catch {

                Write-Output "WARNING: Unable to calculate SHA-256."
                Write-Output "Error: $($_.Exception.Message)"
            }

            # ====================================================
            # CLOSE EXCEL BEFORE INSTALL
            # ====================================================

            Write-Output ""
            Write-Output "=============================================="
            Write-Output "Checking if Microsoft Excel is running"
            Write-Output "=============================================="

            $ExcelProcess = Get-Process `
                -Name "EXCEL" `
                -ErrorAction SilentlyContinue

            if ($ExcelProcess) {

                Write-Output "Microsoft Excel is running."

                Write-Output "Closing Excel forcefully..."

                try {

                    $ExcelProcess |
                        Stop-Process `
                            -Force `
                            -ErrorAction SilentlyContinue

                }
                catch {

                    Write-Output "WARNING: Unable to close Excel cleanly."
                    Write-Output "Error: $($_.Exception.Message)"
                }

                Start-Sleep -Seconds 3

                $ExcelProcessCheck = Get-Process `
                    -Name "EXCEL" `
                    -ErrorAction SilentlyContinue

                if ($ExcelProcessCheck) {

                    Write-Output "WARNING: Excel is still running."
                    Write-Output "MSP installation may fail."

                }
                else {

                    Write-Output "Excel closed successfully."
                }

            }
            else {

                Write-Output "Microsoft Excel is not running."
            }

            # =================================================
            # INSTALL MSP
            # =================================================

            Write-Output ""
            Write-Output "=============================================="
            Write-Output "Installing Excel 2016 $KBNumber"
            Write-Output "=============================================="

            $InstallationAttempted = $true

            try {

                $Arguments = @(
                    "/update"
                    "`"$File`""
                    "/passive"
                    "/norestart"
                )

                Write-Output "Starting Windows Installer..."

                $Process = Start-Process `
                    -FilePath "msiexec.exe" `
                    -ArgumentList $Arguments `
                    -Wait `
                    -PassThru `
                    -WindowStyle Hidden

                $InstallExitCode = $Process.ExitCode

                Write-Output ""
                Write-Output "MSP installer exit code: $InstallExitCode"

                # =================================================
                # INSTALLATION RESULT
                # =================================================

                switch ($InstallExitCode) {

                    0 {

                        Write-Output ""
                        Write-Output "SUCCESS: $KBNumber installed successfully."

                        $InstallationSuccess = $true
                    }

                    3010 {

                        Write-Output ""
                        Write-Output "SUCCESS: $KBNumber installed successfully."
                        Write-Output "A restart is required."

                        $InstallationSuccess = $true
                    }

                    1641 {

                        Write-Output ""
                        Write-Output "SUCCESS: $KBNumber installed successfully."
                        Write-Output "Windows Installer requested a restart."

                        $InstallationSuccess = $true
                    }

                    1603 {

                        Write-Output ""
                        Write-Output "ERROR: Installation failed with MSI error 1603."
                        Write-Output "This is a generic MSI installation failure."
                    }

                    1618 {

                        Write-Output ""
                        Write-Output "ERROR: Another MSI installation is already in progress."
                        Write-Output "Please retry after the existing installation completes."
                    }

                    1642 {

                        Write-Output ""
                        Write-Output "ERROR: This update is not applicable to this system."
                        Write-Output "Possible causes:"
                        Write-Output "- Incorrect Office edition"
                        Write-Output "- Required prerequisite missing"
                        Write-Output "- Update already superseded"
                    }

                    17025 {

                        Write-Output ""
                        Write-Output "ERROR: MSP update cannot be applied to the installed Office product."
                    }

                    default {

                        Write-Output ""
                        Write-Output "ERROR: Installation returned exit code $InstallExitCode"
                    }
                }

            }
            catch {

                Write-Output ""
                Write-Output "ERROR: Unable to start Windows Installer."
                Write-Output "Error: $($_.Exception.Message)"
            }

        }
        else {

            Write-Output ""
            Write-Output "=============================================="
            Write-Output "MSP DOWNLOAD FAILED"
            Write-Output "=============================================="

            Write-Output "The MSP installer was not downloaded successfully."
            Write-Output "Installation skipped."
        }

        # ====================================================
        # CLEANUP
        # ====================================================

        Write-Output ""
        Write-Output "=============================================="
        Write-Output "Cleanup"
        Write-Output "=============================================="

        if (Test-Path $File) {

            try {

                Remove-Item `
                    -Path $File `
                    -Force `
                    -ErrorAction Stop

                Write-Output "Downloaded MSP removed."

            }
            catch {

                Write-Output "WARNING: Unable to remove MSP."
                Write-Output "File: $File"
                Write-Output "Error: $($_.Exception.Message)"
            }

        }
        else {

            Write-Output "No MSP file to clean up."
        }
    }

    # ========================================================
    # OFFICE AUTOMATIC UPDATE POLICY
    # ========================================================

    Write-Output ""
    Write-Output "=============================================="
    Write-Output "Checking Microsoft Office 2016 Automatic Update Policy"
    Write-Output "=============================================="

    $RegPath = `
        "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate"

    if (Test-Path $RegPath) {

        Write-Output "Office update policy registry path found."

        $UpdatePolicy = Get-ItemProperty `
            -Path $RegPath `
            -ErrorAction SilentlyContinue

        if ($null -ne $UpdatePolicy) {

            if (
                $UpdatePolicy.PSObject.Properties.Name `
                -contains "EnableAutomaticUpdates"
            ) {

                $CurrentValue = `
                    $UpdatePolicy.EnableAutomaticUpdates

                Write-Output "EnableAutomaticUpdates value: $CurrentValue"

                if ($CurrentValue -eq 0) {

                    Write-Output "Automatic updates are currently BLOCKED."

                    try {

                        Remove-ItemProperty `
                            -Path $RegPath `
                            -Name "EnableAutomaticUpdates" `
                            -Force `
                            -ErrorAction Stop

                        Write-Output "EnableAutomaticUpdates policy removed."
                        Write-Output "Microsoft Office 2016 automatic updates: NOT BLOCKED"

                    }
                    catch {

                        Write-Output "WARNING: Unable to remove update policy."
                        Write-Output "Error: $($_.Exception.Message)"
                    }

                }
                else {

                    Write-Output "Automatic update policy is not blocking updates."
                    Write-Output "Microsoft Office 2016 automatic updates: NOT BLOCKED"
                }

            }
            else {

                Write-Output "EnableAutomaticUpdates policy value not present."
                Write-Output "Microsoft Office 2016 automatic updates: NOT BLOCKED"
            }

        }
        else {

            Write-Output "Office update policy exists but could not be read."
        }

    }
    else {

        Write-Output "Office automatic update blocking policy not found."
        Write-Output "Microsoft Office 2016 automatic updates: NOT BLOCKED"
    }
}

# ============================================================
# FINAL STATUS
# ============================================================

Write-Output ""
Write-Output "=============================================="
Write-Output "FINAL STATUS"
Write-Output "=============================================="

if (-not $OfficeMSI) {

    Write-Output "Status: NOT APPLICABLE"
    Write-Output "Reason: Office 2016 MSI installation not detected."

}
elseif ($AlreadyInstalled) {

    Write-Output "Status: ALREADY INSTALLED"
    Write-Output "$KBNumber is already installed."

}
elseif ($InstallationSuccess) {

    Write-Output "Status: SUCCESS"
    Write-Output "$KBNumber installation completed successfully."

}
elseif ($InstallationAttempted) {

    Write-Output "Status: INSTALLATION FAILED"
    Write-Output "$KBNumber installation was attempted but did not complete successfully."

}
elseif (-not $DownloadSuccess) {

    Write-Output "Status: DOWNLOAD FAILED"
    Write-Output "$KBNumber MSP could not be downloaded."

}
else {

    Write-Output "Status: COMPLETED"
}

Write-Output ""
Write-Output "=============================================="
Write-Output "Script execution completed."
Write-Output "=============================================="
Write-Output ""

# IMPORTANT:
# No 'exit' command is used.
# This allows ManageEngine/UEMS to complete the PowerShell session normally.