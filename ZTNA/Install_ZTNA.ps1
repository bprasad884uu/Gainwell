# Install_ZTNA.ps1
# Install ZTNA
# Author: Bishnu's Helper
# ManageEngine UEMS compatible - runs SYSTEM context, non-interactive

$DidInstall      = $false
$downloadSuccess = $false
$skipRest        = $false
$exitCode        = 0

Write-Output "=== Checking and Installing ZTNA (Zscaler) ==="

$destination = "$env:TEMP\Zscaler-windows-installer-x64.msi"
$ZTNA_setup  = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/ZTNA/Zscaler-windows-4.9.0.465-installer-x64.msi"
$ZTNA_TargetVersion = "4.9.0.465"

# -------- Functions --------
function Format-Size {
    param ([long]$bytes)
    switch ($bytes) {
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($bytes / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($bytes / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($bytes / 1KB) }
        default        { return "$bytes B" }
    }
}
function Get-ZTNAInstalledInfo {
    $entries = @()
    $entries += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Where-Object { $_.DisplayName -like "*Zscaler*" }
    $entries += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Where-Object { $_.DisplayName -like "*Zscaler*" }
    $entries += Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Where-Object { $_.DisplayName -like "*Zscaler*" }

    if ($entries -and $entries.Count -gt 0) {
        return [PSCustomObject]@{
            Installed = $true
            Version   = $entries[0].DisplayVersion
        }
    } else {
        return [PSCustomObject]@{
            Installed = $false
            Version   = $null
        }
    }
}

# -------- 1) Check first --------
$installInfo = Get-ZTNAInstalledInfo

if (-not $installInfo.Installed) {

    Write-Output "Zscaler is NOT installed."
    Write-Output "Zscaler installation is not required."
    Write-Output "Skipping installation/update."

    # Cleanup any leftover installer
    if (Test-Path $destination) {
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
        Write-Output "Cleaned up leftover installer: $destination"
    }

    # Skip download/install
    $skipRest = $true
}
elseif ($installInfo.Version -eq $ZTNA_TargetVersion) {

    Write-Output "Zscaler version $($installInfo.Version) is already installed."
    Write-Output "No update required."

    # Cleanup any leftover installer
    if (Test-Path $destination) {
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
        Write-Output "Cleaned up leftover installer: $destination"
    }

    # Skip download/install
    $skipRest = $true
}
else {

    Write-Output "Zscaler is installed."
    Write-Output "Installed Version : $($installInfo.Version)"
    Write-Output "Target Version    : $ZTNA_TargetVersion"
    Write-Output "Proceeding with UPDATE."
}

# -------- 2) Download & Install --------
if (-not $skipRest) {

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {}

    if (Test-Path $destination) {
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
    }

    if (-not ("System.Net.Http.HttpClient" -as [type])) {
        Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
    }

    $httpClientHandler = New-Object System.Net.Http.HttpClientHandler
    $httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

    Write-Output "Starting download..."

    try {

        $response = $httpClient.GetAsync(
            $ZTNA_setup,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).Result

        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {

            Write-Output "ERROR: HttpClient request failed: $($response.StatusCode) ($($response.ReasonPhrase))"

            $skipRest = $true
            $exitCode = 1
        }

        if (-not $skipRest) {

            $stream = $response.Content.ReadAsStreamAsync().Result

            if (-not $stream) {

                Write-Output "ERROR: Failed to retrieve response stream."

                $skipRest = $true
                $exitCode = 1
            }
        }

        if (-not $skipRest) {

            $totalSize = $response.Content.Headers.ContentLength

            if ($null -eq $totalSize) {
                Write-Output "Warning: Server did not return file size."
            }

            $fileStream = [System.IO.File]::OpenWrite($destination)

            $bufferSize = 10MB
            $buffer = New-Object byte[] ($bufferSize)
            $downloaded = 0
            $lastLoggedPercent = -10

            Write-Output "Downloading Zscaler Setup..."

            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {

                $fileStream.Write($buffer, 0, $bytesRead)
                $downloaded += $bytesRead

                if ($totalSize) {

                    $progress = [math]::Round(
                        ($downloaded / $totalSize) * 100,
                        0
                    )

                    if ($progress -ge ($lastLoggedPercent + 10)) {

                        Write-Output "Progress: $progress% | Downloaded: $(Format-Size $downloaded) / $(Format-Size $totalSize)"

                        $lastLoggedPercent = $progress
                    }
                }
            }

            $fileStream.Close()
            $stream.Close()

            Write-Output "Download Complete: $destination"

            $downloadSuccess = $true
        }

        $httpClient.Dispose()
    }
    catch {

        try {
            $httpClient.Dispose()
        }
        catch {}

        Write-Output "ERROR: Failed to download Zscaler installer. $_"

        $skipRest = $true
        $exitCode = 1
    }

    # -------- 3) Install / Update --------
    if ($downloadSuccess -and -not $skipRest) {

        Write-Output "Force updating Zscaler..."
        Write-Output "Installed Version : $($installInfo.Version)"
        Write-Output "Target Version    : $ZTNA_TargetVersion"

        $proc = Start-Process `
            "msiexec.exe" `
            -ArgumentList "/i `"$destination`" /qn /norestart" `
            -Wait `
            -PassThru

        if ($proc.ExitCode -eq 0) {

            Write-Output "Zscaler update completed successfully."
            $DidInstall = $true
        }
        elseif ($proc.ExitCode -eq 3010) {

            Write-Output "Zscaler update completed successfully."
            Write-Output "MSI requested reboot (3010), but reboot was suppressed."

            $DidInstall = $true
        }
        else {

            Write-Output "ERROR: Zscaler MSI update failed with exit code $($proc.ExitCode)."
            $exitCode = $proc.ExitCode
        }
    }

    # -------- 4) Post-update --------
    if ($DidInstall) {

        Write-Output "Zscaler update was successful."
        Write-Output "Stopping Zscaler processes..."

        $ProcessesToKill = @(
            "ZSAService",
            "ZSATray",
            "ZSATrayManager"
        )

        foreach ($p in $ProcessesToKill) {

            Get-Process -Name $p -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
        }

        Write-Output "Zscaler processes stopped."
        Write-Output "They will start again on next system boot or user login."
    }
    else {

        Write-Output "No Zscaler update performed."
    }

    # -------- 5) Always Cleanup --------
    if (Test-Path $destination) {

        Remove-Item $destination -Force -ErrorAction SilentlyContinue

        Write-Output "Installer removed: $destination"
    }
}

Write-Output "=== Script Finished ==="
