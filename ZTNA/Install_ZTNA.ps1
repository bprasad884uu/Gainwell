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

if ($installInfo.Installed -and $installInfo.Version -eq $ZTNA_TargetVersion) {
    Write-Output "ZTNA (Zscaler) version $($installInfo.Version) is already installed (matches target). Skipping download and installation."
    if (Test-Path $destination) {
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
        Write-Output "Cleaned up leftover installer: $destination"
    }
    $skipRest = $true
}
elseif ($installInfo.Installed) {
    Write-Output "ZTNA (Zscaler) is installed with version $($installInfo.Version), which differs from target version $ZTNA_TargetVersion. Proceeding with force install."
}
else {
    Write-Output "ZTNA (Zscaler) is not installed. Proceeding with installation."
}

# -------- 2) Download & Install (only if not skipped) --------
if (-not $skipRest) {

    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

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
        $response = $httpClient.GetAsync($ZTNA_setup, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

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
            $startTime = Get-Date
            $lastLoggedPercent = -10

            Write-Output "Downloading ZTNA Setup..."
            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fileStream.Write($buffer, 0, $bytesRead)
                $downloaded += $bytesRead

                if ($totalSize) {
                    $progress = [math]::Round(($downloaded / $totalSize) * 100, 0)
                    # Log every 10% instead of continuous progress line (UEMS log friendly)
                    if ($progress -ge ($lastLoggedPercent + 10)) {
                        Write-Output "Progress: $progress% | Downloaded: $(Format-Size $downloaded) / $(Format-Size $totalSize)"
                        $lastLoggedPercent = $progress
                    }
                }
            }

            $fileStream.Close()
            Write-Output "Download Complete: $destination"
            $downloadSuccess = $true
        }

        $httpClient.Dispose()
    }
    catch {
        try { $httpClient.Dispose() } catch {}
        Write-Output "ERROR: Failed to download ZTNA installer. $_"
        $skipRest = $true
        $exitCode = 1
    }

    if (-not $downloadSuccess -and -not $skipRest) {
        Write-Output "ERROR: All download methods failed. Please check your internet connection."
        $skipRest = $true
        $exitCode = 1
    }

    # -------- 3) Install silently --------
    if ($downloadSuccess -and -not $skipRest) {
        Write-Output "Installing ZTNA from: $destination"
        $proc = Start-Process "msiexec.exe" -ArgumentList "/i `"$destination`" /qn /norestart" -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Output "ZTNA installation completed."
            $DidInstall = $true
        } else {
            Write-Output "ERROR: MSI installation failed with exit code $($proc.ExitCode)."
            $exitCode = $proc.ExitCode
        }
    }

    # -------- 4) Post-install --------
    if ($DidInstall) {
        Write-Output "ZTNA (Zscaler) was installed."
        Write-Output "Stopping ZTNA processes..."
        $ProcessesToKill = @("ZSAService", "ZSATray", "ZSATrayManager")
        foreach ($p in $ProcessesToKill) {
            Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force
        }
        Write-Output "ZTNA processes stopped. They will start on next system boot or user login."
    } else {
        Write-Output "No ZTNA installation performed."
    }

    # -------- 5) Always Cleanup --------
    if (Test-Path $destination) {
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
        Write-Output "Installer removed: $destination"
    }
}

Write-Output "=== Script Finished ==="
exit $exitCode