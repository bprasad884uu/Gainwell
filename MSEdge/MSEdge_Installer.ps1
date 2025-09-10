<#
.SYNOPSIS
  Update Microsoft Edge from GitHub rolling release if machine is out-of-date.

.DESCRIPTION
  - Fetches GitHub release with tag "Edge" from repo bprasad884uu/Gainwell
  - Parses "Version: X.Y.Z.W" from the release body
  - Compares with installed Edge; downloads+installs MSI only if remote is newer (or Edge missing)
  - Optional: set env var GITHUB_TOKEN to a PAT to increase API limits
#>

# Config
$Owner = 'bprasad884uu'
$Repo  = 'Gainwell'
$ReleaseTag = 'Edge'
$assetFileName = 'MicrosoftEdgeEnterpriseX64.msi'
$tempMsi = Join-Path $env:TEMP $assetFileName
$githubApiUrl = "https://api.github.com/repos/$Owner/$Repo/releases/tags/$ReleaseTag"

# Options
$Force = $false   # set to $true to always download+install

function Get-InstalledEdgeVersion {
    # Return the first valid ProductVersion string found (scalar)
    $possible = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
        "$env:LocalAppData\Microsoft\Edge\Application\msedge.exe"
    ) | Get-Unique

    foreach ($p in $possible) {
        if (Test-Path $p) {
            try {
                $ver = (Get-Item $p -ErrorAction Stop).VersionInfo.ProductVersion
                if ($ver -and $ver.ToString().Trim() -ne '') { return $ver.ToString().Trim() }
            } catch {}
        }
    }

    # Registry fallback - return first match
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($rk in $regPaths) {
        try {
            $children = Get-ChildItem -Path $rk -ErrorAction SilentlyContinue
            foreach ($c in $children) {
                $props = Get-ItemProperty -Path $c.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -and $props.DisplayName -like '*Microsoft Edge*' -and $props.DisplayVersion) {
                    return $props.DisplayVersion.ToString().Trim()
                }
            }
        } catch {}
    }

    return $null
}

function Get-RemoteReleaseInfo {
    param([string]$ApiUrl)
    $headers = @{ 'User-Agent' = 'Edge-Updater-Script' }
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "token $($env:GITHUB_TOKEN)" }

    try {
        return Invoke-RestMethod -Uri $ApiUrl -Headers $headers -ErrorAction Stop
    } catch {
        Write-Error "Failed to query GitHub Releases API: $($_.Exception.Message)"
        return $null
    }
}

function Parse-VersionFromBody {
    param([string]$BodyText)
    if (-not $BodyText) { return $null }

    # Look for "Version: 140.0.3485.54"
    $m = [regex]::Match($BodyText, 'Version\s*:\s*([0-9]+(?:\.[0-9]+){1,})', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) { return $m.Groups[1].Value.Trim() }

    # Fallback: first long dotted number (3+ parts)
    $m2 = [regex]::Match($BodyText, '([0-9]+(?:\.[0-9]+){2,})')
    if ($m2.Success) { return $m2.Groups[1].Value.Trim() }
    return $null
}

function Get-MsiAssetDownloadUrl {
    param($releaseObj, $assetName)
    if (-not $releaseObj -or -not $releaseObj.assets) { return $null }
    foreach ($a in $releaseObj.assets) {
        if ($a.name -eq $assetName) { return $a.browser_download_url }
    }
    return $null
}

function Format-Size {
    param ([long]$bytes)
    switch ($bytes) {
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($bytes / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($bytes / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($bytes / 1KB) }
        default        { return "$bytes B" }
    }
}
function Format-Speed {
    param ([double]$bytesPerSecond)
    switch ($bytesPerSecond) {
        { $_ -ge 1GB } { return "{0:N2} GB/s" -f ($bytesPerSecond / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB/s" -f ($bytesPerSecond / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB/s" -f ($bytesPerSecond / 1KB) }
        default        { return "{0:N2} B/s" -f $bytesPerSecond }
    }
}

try {
    Write-Host "Checking local Microsoft Edge version..." -ForegroundColor Cyan
    $installed = Get-InstalledEdgeVersion
    if ($installed) {
        # ensure scalar string
        if ($installed -is [System.Array]) { $installed = ($installed | Where-Object { $_ } | Select-Object -First 1).ToString().Trim() }
        $installed = $installed.ToString().Trim()
        Write-Host "Installed Edge version: $installed" -ForegroundColor Green
    } else {
        Write-Host "Microsoft Edge not detected on this system." -ForegroundColor Yellow
    }

    Write-Host "Querying GitHub release '$ReleaseTag' from $Owner/$Repo ..." -ForegroundColor Cyan
    $release = Get-RemoteReleaseInfo -ApiUrl $githubApiUrl
    if (-not $release) { throw "Cannot get release info from GitHub." }

    # Parse version from release body or name
    $remoteVersion = Parse-VersionFromBody -BodyText $release.body
    if (-not $remoteVersion -and $release.name) { $remoteVersion = Parse-VersionFromBody -BodyText $release.name }
    if ($remoteVersion) {
        # normalize to scalar string
        if ($remoteVersion -is [System.Array]) { $remoteVersion = ($remoteVersion | Where-Object { $_ } | Select-Object -First 1).ToString().Trim() }
        $remoteVersion = $remoteVersion.ToString().Trim()
        Write-Host "Remote release version (parsed): $remoteVersion" -ForegroundColor Cyan
    } else {
        Write-Warning "Could not parse version from release body/name. Remote treated as unknown."
    }

    # Decide whether to download
    $needDownload = $false
    if ($Force) {
        Write-Host "Force flag set. Will download and install." -ForegroundColor Yellow
        $needDownload = $true
    } elseif (-not $installed) {
        Write-Host "Edge not installed. Will download and install." -ForegroundColor Cyan
        $needDownload = $true
    } elseif ($remoteVersion) {
        try {
            if ([version]$installed -lt [version]$remoteVersion) {
                Write-Host "Installed version is older than remote. Will download and install." -ForegroundColor Cyan
                $needDownload = $true
            } else {
                Write-Host "Installed version ($installed) is >= remote version ($remoteVersion). No action needed." -ForegroundColor Green
                $needDownload = $false
            }
        } catch {
            Write-Warning "Version compare failed: $($_.Exception.Message). Will download by default."
            $needDownload = $true
        }
    } else {
        Write-Warning "Remote version unknown and Edge is installed. Defaulting to download+install."
        $needDownload = $true
    }

    if (-not $needDownload) { exit 0 }

    # Get MSI download URL from assets
    $msiUrl = Get-MsiAssetDownloadUrl -releaseObj $release -assetName $assetFileName
    if (-not $msiUrl) { throw "MSI asset '$assetFileName' not found in release assets." }
    Write-Host "MSI download URL: $msiUrl" -ForegroundColor Cyan

    # Download MSI with HttpClient and progress
    if (-not ("System.Net.Http.HttpClient" -as [type])) {
        Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
    }
    $handler = New-Object System.Net.Http.HttpClientHandler
    $client = New-Object System.Net.Http.HttpClient($handler)
    if ($env:GITHUB_TOKEN) {
        $client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::Parse("token $($env:GITHUB_TOKEN)")
    }
    $client.DefaultRequestHeaders.Add('User-Agent','Edge-Updater-Script')

    Write-Host "Starting download to $tempMsi" -ForegroundColor Cyan
    $resp = $client.GetAsync($msiUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
    if ($resp.StatusCode -ne [System.Net.HttpStatusCode]::OK) { throw "Download request failed: $($resp.StatusCode) $($resp.ReasonPhrase)" }

    $stream = $resp.Content.ReadAsStreamAsync().Result
    $total = $resp.Content.Headers.ContentLength
    if (-not $total) { Write-Warning "Server did not return content length."; $total = 0 }

    $dir = Split-Path $tempMsi
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

    $fs = [System.IO.File]::OpenWrite($tempMsi)
    $bufferSize = 8MB
    $buffer = New-Object byte[] ($bufferSize)
    $downloaded = 0
    $start = Get-Date

    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $fs.Write($buffer, 0, $read)
        $downloaded += $read
        $elapsed = (Get-Date) - $start
        $speed = if ($elapsed.TotalSeconds -gt 0) { $downloaded / $elapsed.TotalSeconds } else { 0 }
        $progressPct = if ($total -gt 0) { ($downloaded / $total) * 100 } else { 0 }

        $eta = if ($speed -gt 0 -and $total -gt 0) {
            $rem = $total - $downloaded
            $secs = [math]::Round($rem / $speed,0)
            (New-TimeSpan -Seconds $secs).ToString("hh\:mm\:ss")
        } else { "N/A" }

        $sizeText = if ($total -gt 0) { "Total: $(Format-Size $total) | " } else { "" }
        Write-Host "`r$sizeText Progress: $([math]::Round($progressPct,2))% | Downloaded: $(Format-Size $downloaded) | Speed: $(Format-Speed $speed) | ETA: $eta" -NoNewline
    }
    $fs.Close()
    Write-Host "`nDownload finished: $tempMsi" -ForegroundColor Green
    $client.Dispose()

    if (-not (Test-Path $tempMsi)) { throw "Downloaded MSI not found at $tempMsi" }

    # Run silent MSI install
    Write-Host "Running silent MSI install..." -ForegroundColor Cyan
    $msiArgs = "/i `"$tempMsi`" /qn /norestart"
    $proc = Start-Process -FilePath msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -eq 0) {
        Write-Host "MSI install completed successfully." -ForegroundColor Green
    } else {
        Write-Warning "msiexec returned exit code $($proc.ExitCode). Consider using /l*v to generate a log."
    }

} catch {
    Write-Error "Error: $($_.Exception.Message)"
    return
} finally {
    try { if (Test-Path $tempMsi) { Remove-Item -Path $tempMsi -Force -ErrorAction SilentlyContinue } } catch {}
}
