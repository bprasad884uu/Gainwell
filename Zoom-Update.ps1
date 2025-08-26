# ================================
# Zoom update (console-only)
# ================================
$ErrorActionPreference = 'SilentlyContinue'

# ---- 0) Config (local version, no lookup) ----
$latestVersion = '6.5.13227'
$downloadUrl   = 'https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64'
$tempPath      = Join-Path $env:TEMP 'ZoomInstallerFull.msi'

# ---- 1) Helper: formatters for progress ----
function Format-Size {
    param([long]$bytes)
    switch ($bytes) {
        {$_ -ge 1GB} {return ('{0:N2} GB' -f ($bytes/1GB))}
        {$_ -ge 1MB} {return ('{0:N2} MB' -f ($bytes/1MB))}
        {$_ -ge 1KB} {return ('{0:N2} KB' -f ($bytes/1KB))}
        default      {return "$bytes B"}
    }
}
function Format-Speed {
    param([double]$bps)
    switch ($bps) {
        {$_ -ge 1GB} {return ('{0:N2} GB/s' -f ($bps/1GB))}
        {$_ -ge 1MB} {return ('{0:N2} MB/s' -f ($bps/1MB))}
        {$_ -ge 1KB} {return ('{0:N2} KB/s' -f ($bps/1KB))}
        default      {return ('{0:N2} B/s' -f $bps)}
    }
}

# ---- 2) Helper: download with console progress ----
function Get-FileWithProgress {
    param(
        [Parameter(Mandatory)] [string]$Url,
        [Parameter(Mandatory)] [string]$OutFile
    )
    Add-Type -AssemblyName System.Net.Http
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $client  = [System.Net.Http.HttpClient]::new($handler)

    try {
        $response = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
            Write-Host "`nDownload failed: $($response.StatusCode) $($response.ReasonPhrase)"
            return $false
        }

        $stream = $response.Content.ReadAsStreamAsync().Result
        $total  = $response.Content.Headers.ContentLength
        if ($null -eq $total) { $total = 1024L * 1024L * 1024L }  # fallback 1GB cap so progress math works

        $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $buffer     = New-Object byte[] (10MB)
            $downloaded = 0L
            $startTime  = Get-Date

            Write-Host "`nDownloading Zoom MSI..."
            while (($read = $stream.Read($buffer,0,$buffer.Length)) -gt 0) {
                $fs.Write($buffer,0,$read)
                $downloaded += $read
                $elapsed  = (Get-Date) - $startTime
                $speed    = if ($elapsed.TotalSeconds -gt 0) { $downloaded / $elapsed.TotalSeconds } else { 0 }
                $progress = if ($total -gt 0) { [math]::Min(100, ($downloaded / $total) * 100) } else { 0 }
                Write-Host ("`rTotal: {0} | Progress: {1:N2}% | Downloaded: {2} | Speed: {3}" -f (Format-Size $total), $progress, (Format-Size $downloaded), (Format-Speed $speed)) -NoNewline
            }
            Write-Host "`nDownload complete: $OutFile"
        } finally {
            $fs.Close()
        }
    } catch {
        Write-Host "`n[!] Download error: $($_.Exception.Message)"
        return $false
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
    return $true
}

# ---- 3) Helper: robust version parsing ----
function Get-NormalizedVersion {
    param([string]$v)
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    $clean = ($v -replace '[^\d\.]','') # e.g. "6.0.11 (39959)" -> "6.0.11"
    try { return [version]$clean } catch { return $null }
}

# ---- 4) Helper: force uninstall for a found install ----
function Invoke-ForceUninstall {
    param(
        [Parameter(Mandatory)] [pscustomobject]$Install
    )
    # Try to extract a product code if present in strings, else run uninstall string silently.
    $uninstall = $Install.UninstallString
    $guid = $null
    if ($uninstall -match '\{[0-9A-Fa-f\-]{36}\}') { $guid = $matches[0] }

    # Best effort: kill Zoom processes first (prevents in-use files)
    Get-Process -Name zoom,zoomlauncher,zoomoutlookplugin -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if ($guid) {
        Write-Host " - Uninstall via MSI product code $guid"
        Start-Process msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait
        return
    }

    if ($uninstall) {
        # If it's an MSI /I, flip to /X; ensure silent flags
        if ($uninstall -match '(msiexec\.exe|MsiExec\.exe).*?/I\s*\{') {
            $uninstall = $uninstall -replace '/I','/X'
        }
        if ($uninstall -notmatch '/qn' -and $uninstall -notmatch '/quiet') {
            $uninstall += ' /qn'
        }
        if ($uninstall -notmatch '/norestart') {
            $uninstall += ' /norestart'
        }

        Write-Host " - Uninstall via uninstall string"
        # Run through cmd to preserve embedded quotes/args reliably
        Start-Process -FilePath cmd.exe -ArgumentList "/c $uninstall" -WindowStyle Hidden -Wait
    } else {
        Write-Host " - No uninstall string found; skipping uninstall attempt."
    }
}

# ---- 5) Enumerate installs exactly where you asked ----
$userSIDs = Get-ChildItem "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -notlike "*_Classes" }
$hklmPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX"
)
$profiles = Get-CimInstance Win32_UserProfile | Select-Object LocalPath,SID

$installs = @()

# HKU (per-user) ZoomUMX
foreach ($sidKey in $userSIDs) {
    $SID = $sidKey.PSChildName
    $regPath = "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX"
    if (Test-Path $regPath) {
        $p = Get-ItemProperty -Path $regPath
        $u = ($profiles | Where-Object { $_.SID -eq $SID }).LocalPath
        $userName = if ($u) { Split-Path $u -Leaf } else { $SID }
        $installs += [pscustomobject]@{
            Scope            = 'User'
            User             = $userName
            Name             = $p.DisplayName
            Version          = $p.DisplayVersion
            UninstallString  = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $p.UninstallString }
            RegPath          = $regPath
        }
    }
}

# HKLM (machine) ZoomUMX
foreach ($path in $hklmPaths) {
    if (Test-Path $path) {
        $p = Get-ItemProperty -Path $path
        $installs += [pscustomobject]@{
            Scope            = 'Machine'
            User             = 'All'
            Name             = $p.DisplayName
            Version          = $p.DisplayVersion
            UninstallString  = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $p.UninstallString }
            RegPath          = $path
        }
    }
}

# ---- 6) If nothing installed, do nothing ----
if (-not $installs -or $installs.Count -eq 0) { exit 0 }

# ---- 7) Compare versions and decide ----
$targetVer = Get-NormalizedVersion $latestVersion
$needsUpdate = @()

foreach ($i in $installs) {
    $iv = Get-NormalizedVersion $i.Version
    if ($null -eq $iv) { continue }             # skip unparsable
    if ($iv -lt $targetVer) { $needsUpdate += $i }
}

if (-not $needsUpdate -or $needsUpdate.Count -eq 0) {
    # Already up to date everywhere → do nothing
    exit 0
}

# ---- 8) Uninstall all outdated instances ----
foreach ($i in $needsUpdate) {
    $name = if ($i.Name) { $i.Name } else { "Zoom" }
    Write-Host ("[Uninstall] {0} ({1}) {2} -> target {3}" -f $name, $i.Scope, $i.Version, $latestVersion)
    Invoke-ForceUninstall -Install $i
}

# ---- 9) Download new MSI once ----
if (Test-Path $tempPath) { Remove-Item $tempPath -Force -ErrorAction SilentlyContinue }
$ok = Get-FileWithProgress -Url $downloadUrl -OutFile $tempPath
if (-not $ok -or -not (Test-Path $tempPath)) { exit 1 }

# ---- 10) Install new version ----
Write-Host "[Install] Installing Zoom $latestVersion ..."
Start-Process msiexec.exe -ArgumentList "/i `"$tempPath`" /qn /norestart" -Wait
Write-Host "[Done] Zoom install attempted."
