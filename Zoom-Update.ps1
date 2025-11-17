# ================================
# Zoom update (console-only)
# ================================
$ErrorActionPreference = 'SilentlyContinue'

# ---- 0) Config (local version, no lookup) ----
$latestVersion = '6.5.13227'
$downloadUrl   = 'https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64'
$tempPath      = Join-Path $env:TEMP 'ZoomInstallerFull.msi'

Write-Host "=== Zoom Updater Script ==="
Write-Host "Target version: $latestVersion"
Write-Host ""

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

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $client  = [System.Net.Http.HttpClient]::new($handler)

    try {
        $response = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
            Write-Host "`n[Error] Download failed: $($response.StatusCode) $($response.ReasonPhrase)"
            return $false
        }

        $stream = $response.Content.ReadAsStreamAsync().Result
        $total  = $response.Content.Headers.ContentLength
        if ($null -eq $total) { $total = 1024L * 1024L * 1024L }  # fallback 1GB

        $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $buffer     = New-Object byte[] (10MB)
            $downloaded = 0L
            $startTime  = Get-Date

            Write-Host "`n[Download] Downloading Zoom MSI..."
            while (($read = $stream.Read($buffer,0,$buffer.Length)) -gt 0) {
                $fs.Write($buffer,0,$read)
                $downloaded += $read
                $elapsed  = (Get-Date) - $startTime
                $speed    = if ($elapsed.TotalSeconds -gt 0) { $downloaded / $elapsed.TotalSeconds } else { 0 }
                $progress = if ($total -gt 0) { [math]::Min(100, ($downloaded / $total) * 100) } else { 0 }
                Write-Host ("`r[Download] Total: {0} | Progress: {1:N2}% | Downloaded: {2} | Speed: {3}" -f (Format-Size $total), $progress, (Format-Size $downloaded), (Format-Speed $speed)) -NoNewline
            }
            Write-Host "`n[Download] Completed: $OutFile"
        } finally {
            $fs.Close()
        }
    } catch {
        Write-Host "`n[Error] Download error: $($_.Exception.Message)"
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

    $uninstall = $Install.UninstallString
    $guid = $null
    if ($uninstall -match '\{[0-9A-Fa-f\-]{36}\}') { $guid = $matches[0] }

    # Kill Zoom processes
    Get-Process -Name zoom,zoomlauncher,zoomoutlookplugin -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if ($guid) {
        Write-Host "    -> Uninstall via MSI product code $guid"
        Start-Process msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait
        return
    }

    if ($uninstall) {
        if ($uninstall -match '(msiexec\.exe|MsiExec\.exe).*?/I\s*\{') {
            $uninstall = $uninstall -replace '/I','/X'
        }
        if ($uninstall -notmatch '/qn' -and $uninstall -notmatch '/quiet') {
            $uninstall += ' /qn'
        }
        if ($uninstall -notmatch '/norestart') {
            $uninstall += ' /norestart'
        }

        Write-Host "    -> Uninstall via uninstall string"
        Start-Process -FilePath cmd.exe -ArgumentList "/c $uninstall" -WindowStyle Hidden -Wait
    } else {
        Write-Host "    -> No uninstall string found; skipping uninstall."
    }
}

# ---- 5) Enumerate installs (HKLM + HKU, any Zoom display name) ----
Write-Host "[Info] Detecting existing Zoom installs..."

$installs = @()

# HKLM Zoom (machine-wide)
$hklmBases = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($base in $hklmBases) {
    if (-not (Test-Path $base)) { continue }
    Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $p = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
            if ($p.DisplayName -and $p.DisplayName -like '*Zoom*') {
                $installs += [pscustomobject]@{
                    Scope           = 'Machine'
                    User            = 'All'
                    Name            = $p.DisplayName
                    Version         = $p.DisplayVersion
                    UninstallString = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $p.UninstallString }
                    RegPath         = $_.PsPath
                }
            }
        } catch {}
    }
}

# HKU Zoom (per-user)
$profiles = Get-CimInstance Win32_UserProfile | Select-Object LocalPath,SID
$userSIDs = Get-ChildItem "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -notlike "*_Classes" }

foreach ($sidKey in $userSIDs) {
    $SID = $sidKey.PSChildName
    $regBase = "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    if (-not (Test-Path $regBase)) { continue }

    $profile = $profiles | Where-Object { $_.SID -eq $SID }
    $userName = if ($profile -and $profile.LocalPath) { Split-Path $profile.LocalPath -Leaf } else { $SID }

    Get-ChildItem $regBase -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $p = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
            if ($p.DisplayName -and $p.DisplayName -like '*Zoom*') {
                $installs += [pscustomobject]@{
                    Scope           = 'User'
                    User            = $userName
                    Name            = $p.DisplayName
                    Version         = $p.DisplayVersion
                    UninstallString = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $p.UninstallString }
                    RegPath         = $_.PsPath
                }
            }
        } catch {}
    }
}

# ---- 6) If nothing installed, log and exit ----
if (-not $installs -or $installs.Count -eq 0) {
    Write-Host "[Info] No Zoom installations found. Nothing to do."
    exit 0
}

Write-Host "[Info] Detected Zoom installs:"
foreach ($i in $installs) {
    $name = if ($i.Name) { $i.Name } else { "Zoom" }
    $ver  = if ($i.Version) { $i.Version } else { "Unknown" }
    Write-Host "$name - $ver"
}
Write-Host ""

# ---- 7) Compare versions and decide ----
$targetVer   = Get-NormalizedVersion $latestVersion
$needsUpdate = @()

foreach ($i in $installs) {
    $iv = Get-NormalizedVersion $i.Version
    if ($null -eq $iv) {
        Write-Host "[Warn] Could not parse version '$($i.Version)' for '$($i.Name)'; skipping."
        continue
    }
    if ($iv -lt $targetVer) {
        $needsUpdate += $i
    }
}

if (-not $needsUpdate -or $needsUpdate.Count -eq 0) {
    Write-Host "[Info] All Zoom installs are already at $latestVersion or newer. No update needed."
    exit 0
}

Write-Host "[Info] Installs needing update:"
$needsUpdate | Format-Table Scope, User, Name, Version -AutoSize
Write-Host ""

# ---- 8) Uninstall all outdated instances ----
foreach ($i in $needsUpdate) {
    $name = if ($i.Name) { $i.Name } else { "Zoom" }
    Write-Host ("[Uninstall] {0} ({1} - {2}) {3} -> target {4}" -f $name, $i.Scope, $i.User, $i.Version, $latestVersion)
    Invoke-ForceUninstall -Install $i
}

# ---- 9) Download new MSI once ----
if (Test-Path $tempPath) {
    Write-Host "[Info] Removing old installer: $tempPath"
    Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
}

Write-Host "[Info] Downloading new Zoom installer..."
$ok = Get-FileWithProgress -Url $downloadUrl -OutFile $tempPath
if (-not $ok -or -not (Test-Path $tempPath)) {
    Write-Host "[Error] Download failed or file missing; aborting."
    exit 1
}

# ---- 10) Install new version ----
Write-Host "[Install] Installing Zoom $latestVersion ..."
Start-Process msiexec.exe -ArgumentList "/i `"$tempPath`" /qn /norestart" -Wait
Write-Host "[Done] Zoom install attempted."
exit 0
