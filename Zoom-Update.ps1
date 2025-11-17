# =========================================
# Zoom Updater
# =========================================

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------
# 1. Get Latest Windows Version from Zoom Release Notes
# ------------------------------------------------------
function Get-LatestZoomWindowsVersion {

    $url = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0061222"

    try {
        $headers = @{ "User-Agent" = "Mozilla/5.0" }

        $resp = Invoke-WebRequest -Uri $url -Headers $headers -UseBasicParsing -ErrorAction Stop
        $html = $resp.Content
        if (-not $html) { return $null }

        # Extract headers from tables
        $headerMatches = [regex]::Matches($html, "<th.*?>(.*?)<\/th>")
        $headersList = @()
        foreach ($h in $headerMatches) {
            $headersList += ($h.Groups[1].Value -replace "<.*?>","").Trim()
        }

        $winIndex = $headersList.IndexOf("Windows")
        if ($winIndex -lt 0) { return $null }

        # Extract each table row
        $rowMatches = [regex]::Matches($html, "<tr[^>]*>(.*?)<\/tr>", "Singleline")

        foreach ($row in $rowMatches) {
            $cells = [regex]::Matches($row.Value, "<td.*?>(.*?)<\/td>", "Singleline")
            if ($cells.Count -eq 0) { continue }

            $clean = @()
            foreach ($c in $cells) {
                $clean += (($c.Groups[1].Value -replace "<.*?>","").Trim())
            }

            if ($winIndex -ge $clean.Count) { continue }

            $winCell = $clean[$winIndex]
            if ($winCell -eq "--") { continue }

            if ($winCell -match "(\d+\.\d+\.\d+)\s*\((\d+)\)") {
                $base  = $Matches[1]
                $build = $Matches[2]

                $parts = $base.Split(".")
                return "{0}.{1}.{2}" -f $parts[0], $parts[1], $build
            }
        }
    }
    catch {
        Write-Host "[Warn] Error fetching Zoom release notes: $($_.Exception.Message)"
    }

    return $null
}

# ------------------------------------------------------
# 2. Other Helpers
# ------------------------------------------------------

function Get-NormalizedVersion {
    param([string]$v)
    if (-not $v) { return $null }
    try { return [version]($v -replace '[^\d\.]', '') }
    catch { return $null }
}

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
        if ($response.StatusCode -ne 200) { return $false }

        $stream = $response.Content.ReadAsStreamAsync().Result
        $total  = $response.Content.Headers.ContentLength

        $fs = [System.IO.File]::Open($OutFile, 2, 2, 0)
        $buffer = New-Object byte[] (10MB)
        $downloaded = 0
        $start = Get-Date

        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fs.Write($buffer, 0, $read)
            $downloaded += $read
        }
        $fs.Close()
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Invoke-ForceUninstall {
    param([pscustomobject]$Install)

    Get-Process -Name zoom,zoomlauncher,zoomoutlookplugin -ErrorAction SilentlyContinue | Stop-Process -Force

    $uninstall = $Install.UninstallString

    if ($uninstall -match "\{[0-9A-Fa-f\-]{36}\}") {
        $guid = $matches[0]
        Start-Process msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait
        return
    }

    if ($uninstall) {
        if ($uninstall -match "/I") { $uninstall = $uninstall -replace "/I","/X" }
        if ($uninstall -notmatch "/qn") { $uninstall += " /qn" }
        if ($uninstall -notmatch "/norestart") { $uninstall += " /norestart" }

        Start-Process cmd.exe -ArgumentList "/c $uninstall" -WindowStyle Hidden -Wait
    }
}

# ------------------------------------------------------
# 3. Scan Installed Zoom Versions
# ------------------------------------------------------

Write-Host "[Info] Detecting installed Zoom versions..."

$installs = @()

# -----------------------
# MACHINE-WIDE INSTALLS
# -----------------------
$hklmPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($path in $hklmPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path | ForEach-Object {
            try {
                $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($p.DisplayName -like "*Zoom*") {
                    $installs += [pscustomobject]@{
                        Scope = "Machine"
                        User  = "All"
                        Name  = $p.DisplayName
                        Version = $p.DisplayVersion
                        UninstallString = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $p.UninstallString }
                        RegPath = $_.PSPath
                    }
                }
            } catch {}
        }
    }
}

# -----------------------
# PER-USER INSTALLS
# -----------------------
$userProfiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.Loaded -eq $true }

foreach ($profile in $userProfiles) {
    $sid = $profile.SID
    $userName = Split-Path $profile.LocalPath -Leaf

    $userUninstall = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"

    if (Test-Path $userUninstall) {
        Get-ChildItem $userUninstall | ForEach-Object {
            try {
                $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($p.DisplayName -like "*Zoom*") {
                    $installs += [pscustomobject]@{
                        Scope = "User"
                        User  = $userName
                        Name  = $p.DisplayName
                        Version = $p.DisplayVersion
                        UninstallString = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $p.UninstallString }
                        RegPath = $_.PSPath
                    }
                }
            } catch {}
        }
    }
}

# -----------------------
# SHOW DETECTED INSTALLS
# -----------------------
if ($installs.Count -eq 0) {
    Write-Host "[Info] No Zoom installation found."
    exit 0
}

Write-Host "[Info] Detected Zoom installs:"
foreach ($i in $installs) {
    Write-Host ("- {0} ({1}) - {2}" -f $i.Name, $i.Scope, $i.Version)
}
Write-Host ""

# ------------------------------------------------------
# 4. Get Latest Windows Version
# ------------------------------------------------------

$latestVersion = Get-LatestZoomWindowsVersion

if (-not $latestVersion) {
    Write-Host "[Error] Could not determine latest Zoom version."
    exit 1
}

Write-Host "[Info] Latest Zoom version available: $latestVersion"

$target = Get-NormalizedVersion $latestVersion

# ------------------------------------------------------
# 5. Compare Versions
# ------------------------------------------------------

$needsUpdate = @()

foreach ($i in $installs) {
    $iv = Get-NormalizedVersion $i.Version
    if ($iv -lt $target) {
        $needsUpdate += $i
    }
}

if ($needsUpdate.Count -eq 0) {
    Write-Host "[Info] Already up to date."
    exit 0
}

# ------------------------------------------------------
# 6. Download + Install
# ------------------------------------------------------

$downloadUrl = "https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64"
$tempPath = Join-Path $env:TEMP "ZoomInstallerFull.msi"

if (Test-Path $tempPath) { Remove-Item $tempPath -Force }

Write-Host "[Info] Downloading Zoom $latestVersion..."
$ok = Get-FileWithProgress -Url $downloadUrl -OutFile $tempPath

if (-not $ok) {
    Write-Host "[Error] Download failed."
    exit 1
}

<#foreach ($i in $needsUpdate) {
    Write-Host "[Uninstall] $($i.Name) $($i.Version)"
    Invoke-ForceUninstall $i
}#>

Write-Host "[Install] Installing Zoom $latestVersion..."
Start-Process msiexec.exe -ArgumentList "/i `"$tempPath`" /qn /norestart" -Wait

Write-Host "[Done]"
