# =================================================
# PowerShell 7 Setup and Integration
# =================================================

# -------------------------
# Paths
# -------------------------
$PwshStable  = "C:\Program Files\PowerShell\7\pwsh.exe"
$PwshPreview = "C:\Program Files\PowerShell\7-preview\pwsh.exe"

# -------------------------
# Helpers
# -------------------------
function Write-OK([string]$msg){ Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info([string]$msg){ Write-Host "[..] $msg" -ForegroundColor Cyan }
function Write-Warn([string]$msg){ Write-Warning $msg }
function Write-Err([string]$msg){ Write-Host "[ERR] $msg" -ForegroundColor Red }

# -------------------------------------------------
# 1. Ensure PowerShell 7 (Stable) is installed
# -------------------------------------------------
Write-Info "Checking PowerShell 7 installation..."

# --- Get latest stable release info from GitHub ---
try {
    $releasesJson = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing
    $tag          = $releasesJson.tag_name.TrimStart("v")
    $targetVer    = [Version]$tag
    $asset        = $releasesJson.assets | Where-Object { $_.name -like "*win-x64.msi" }
    $msiUrl       = $asset.browser_download_url
    $msiFile      = "$env:TEMP\$($asset.name)"
    Write-Info "Latest PowerShell stable release detected: $targetVer"
} catch {
    Write-Warn "Failed to fetch latest release info. Falling back to 7.5.4."
    $targetVer = [Version]"7.5.4"
    $msiUrl    = "https://github.com/PowerShell/PowerShell/releases/download/v7.5.4/PowerShell-7.5.4-win-x64.msi"
    $msiFile   = "$env:TEMP\PowerShell-7.5.4-win-x64.msi"
}

function Get-InstalledPwshVersion {
    param([string]$exePath)
    if (-not (Test-Path $exePath)) { return $null }
    try {
        $out = & $exePath -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
        return [Version]$out.Trim()
    } catch { return $null }
}

$installedStableVer = Get-InstalledPwshVersion -exePath $PwshStable

if ($installedStableVer) {
    Write-Info "Detected PowerShell 7 stable: $installedStableVer"
} else {
    Write-Info "PowerShell 7 stable not detected."
}

if (-not $installedStableVer -or $installedStableVer -lt $targetVer) {

    Write-Info "Installing / upgrading PowerShell 7 stable to $targetVer..."

    try {
        # --- Formatting functions ---
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

        # --- HttpClient download with progress ---
        if (-not ("System.Net.Http.HttpClient" -as [type])) {
            Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll"
        }

        $httpClientHandler = New-Object System.Net.Http.HttpClientHandler
        $httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

        Write-Info "`nStarting download of PowerShell $targetVer..."
        $response = $httpClient.GetAsync($msiUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
            Write-Warn "`nHttpClient request failed: $($response.StatusCode) ($($response.ReasonPhrase))" -ForegroundColor Red
            exit
        }

        $stream = $response.Content.ReadAsStreamAsync().Result
        if (-not $stream) {
            Write-Warn "`nFailed to retrieve response stream." -ForegroundColor Red
            exit
        }

        $totalSize = $response.Content.Headers.ContentLength
        $fileStream = [System.IO.File]::OpenWrite($msiFile)
        $bufferSize = 10MB
        $buffer = New-Object byte[] ($bufferSize)
        $downloaded = 0
        $startTime = Get-Date

        Write-Info "`nDownloading PowerShell MSI..."
        while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fileStream.Write($buffer, 0, $bytesRead)
            $downloaded += $bytesRead
            $elapsed = (Get-Date) - $startTime
            $speed = $downloaded / $elapsed.TotalSeconds
            $progress = ($downloaded / $totalSize) * 100

            $remainingBytes = $totalSize - $downloaded
            $etaSeconds = if ($speed -gt 0) { [math]::Round($remainingBytes / $speed, 2) } else { "Calculating..." }

            if ($etaSeconds -is [double]) {
                $etaHours = [math]::Floor($etaSeconds / 3600)
                $etaMinutes = [math]::Floor(($etaSeconds % 3600) / 60)
                $etaRemainingSeconds = [math]::Floor($etaSeconds % 60)

                $etaFormatted = ""
                if ($etaHours -gt 0) { $etaFormatted += "${etaHours}h " }
                if ($etaMinutes -gt 0) { $etaFormatted += "${etaMinutes}m " }
                if ($etaRemainingSeconds -gt 0 -or $etaFormatted -eq "") { $etaFormatted += "${etaRemainingSeconds}s" }
            } else {
                $etaFormatted = "Calculating..."
            }
            Write-Host "`rTotal: $(Format-Size $totalSize) | Progress: $([math]::Round($progress,2))% | Downloaded: $(Format-Size $downloaded) | Speed: $(Format-Speed $speed) | ETA: $etaFormatted" -NoNewline
        }

        $fileStream.Close()
        Write-OK "`nDownload Completed."
        $httpClient.Dispose()

        Write-Info "`nInstalling..."
        Start-Process "msiexec.exe" -ArgumentList "/i `"$msiFile`" /quiet /norestart" -Wait
        Remove-Item $msiFile -Force -ErrorAction SilentlyContinue
		Write-OK "`nPowershell $targetVer Installed."
    } catch {
        Write-Warn "Installation failed: $_"
    }
} else {
    Write-OK "PowerShell $installedVer is up to date (>= $targetVer). Skipping install."
}

# -------------------------------------------------
# 2. Smart default selection (Preview > Stable)
# -------------------------------------------------

if (Test-Path $PwshPreview) {
    $DefaultPwsh = $PwshPreview
    $PwshType    = "Preview"
}
elseif (Test-Path $PwshStable) {
    $DefaultPwsh = $PwshStable
    $PwshType    = "Stable"
}
else {
    Write-Warn "No PowerShell 7 installation available after install step."
    return
}

Write-Info "Using PowerShell $PwshType as system default."

# -------------------------------------------------
# 3. All Users PowerShell 5.1 redirect
# -------------------------------------------------

$AllUsersProfile = "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1"

if (!(Test-Path $AllUsersProfile)) {
    New-Item -ItemType File -Path $AllUsersProfile -Force | Out-Null
}

$ProfileContent = @"
# --- Auto redirect to PowerShell 7 ($PwshType) ---
if (`$PSVersionTable.PSVersion.Major -lt 6) {
    `$pwsh = '$DefaultPwsh'
    if (Test-Path `$pwsh) {
        & `$pwsh
        exit
    }
}
"@

if (-not (Select-String -Path $AllUsersProfile -Pattern "Auto redirect to PowerShell 7" -Quiet)) {
    Add-Content -Path $AllUsersProfile -Value $ProfileContent
}

Write-OK "PowerShell redirect configured."

# -------------------------------------------------
# 4. Windows Terminal - existing users
# -------------------------------------------------

Write-Info "Configuring Windows Terminal default (existing users)..."

$UserProfiles = Get-ChildItem "C:\Users" -Directory |
    Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

foreach ($User in $UserProfiles) {

    $WtSettingsPath = "C:\Users\$($User.Name)\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
    if (!(Test-Path $WtSettingsPath)) { continue }

    try {
        $json = Get-Content $WtSettingsPath -Raw | ConvertFrom-Json
        $pwshProfile = $json.profiles.list | Where-Object {
            $_.commandline -eq $DefaultPwsh
        }

        if ($pwshProfile) {
            $json.defaultProfile = $pwshProfile.guid
            $json | ConvertTo-Json -Depth 10 | Set-Content $WtSettingsPath -Encoding UTF8
        }
    } catch {
        Write-Warn "Failed to update Terminal for user: $($User.Name)"
    }
}

# -------------------------------------------------
# 5. Windows Terminal - new users
# -------------------------------------------------

Write-Info "Configuring Windows Terminal default for new users..."

$DefaultUserPath = "C:\Users\Default\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState"
$DefaultSettingsPath = Join-Path $DefaultUserPath "settings.json"

if (!(Test-Path $DefaultUserPath)) {
    New-Item -ItemType Directory -Path $DefaultUserPath -Force | Out-Null
}

if (!(Test-Path $DefaultSettingsPath)) {
    $Guid = [guid]::NewGuid().ToString()
    @{
        defaultProfile = "{$Guid}"
        profiles = @{
            list = @(
                @{
                    guid        = "{$Guid}"
                    name        = "PowerShell ($PwshType)"
                    commandline = $DefaultPwsh
                }
            )
        }
    } | ConvertTo-Json -Depth 10 |
        Set-Content $DefaultSettingsPath -Encoding UTF8
}

Write-OK "PowerShell 7 install + smart default configuration completed."

# -------------------------------------------------
# 6. Replace Win+X menu PowerShell links
# -------------------------------------------------
Write-Info "Updating Win+X menu shortcuts for all users..."

$UserProfiles = Get-ChildItem "C:\Users" -Directory |
    Where-Object { $_.Name -notin @("Public","Default User","All Users") }

foreach ($User in $UserProfiles) {
    $winxPath = "C:\Users\$($User.Name)\AppData\Local\Microsoft\Windows\WinX"
    if (!(Test-Path $winxPath)) { continue }
    try {
        $shortcuts = Get-ChildItem -Path $winxPath -Recurse -Filter *.lnk
        foreach ($sc in $shortcuts) {
            $wshell = New-Object -ComObject WScript.Shell
            $shortcut = $wshell.CreateShortcut($sc.FullName)

            if ($shortcut.TargetPath -match "powershell.exe") {
                $shortcut.TargetPath  = $DefaultPwsh
                $shortcut.IconLocation = "$DefaultPwsh,0"
                $shortcut.Save()
                Write-Info "Updated Win+X shortcut for user $($User.Name)."
            }
        }
    }
    catch {
        Write-Warn "Failed to update Win+X menu for user: $($User.Name)"
    }
}
Write-OK "Win+X menu updated to use PowerShell ($PwshType) for all users."
