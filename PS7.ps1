# =================================================
# PowerShell 7 – Install, Cleanup, Default Integrate
# =================================================
# -------------------------
# Helpers
# -------------------------
function Write-OK([string]$msg){ Write-Host "`n[OK] $msg" -ForegroundColor Green }
function Write-Info([string]$msg){ Write-Host "`n[..] $msg" -ForegroundColor Cyan }
function Write-Warn([string]$msg){ Write-Warning $msg }
function Write-Err([string]$msg){ Write-Host "[ERR] $msg" -ForegroundColor Red }

# -------------------------
# Paths
# -------------------------
$PwshStable  = "C:\Program Files\PowerShell\7\pwsh.exe"
$PwshPreview = "C:\Program Files\PowerShell\7-preview\pwsh.exe"

# -------------------------
# MSIX detection (WindowsApps)
# If PowerShell 7 exists as MSIX, use it and skip the MSI install.
# -------------------------
$WindowsAppsPath = "$env:ProgramFiles\WindowsApps"
$UseMsix = $false

function Get-MsixPwsh {
    param([string]$Filter)
    if (-not (Test-Path $WindowsAppsPath)) { return $null }
    Get-ChildItem -Path $WindowsAppsPath -Directory -Filter $Filter -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-Path (Join-Path $_.FullName "AppxManifest.xml")) -and
            (Test-Path (Join-Path $_.FullName "pwsh.exe")) -and
            $_.Name -match '_(\d+\.\d+\.\d+\.\d+)_'
        } |
        Sort-Object { [version]([regex]::Match($_.Name, '_(\d+\.\d+\.\d+\.\d+)_').Groups[1].Value) } -Descending |
        Select-Object -First 1 |
        ForEach-Object { Join-Path $_.FullName "pwsh.exe" }
}

$MsixStable  = Get-MsixPwsh -Filter "Microsoft.PowerShell_*"
$MsixPreview = Get-MsixPwsh -Filter "Microsoft.PowerShellPreview_*"

if ($MsixStable -or $MsixPreview) {
    $UseMsix = $true
    if ($MsixStable)  { $PwshStable  = $MsixStable }
    if ($MsixPreview) { $PwshPreview = $MsixPreview }
    Write-Info "PowerShell 7 MSIX detected. Skipping MSI install."
}

# -------------------------------------------------
# MSIX registration for the executing user
# Direct execution from WindowsApps can return 0x80070005
# when the package is staged but not registered for this user.
# -------------------------------------------------
if ($UseMsix) {
    $MsixCandidates = @(
        Get-ChildItem -Path $WindowsAppsPath -Directory `
            -Filter "Microsoft.PowerShell_*" -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-Path (Join-Path $_.FullName "AppxManifest.xml")) -and
            $_.Name -match '_(\d+\.\d+\.\d+\.\d+)_'
        } |
        Sort-Object {
            [version]([regex]::Match($_.Name, '_(\d+\.\d+\.\d+\.\d+)_').Groups[1].Value)
        } -Descending
    )

    foreach ($MsixFolder in $MsixCandidates) {
        $ManifestPath = Join-Path $MsixFolder.FullName "AppxManifest.xml"
        $FolderVersion = [version]([regex]::Match(
            $MsixFolder.Name, '_(\d+\.\d+\.\d+\.\d+)_'
        ).Groups[1].Value)

        $Registered = Get-AppxPackage -Name "Microsoft.PowerShell" `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.Version -eq $FolderVersion.ToString() } |
            Select-Object -First 1

        if (!$Registered) {
            Write-Info "Registering PowerShell MSIX $FolderVersion for current user..."
            try {
                Add-AppxPackage -Register $ManifestPath -DisableDevelopmentMode -ErrorAction Stop
                Write-OK "MSIX registration completed for $FolderVersion."
            }
            catch {
                Write-Warn "MSIX registration failed for $FolderVersion : $($_.Exception.Message)"
                throw
            }
        }
        else {
            Write-OK "PowerShell MSIX $FolderVersion already registered for current user."
        }
    }
}

# -------------------------
# Helper: Get pwsh version
# -------------------------
function Get-PwshVersion {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            return [Version](& $Path -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')
        } catch {}
    }
    return $null
}

# =================================================
# 1. Ensure PowerShell 7 STABLE installed
# =================================================
if (-not $UseMsix) {

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

        Write-Info "Starting download of PowerShell $targetVer..."
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

        Write-Info "Downloading PowerShell MSI..."
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
        Write-OK "Download Completed."
        $httpClient.Dispose()

        Write-Info "Installing..."
        Start-Process "msiexec.exe" -ArgumentList "/i `"$msiFile`" /quiet /norestart" -Wait
        Remove-Item $msiFile -Force -ErrorAction SilentlyContinue
		Write-OK "Powershell $targetVer Installed."
    } catch {
        Write-Warn "Installation failed: $_"
    }
} else {
    Write-OK "PowerShell $installedStableVer is up to date (>= $targetVer). Skipping install."
}

}  # end if (-not $UseMsix)

# =================================================
# 2. Select DEFAULT pwsh (Preview > Stable)
# =================================================
if (Test-Path $PwshPreview) {
    $DefaultPwsh = $PwshPreview
    $PwshType = "Preview"
}
elseif (Test-Path $PwshStable) {
    $DefaultPwsh = $PwshStable
    $PwshType = "Stable"
}
else {
    Write-Error "No PowerShell 7 found after install step."
    exit 1
}

Write-Info "Using PowerShell $PwshType as default: $DefaultPwsh"

# Terminal/WinX should invoke the registered app execution command,
# not launch the packaged executable directly from WindowsApps.
$DefaultPwshCommand = "pwsh.exe"

<# # =================================================
# 3. Safe replace – All Users PowerShell 5.1 profile
# =================================================
Write-Info "Configuring system-wide PowerShell redirect..."

$AllUsersProfile = "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1"
$MarkerStart = "# >>> PWSH REDIRECT START"
$MarkerEnd   = "# <<< PWSH REDIRECT END"

$RedirectBlock = @"
$MarkerStart
if (`$PSVersionTable.PSVersion.Major -lt 6) {
    `$pwsh = '$DefaultPwsh'
    if (Test-Path `$pwsh) {
        & `$pwsh
        exit
    }
}
$MarkerEnd
"@

if (!(Test-Path $AllUsersProfile)) {
    Set-Content $AllUsersProfile $RedirectBlock
} else {
    $content = Get-Content $AllUsersProfile -Raw
    if ($content -match [regex]::Escape($MarkerStart)) {
        $content = [regex]::Replace(
            $content,
            "$MarkerStart[\s\S]*?$MarkerEnd",
            $RedirectBlock
        )
    } else {
        $content += "`r`n$RedirectBlock"
    }
    Set-Content $AllUsersProfile $content
}

Write-OK "PowerShell redirect configured."
#>
# =================================================
# 4. Windows Terminal – EXISTING USERS
# =================================================
Write-Info "Configuring Windows Terminal (existing users)..."

$UserProfiles = Get-ChildItem C:\Users -Directory |
    Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

foreach ($User in $UserProfiles) {

    $SettingsPath = "C:\Users\$($User.Name)\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
    if (!(Test-Path $SettingsPath)) { continue }

    try {
        $json = Get-Content $SettingsPath -Raw | ConvertFrom-Json

        $pwshProfile = $json.profiles.list | Where-Object {
            $_.commandline -eq $DefaultPwshCommand
        }

        if (-not $pwshProfile) {
            $guid = "{"+([guid]::NewGuid())+"}"
            $pwshProfile = @{
                guid        = $guid
                name        = "PowerShell ($PwshType)"
                commandline = $DefaultPwshCommand
            }
            $json.profiles.list += $pwshProfile
        }

        $json.defaultProfile = $pwshProfile.guid
        $json | ConvertTo-Json -Depth 10 | Set-Content $SettingsPath -Encoding UTF8
    }
    catch {
        Write-Warn "Terminal update failed for user $($User.Name)"
    }
}

# =================================================
# 5. Windows Terminal – NEW USERS
# =================================================
Write-Info "Configuring Windows Terminal default for new users..."

$DefaultUserPath = "C:\Users\Default\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState"
$DefaultSettings = Join-Path $DefaultUserPath "settings.json"

if (!(Test-Path $DefaultUserPath)) {
    New-Item -ItemType Directory -Path $DefaultUserPath -Force | Out-Null
}

if (!(Test-Path $DefaultSettings)) {
    $guid = "{"+([guid]::NewGuid())+"}"
    @{
        defaultProfile = $guid
        profiles = @{
            list = @(
                @{
                    guid        = $guid
                    name        = "PowerShell ($PwshType)"
                    commandline = $DefaultPwshCommand
                }
            )
        }
    } | ConvertTo-Json -Depth 10 |
        Set-Content $DefaultSettings -Encoding UTF8
}

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
                $shortcut.TargetPath  = "pwsh.exe"
                $shortcut.Arguments   = "-NoLogo"
                $shortcut.IconLocation = "pwsh.exe,0"
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

taskkill /im powershell.exe /f
taskkill /im pwsh.exe /f