<#
    System Cleanup Utility
    -----------------------
    PowerShell 5.1+ compatible. Tested syntax avoids version-specific operators
    (no ternary, no null-coalescing, no $PSStyle) so it runs the same way on
    Windows PowerShell 5.1 and PowerShell 7+.

    What this does:
      - Cleans the same categories/headings shown in the reference UI
        (Edge Chromium, Internet Explorer, Windows Explorer, System, Advanced,
        Google Chrome, Mozilla Firefox, Windows Store, Applications, Internet,
        Multimedia, Utilities, Windows)
      - Only cleans items that were CHECKED in the reference screenshots.
        Anything password-related or unchecked (Saved Passwords, Autocomplete
        Form History, Network Passwords, Wipe Free Space) is intentionally
        left alone.
      - Shows a live progress bar + percentage next to every heading while it
        works through that heading's items.
      - At the end, prints an Advanced Report (per item: size + file count)
        and a per-drive report (Total / Used / Before / Cleaned / Difference).
      - Runs TRIM on SSD volumes (skips HDDs automatically).

    Usage:
      .\Windows11-Debloater.ps1            -> actually cleans
      .\Windows11-Debloater.ps1 -DryRun    -> only measures, deletes nothing

    Notes:
      - Run as Administrator for best results. Without elevation, some items
        (other users' Recycle Bin, Event Logs, Delivery Optimization, machine
        PATH dedupe, SSD TRIM) will be skipped silently and safely.
      - Add your own extra paths to $CustomCleanupPaths below if you want this
        script to also clean ManageEngine agent temp folders, custom log
        locations, etc.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$DisableTelemetry,
    [switch]$SetupPwsh7,
    [switch]$DisableRecall,
    [switch]$EnableRecall,
    [switch]$LaptopMode
)

# ===========================================================================
# Global state
# ===========================================================================
$Script:DryRun             = $DryRun.IsPresent
$Script:DisableTelemetry   = $DisableTelemetry.IsPresent
$Script:SetupPwsh7         = $SetupPwsh7.IsPresent
$Script:DisableRecall      = $DisableRecall.IsPresent
$Script:EnableRecall       = $EnableRecall.IsPresent
$Script:LaptopMode         = $LaptopMode.IsPresent
$Script:Results            = New-Object System.Collections.Generic.List[Object]
$Script:TotalBytesCleaned  = 0L
$Script:BytesByDrive        = @{}

# Add your own custom paths here, e.g. @("D:\Logs\*.log", "C:\Temp\Agent\*")
$CustomCleanupPaths = @()

# Color assigned to each heading (used for the progress bar and the report)
$Script:HeadingColors = @{
    "Browsers"          = [ConsoleColor]::Blue
    "Edge Chromium"     = [ConsoleColor]::Blue
    "Internet Explorer" = [ConsoleColor]::DarkBlue
    "Windows Explorer"  = [ConsoleColor]::Yellow
    "System"            = [ConsoleColor]::Cyan
    "Advanced"          = [ConsoleColor]::Magenta
    "Google Chrome"     = [ConsoleColor]::Red
    "Mozilla Firefox"   = [ConsoleColor]::DarkYellow
    "Windows Store"     = [ConsoleColor]::Green
    "Applications"      = [ConsoleColor]::Gray
    "Internet"          = [ConsoleColor]::Cyan
    "Multimedia"        = [ConsoleColor]::Magenta
    "Utilities"         = [ConsoleColor]::DarkGray
    "Windows"           = [ConsoleColor]::Blue
}

function Get-HeadingColor {
    param([string]$Heading)
    if ($Script:HeadingColors.ContainsKey($Heading)) {
        return $Script:HeadingColors[$Heading]
    }
    return [ConsoleColor]::White
}

# ===========================================================================
# Helper functions
# ===========================================================================

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Set-RegValue {
    <# Creates the key if missing, then sets the value. Respects -DryRun. #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [string]$Type = "DWord"
    )
    try {
        if ($Script:DryRun) { return $true }
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction SilentlyContinue | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Disable-ScheduledTaskByPath {
    <# FullPath example: "Microsoft\Windows\Application Experience\MareBackup" #>
    param([string]$FullPath)
    try {
        $taskName = Split-Path -Path $FullPath -Leaf
        $parent   = Split-Path -Path $FullPath -Parent
        $taskPath = "\$parent\"
        $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
        if ($task) {
            if (-not $Script:DryRun) {
                try { Disable-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue | Out-Null } catch { }
            }
            return $true
        }
    } catch { }
    return $false
}

function Format-Size {
    param([long]$Bytes)
    if ($null -eq $Bytes) { $Bytes = 0 }
    $abs = [math]::Abs($Bytes)
    if ($abs -ge 1TB) {
        return ("{0:N2} TB" -f ($Bytes / 1TB))
    }
    elseif ($abs -ge 1GB) {
        return ("{0:N2} GB" -f ($Bytes / 1GB))
    }
    elseif ($abs -ge 1MB) {
        return ("{0:N2} MB" -f ($Bytes / 1MB))
    }
    elseif ($abs -ge 1KB) {
        return ("{0:N2} KB" -f ($Bytes / 1KB))
    }
    else {
        return ("{0:N0} Bytes" -f $Bytes)
    }
}

function Write-HeadingProgress {
    param(
        [string]$Heading,
        [int]$PercentComplete,
        [int]$BarWidth = 36,
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    if ($PercentComplete -lt 0) { $PercentComplete = 0 }
    if ($PercentComplete -gt 100) { $PercentComplete = 100 }

    $filled = [math]::Floor(($PercentComplete / 100) * $BarWidth)
    if ($filled -gt $BarWidth) { $filled = $BarWidth }

    # Using hex char codes (not literal pasted characters) keeps this .ps1
    # file itself pure ASCII on disk, while still drawing block characters
    # at runtime: 0x2588 = full block, 0x2591 = light shade.
    $fillChar  = [char]0x2588
    $emptyChar = [char]0x2591

    # Build the raw bar first, then overlay the percentage label centered
    # on top of it. Each character keeps whatever color its position would
    # have had (Green if under the filled portion, DarkGray if under the
    # track) - so the label itself turns green character-by-character as
    # the fill catches up to it, instead of being a separate fixed color.
    $barChars = New-Object 'char[]' $BarWidth
    for ($i = 0; $i -lt $BarWidth; $i++) {
        if ($i -lt $filled) { $barChars[$i] = $fillChar } else { $barChars[$i] = $emptyChar }
    }

    $label = "{0}%" -f $PercentComplete
    $labelStart = [math]::Floor(($BarWidth - $label.Length) / 2)
    if ($labelStart -lt 0) { $labelStart = 0 }
    for ($i = 0; $i -lt $label.Length; $i++) {
        $pos = $labelStart + $i
        if ($pos -ge 0 -and $pos -lt $BarWidth) {
            $barChars[$pos] = $label[$i]
        }
    }

    Write-Host -NoNewline "`r  "
    Write-Host -NoNewline ("{0,-22}" -f $Heading) -ForegroundColor $Color
    Write-Host -NoNewline " ["

    # Emit the bar in runs of same-color characters (minimizes Write-Host
    # calls while still allowing the label to straddle the fill boundary).
    $i = 0
    while ($i -lt $BarWidth) {
        $isFilled = ($i -lt $filled)
        $runColor = [ConsoleColor]::DarkGray
        if ($isFilled) { $runColor = [ConsoleColor]::Green }
        $j = $i
        while ($j -lt $BarWidth -and (($j -lt $filled) -eq $isFilled)) { $j++ }
        $run = -join $barChars[$i..($j - 1)]
        Write-Host -NoNewline $run -ForegroundColor $runColor
        $i = $j
    }

    Write-Host -NoNewline "] "
    Write-Host -NoNewline "      "
}

function Add-DriveBytes {
    param([string]$Drive, [long]$Bytes)
    if (-not $Script:BytesByDrive.ContainsKey($Drive)) {
        $Script:BytesByDrive[$Drive] = 0L
    }
    $Script:BytesByDrive[$Drive] += $Bytes
}

function Remove-CleanupTarget {
    <#
        Deletes files/folders matching one or more path patterns (wildcards OK).
        Always measures size/file count first; only deletes if -DryRun is off.
    #>
    param([Parameter(Mandatory)][string[]]$Paths)

    $totalBytes = 0L
    $totalFiles = 0

    foreach ($pattern in $Paths) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        try { $items = Get-ChildItem -Path $pattern -Force -ErrorAction SilentlyContinue } catch { $items = $null }
        if (-not $items) { continue }

        foreach ($item in $items) {
            try {
                if ($item.PSIsContainer) {
                    $files = Get-ChildItem -Path $item.FullName -Recurse -Force -File -ErrorAction SilentlyContinue
                    if ($files) {
                        $sum = $files | Measure-Object -Property Length -Sum
                        if ($sum.Sum) { $totalBytes += $sum.Sum }
                        $totalFiles += $sum.Count
                    }
                    if (-not $Script:DryRun) {
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    }
                } else {
                    $totalBytes += $item.Length
                    $totalFiles += 1
                    if (-not $Script:DryRun) {
                        Remove-Item -Path $item.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch { continue }
        }
    }

    return @{ Bytes = $totalBytes; Files = $totalFiles }
}

function Clear-RegistryTree {
    <#
        Clears values under one or more registry keys. With -Recurse it also
        clears values in every subkey (used for MRU-style keys). Subkeys
        themselves are not deleted, only their values.
    #>
    param([string[]]$RegPaths, [switch]$Recurse)

    $count = 0
    foreach ($base in $RegPaths) {
        if ([string]::IsNullOrWhiteSpace($base)) { continue }
        if (-not (Test-Path $base)) { continue }

        $keys = New-Object System.Collections.Generic.List[string]
        $keys.Add($base)
        if ($Recurse) {
            try {
                Get-ChildItem -Path $base -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $keys.Add($_.PSPath) }
            } catch { }
        }

        foreach ($k in $keys) {
            try {
                $props = (Get-Item -Path $k -Force -ErrorAction SilentlyContinue).Property
                foreach ($p in $props) {
                    $count++
                    if (-not $Script:DryRun) {
                        try { Remove-ItemProperty -Path $k -Name $p -Force -ErrorAction SilentlyContinue } catch { }
                    }
                }
            } catch { continue }
        }
    }
    return $count
}

function Remove-BrokenShortcuts {
    <# Removes .lnk shortcuts whose target no longer exists. #>
    param([string[]]$Folders)

    $bytes = 0L
    $files = 0
    $wsh = $null
    try { $wsh = New-Object -ComObject WScript.Shell } catch { }
    if (-not $wsh) { return @{ Bytes = 0; Files = 0 } }

    foreach ($folder in $Folders) {
        if (-not (Test-Path $folder)) { continue }
        $links = Get-ChildItem -Path $folder -Filter '*.lnk' -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($link in $links) {
            try {
                $sc = $wsh.CreateShortcut($link.FullName)
                $target = $sc.TargetPath
                if ($target -and -not (Test-Path $target)) {
                    $bytes += $link.Length
                    $files += 1
                    if (-not $Script:DryRun) {
                        Remove-Item -Path $link.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch { continue }
        }
    }
    return @{ Bytes = $bytes; Files = $files }
}

function Get-FixedDriveSnapshot {
    $result = @{}
    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
        foreach ($d in $disks) {
            $result[$d.DeviceID] = @{
                Total = [long]$d.Size
                Free  = [long]$d.FreeSpace
            }
        }
    } catch { }
    return $result
}

function Get-DriveMediaTypeMap {
    $map = @{}
    try {
        $disks = Get-Disk -ErrorAction SilentlyContinue
        foreach ($disk in $disks) {
            $mediaType = "Unknown"
            try {
                $phys = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq $disk.Number }
                if ($phys) { $mediaType = $phys.MediaType }
            } catch { }
            try {
                $parts = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
                foreach ($p in $parts) {
                    if ($p.DriveLetter -and ($p.DriveLetter -ne 0)) {
                        $map[[string]$p.DriveLetter] = $mediaType
                    }
                }
            } catch { }
        }
    } catch { }
    return $map
}

function Invoke-SsdTrim {
    param([hashtable]$MediaMap, [string[]]$DriveLetters)
    $results = @()
    foreach ($dl in $DriveLetters) {
        $letter = $dl.TrimEnd(':')
        $media = $MediaMap[$letter]
        if ($media -eq 'SSD') {
            try {
                Optimize-Volume -DriveLetter $letter -ReTrim -ErrorAction Stop
                $results += [PSCustomObject]@{ Drive = $dl; Status = "TRIM completed" }
            } catch {
                $results += [PSCustomObject]@{ Drive = $dl; Status = "TRIM failed or needs Administrator rights" }
            }
        } elseif ($media -eq 'HDD') {
            $results += [PSCustomObject]@{ Drive = $dl; Status = "Skipped (HDD, not SSD)" }
        } else {
            $results += [PSCustomObject]@{ Drive = $dl; Status = "Skipped (media type unknown)" }
        }
    }
    return ($results | Sort-Object Drive)
}

function Show-DriveStatusReport {
    <# Per-drive health snapshot: OK under 80% used, WARNING under 90%, else CRITICAL. #>
    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    } catch { $disks = $null }
    if (-not $disks) { return }

    foreach ($drive in ($disks | Sort-Object DeviceID)) {
        if (-not $drive.Size -or $drive.Size -eq 0) { continue }
        $usedPercent = [math]::Round((($drive.Size - $drive.FreeSpace) / $drive.Size) * 100, 1)
        $freePercent = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 1)

        $statusTag = "[OK]"; $statusColor = [ConsoleColor]::Green
        if ($usedPercent -ge 90) { $statusTag = "[CRITICAL]"; $statusColor = [ConsoleColor]::Red }
        elseif ($usedPercent -ge 80) { $statusTag = "[WARNING]"; $statusColor = [ConsoleColor]::Yellow }

        Write-Host ""
        Write-Host ("DeviceID  : {0}" -f $drive.DeviceID) -ForegroundColor Cyan
        Write-Host ("TotalSize : {0}" -f (Format-Size $drive.Size)) -ForegroundColor White
        Write-Host ("FreeSpace : {0}" -f (Format-Size $drive.FreeSpace)) -ForegroundColor Green
        Write-Host ("UsedSpace : {0}" -f (Format-Size ($drive.Size - $drive.FreeSpace))) -ForegroundColor Yellow
        Write-Host -NoNewline "Used%     : "
        Write-Host ("{0} %" -f $usedPercent) -ForegroundColor $statusColor
        Write-Host -NoNewline "Free%     : "
        Write-Host ("{0} %" -f $freePercent) -ForegroundColor Green
        Write-Host -NoNewline "Status    : "
        Write-Host $statusTag -ForegroundColor $statusColor
    }
}

function Write-OK   { param([string]$Message) Write-Host ("`n[OK] {0}" -f $Message) -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host ("`n[..] {0}" -f $Message) -ForegroundColor Cyan }
function Write-Warn { param([string]$Message) Write-Warning $Message }
function Write-Err  { param([string]$Message) Write-Host ("`n[ERR] {0}" -f $Message) -ForegroundColor Red }

function Ensure-Key {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
        }
    } catch { }
}

function Format-Speed {
    param([double]$BytesPerSecond)
    if ($BytesPerSecond -ge 1GB) { return ("{0:N2} GB/s" -f ($BytesPerSecond / 1GB)) }
    elseif ($BytesPerSecond -ge 1MB) { return ("{0:N2} MB/s" -f ($BytesPerSecond / 1MB)) }
    elseif ($BytesPerSecond -ge 1KB) { return ("{0:N2} KB/s" -f ($BytesPerSecond / 1KB)) }
    else { return ("{0:N2} B/s" -f $BytesPerSecond) }
}

function Get-InstalledPwshVersion {
    param([string]$ExePath)
    if (-not (Test-Path $ExePath)) { return $null }
    try {
        $out = & $ExePath -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
        return [Version]$out.Trim()
    } catch {
        return $null
    }
}

function Disable-WindowsRecall {
    #Write-Info "Disabling Windows Recall / AI Data Analysis..."
    if ($Script:DryRun) { Write-Info "(dry run, no changes made)"; return }
    Ensure-Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    $null = Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1 -Type "DWord"
    try {
        $feature = (& dism.exe /online /Get-Features 2>$null | Select-String "Recall")
        if ($feature) {
            & dism.exe /Online /Disable-Feature /FeatureName:Recall /NoRestart | Out-Null
        } else {
            #Write-Info "Recall feature not detected on this system."
        }
    } catch { }
    Write-OK "Recall disabled."
}

function Enable-WindowsRecall {
    Write-Info "Enabling Windows Recall / AI Data Analysis..."
    if ($Script:DryRun) { Write-Info "(dry run, no changes made)"; return }
    try { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -ErrorAction SilentlyContinue } catch { }
    try {
        $feature = (& dism.exe /online /Get-Features 2>$null | Select-String "Recall")
        if ($feature) {
            & dism.exe /Online /Enable-Feature /FeatureName:Recall /NoRestart | Out-Null
        } else {
            Write-Info "Recall feature not detected on this system."
        }
    } catch { }
    Write-OK "Recall enable attempted."
}

function Set-LaptopHibernationDefaults {
    #Write-Info "Enabling hibernation and configuring laptop power defaults..."
    if ($Script:DryRun) { Write-Info "(dry run, no changes made)"; return }
    try { & powercfg.exe /hibernate on } catch { }
    $null = Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" -Name "Attributes" -Value 2 -Type "DWord"
    $null = Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\94ac6d29-73ce-41a6-809f-6363ba21b47e" -Name "Attributes" -Value 2 -Type "DWord"
    try {
        & powercfg.exe /change standby-timeout-ac 0
        & powercfg.exe /change standby-timeout-dc 60
        & powercfg.exe /change monitor-timeout-ac 20
        & powercfg.exe /change monitor-timeout-dc 10
    } catch { }
    Write-OK "Hibernation and laptop power defaults applied."
}

function Invoke-Pwsh7Setup {
    <#
        Installs/updates PowerShell 7 (stable) if needed, then points Windows
        Terminal (existing + new users) and the Win+X menu at it, and opts
        pwsh itself out of telemetry. Network call to the GitHub API for the
        latest release; falls back to a pinned version if that fails.
    #>
    $PwshStable  = "C:\Program Files\PowerShell\7\pwsh.exe"
    $PwshPreview = "C:\Program Files\PowerShell\7-preview\pwsh.exe"

    Write-OK "Checking PowerShell 7 installation..."

    try {
        $releasesJson = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing
        $tag       = $releasesJson.tag_name.TrimStart("v")
        $targetVer = [Version]$tag
        $asset     = $releasesJson.assets | Where-Object { $_.name -like "*win-x64.msi" }
        $msiUrl    = $asset.browser_download_url
        $msiFile   = "$env:TEMP\$($asset.name)"
        #Write-Info ("Latest PowerShell stable release detected: {0}" -f $targetVer)
    } catch {
        Write-Warn "Failed to fetch latest release info. Falling back to 7.5.4."
        $targetVer = [Version]"7.5.4"
        $msiUrl    = "https://github.com/PowerShell/PowerShell/releases/download/v7.5.4/PowerShell-7.5.4-win-x64.msi"
        $msiFile   = "$env:TEMP\PowerShell-7.5.4-win-x64.msi"
    }

    $installedStableVer = Get-InstalledPwshVersion -ExePath $PwshStable
    #if ($installedStableVer) { Write-Info ("Detected PowerShell 7 stable: {0}" -f $installedStableVer) }

    $installedPreviewVer = Get-InstalledPwshVersion -ExePath $PwshPreview
    #if ($installedPreviewVer) { Write-Info ("Detected PowerShell 7 Preview: {0}" -f $installedPreviewVer) }

    $needsInstall = (-not $installedPreviewVer) -and ((-not $installedStableVer) -or ($installedStableVer -lt $targetVer))

    if ($needsInstall -and -not $Script:DryRun) {
        Write-Info ("Installing / upgrading PowerShell 7 stable to {0}..." -f $targetVer)
        try {
            if (-not ("System.Net.Http.HttpClient" -as [type])) {
                Add-Type -Path ("$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())System.Net.Http.dll")
            }
            $httpClientHandler = New-Object System.Net.Http.HttpClientHandler
            $httpClient = New-Object System.Net.Http.HttpClient($httpClientHandler)

            Write-Info ("Starting download of PowerShell {0}..." -f $targetVer)
            $response = $httpClient.GetAsync($msiUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                Write-Err ("Download request failed: {0} ({1})" -f $response.StatusCode, $response.ReasonPhrase)
            } else {
                $stream     = $response.Content.ReadAsStreamAsync().Result
                $totalSize  = $response.Content.Headers.ContentLength
                $fileStream = [System.IO.File]::OpenWrite($msiFile)
                $bufferSize = 10MB
                $buffer     = New-Object byte[] ($bufferSize)
                $downloaded = 0L
                $startTime  = Get-Date

                #Write-Info "Downloading PowerShell MSI..."
                while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $fileStream.Write($buffer, 0, $bytesRead)
                    $downloaded += $bytesRead
                    $elapsed = (Get-Date) - $startTime
                    $speed = 0
                    if ($elapsed.TotalSeconds -gt 0) { $speed = $downloaded / $elapsed.TotalSeconds }
                    $progress = 0
                    if ($totalSize -gt 0) { $progress = ($downloaded / $totalSize) * 100 }

                    $etaFormatted = "Calculating..."
                    if ($speed -gt 0 -and $totalSize -gt 0) {
                        $remainingBytes = $totalSize - $downloaded
                        $etaSeconds = [math]::Round($remainingBytes / $speed, 0)
                        $etaHours = [math]::Floor($etaSeconds / 3600)
                        $etaMinutes = [math]::Floor(($etaSeconds % 3600) / 60)
                        $etaRemainingSeconds = [math]::Floor($etaSeconds % 60)
                        $etaFormatted = ""
                        if ($etaHours -gt 0) { $etaFormatted += "${etaHours}h " }
                        if ($etaMinutes -gt 0) { $etaFormatted += "${etaMinutes}m " }
                        if ($etaRemainingSeconds -gt 0 -or $etaFormatted -eq "") { $etaFormatted += "${etaRemainingSeconds}s" }
                    }

                    Write-Host -NoNewline ("`rTotal: {0} | Progress: {1}% | Downloaded: {2} | Speed: {3} | ETA: {4}    " -f (Format-Size $totalSize), ([math]::Round($progress, 2)), (Format-Size $downloaded), (Format-Speed $speed), $etaFormatted)
                }
                $fileStream.Close()
                Write-Host ""
                Write-OK "Download completed."
                $httpClient.Dispose()

                Write-Info "Installing..."
                Start-Process "msiexec.exe" -ArgumentList "/i `"$msiFile`" /quiet /norestart" -Wait
                Remove-Item $msiFile -Force -ErrorAction SilentlyContinue
                Write-OK ("PowerShell {0} installed." -f $targetVer)
            }
        } catch {
            Write-Warn ("Installation failed: {0}" -f $_)
        }
    } elseif ($needsInstall -and $Script:DryRun) {
        Write-Info ("Would install / upgrade PowerShell 7 to {0} (dry run)." -f $targetVer)
    } else {
        $installedVerLabel = "Unknown"
        if ($installedPreviewVer) { $installedVerLabel = "Preview $installedPreviewVer" }
        elseif ($installedStableVer) { $installedVerLabel = "Stable $installedStableVer" }
        Write-OK ("PowerShell {0} is up to date. Skipping install." -f $installedVerLabel)
    }

    $DefaultPwsh = $null
    $PwshType    = $null
    if (Test-Path $PwshPreview) { $DefaultPwsh = $PwshPreview; $PwshType = "Preview" }
    elseif (Test-Path $PwshStable) { $DefaultPwsh = $PwshStable; $PwshType = "Stable" }

    if (-not $DefaultPwsh) {
        Write-Warn "No PowerShell 7 installation available after install step. Skipping Terminal/WinX/telemetry configuration."
        return
    }

    #Write-Info ("Using PowerShell {0} as system default." -f $PwshType)

    if ($Script:DryRun) {
        Write-Info "(dry run, skipping Windows Terminal / Win+X / telemetry changes)"
        return
    }

    #Write-Info "Configuring Windows Terminal (existing users)..."
    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

    foreach ($User in $UserProfiles) {
        $SettingsPath = "C:\Users\$($User.Name)\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        if (-not (Test-Path $SettingsPath)) { continue }
        try {
            $json = Get-Content $SettingsPath -Raw | ConvertFrom-Json
            $pwshProfile = $json.profiles.list | Where-Object { $_.commandline -eq $DefaultPwsh }
            if (-not $pwshProfile) {
                $guid = "{" + ([guid]::NewGuid()) + "}"
                $pwshProfile = @{ guid = $guid; name = "PowerShell ($PwshType)"; commandline = $DefaultPwsh }
                $json.profiles.list += $pwshProfile
            }
            $json.defaultProfile = $pwshProfile.guid
            $json | ConvertTo-Json -Depth 10 | Set-Content $SettingsPath -Encoding UTF8
        } catch {
            Write-Warn ("Terminal update failed for user {0}" -f $User.Name)
        }
    }

    #Write-Info "Configuring Windows Terminal default for new users..."
    $DefaultUserPath = "C:\Users\Default\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState"
    $DefaultSettings = Join-Path $DefaultUserPath "settings.json"
    if (-not (Test-Path $DefaultUserPath)) {
        New-Item -ItemType Directory -Path $DefaultUserPath -Force | Out-Null
    }
    if (-not (Test-Path $DefaultSettings)) {
        $guid = "{" + ([guid]::NewGuid()) + "}"
        @{
            defaultProfile = $guid
            profiles = @{
                list = @(
                    @{ guid = $guid; name = "PowerShell ($PwshType)"; commandline = $DefaultPwsh }
                )
            }
        } | ConvertTo-Json -Depth 10 | Set-Content $DefaultSettings -Encoding UTF8
    }

    #Write-Info "Updating Win+X menu shortcuts for all users..."
    $UserProfiles2 = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public", "Default User", "All Users") }

    foreach ($User in $UserProfiles2) {
        $winxPath = "C:\Users\$($User.Name)\AppData\Local\Microsoft\Windows\WinX"
        if (-not (Test-Path $winxPath)) { continue }
        try {
            $shortcuts = Get-ChildItem -Path $winxPath -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue
            foreach ($sc in $shortcuts) {
                $wshell = New-Object -ComObject WScript.Shell
                $shortcut = $wshell.CreateShortcut($sc.FullName)
                if ($shortcut.TargetPath -match "powershell.exe") {
                    $shortcut.TargetPath   = $DefaultPwsh
                    $shortcut.IconLocation = "$DefaultPwsh,0"
                    $shortcut.Save()
                    #Write-Info ("Updated Win+X shortcut for user {0}." -f $User.Name)
                }
            }
        } catch {
            Write-Warn ("Failed to update Win+X menu for user: {0}" -f $User.Name)
        }
    }
    Write-OK ("Win+X menu updated to use PowerShell ({0}) for all users." -f $PwshType)

    #Write-Info "Opting out of PowerShell telemetry..."
    try { [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine') } catch { }
    Write-OK "PowerShell 7 telemetry disabled."
}

function Invoke-CleanupItem {
    param([hashtable]$Item)

    switch ($Item.Type) {
        'Files' {
            return Remove-CleanupTarget -Paths $Item.Paths
        }
        'Registry' {
            $count = Clear-RegistryTree -RegPaths $Item.RegPaths -Recurse:$Item.Recurse
            return @{ Bytes = 0; Files = $count }
        }
        'Special' {
            return (& $Item.Action)
        }
        default {
            return @{ Bytes = 0; Files = 0 }
        }
    }
}

# ===========================================================================
# Category / item definitions
# (Only items that were CHECKED in the reference screenshots are included)
# ===========================================================================

$EdgeBase    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
$ChromeBase  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$FirefoxRoam = "$env:APPDATA\Mozilla\Firefox\Profiles"
$FirefoxLoc  = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"

$Categories = @(

    @{
        Heading = "Browsers"
        Items = @(
            # --- Edge Chromium ---
            @{ Name = "Internet Cache";          ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\*\Cache\Cache_Data\*", "$EdgeBase\*\Code Cache\*", "$EdgeBase\*\GPUCache\*") }
            @{ Name = "Cookies";                 ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\*\Network\Cookies", "$EdgeBase\*\Network\Cookies-journal") }
            @{ Name = "Internet History";        ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\*\History", "$EdgeBase\*\History-journal") }
            @{ Name = "Download History";        ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\*\Network\Downloads") }
            @{ Name = "Last Download Location";  ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @() }
            @{ Name = "Session";                 ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\*\Sessions\*", "$EdgeBase\*\Current Session", "$EdgeBase\*\Current Tabs", "$EdgeBase\*\Last Session", "$EdgeBase\*\Last Tabs") }
            # Saved Form Information: only stale journal file removed, real Web Data
            # (autofill) left untouched on purpose, same caution as passwords.
            @{ Name = "Saved Form Information";  ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\*\Web Data-journal") }
            @{ Name = "Compact Databases";        ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\*\*-journal") }
            @{ Name = "Metrics Temp Files";       ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\BrowserMetrics*", "$EdgeBase\*\BrowserMetrics*") }
            @{ Name = "Bookmarks Backup";         ReportCategory = "Edge Chromium"; Type = "Files"; Paths = @("$EdgeBase\*\Bookmarks.bak") }

            # --- Internet Explorer ---
            @{ Name = "Temporary Internet Files"; ReportCategory = "Internet Explorer"; Type = "Files";    Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*") }
            @{ Name = "History";                  ReportCategory = "Internet Explorer"; Type = "Files";    Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\History\*") }
            @{ Name = "Cookies";                  ReportCategory = "Internet Explorer"; Type = "Files";    Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\INetCookies\*", "$env:APPDATA\Microsoft\Windows\Cookies\*") }
            @{ Name = "Recently Typed URLs";       ReportCategory = "Internet Explorer"; Type = "Registry"; RegPaths = @("HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"); Recurse = $false }
            @{ Name = "Index.dat files";           ReportCategory = "Internet Explorer"; Type = "Files";    Paths = @("$env:USERPROFILE\Cookies\index.dat", "$env:LOCALAPPDATA\Microsoft\Windows\History\*\index.dat") }
            @{ Name = "Last Download Location";    ReportCategory = "Internet Explorer"; Type = "Files";    Paths = @() }

            # --- Google Chrome ---
            @{ Name = "Internet Cache";         ReportCategory = "Google Chrome"; Type = "Files"; Paths = @("$ChromeBase\*\Cache\Cache_Data\*", "$ChromeBase\*\Code Cache\*", "$ChromeBase\*\GPUCache\*") }
            @{ Name = "Internet History";       ReportCategory = "Google Chrome"; Type = "Files"; Paths = @("$ChromeBase\*\History", "$ChromeBase\*\History-journal") }
            @{ Name = "Cookies";                ReportCategory = "Google Chrome"; Type = "Files"; Paths = @("$ChromeBase\*\Network\Cookies", "$ChromeBase\*\Network\Cookies-journal") }
            @{ Name = "Download History";       ReportCategory = "Google Chrome"; Type = "Files"; Paths = @("$ChromeBase\*\Network\Downloads") }
            @{ Name = "Last Download Location";  ReportCategory = "Google Chrome"; Type = "Files"; Paths = @() }
            @{ Name = "Metrics Temp Files";      ReportCategory = "Google Chrome"; Type = "Files"; Paths = @("$ChromeBase\BrowserMetrics*", "$ChromeBase\*\BrowserMetrics*") }
            @{ Name = "Session";                ReportCategory = "Google Chrome"; Type = "Files"; Paths = @("$ChromeBase\*\Sessions\*", "$ChromeBase\*\Current Session", "$ChromeBase\*\Current Tabs", "$ChromeBase\*\Last Session", "$ChromeBase\*\Last Tabs") }
            @{ Name = "Compact Databases";       ReportCategory = "Google Chrome"; Type = "Files"; Paths = @("$ChromeBase\*\*-journal") }

            # --- Mozilla Firefox ---
            @{ Name = "Internet Cache"; ReportCategory = "Mozilla Firefox"; Type = "Files"; Paths = @("$FirefoxLoc\*\cache2\*", "$FirefoxLoc\*\startupCache\*") }
            @{ Name = "Cookies";        ReportCategory = "Mozilla Firefox"; Type = "Files"; Paths = @("$FirefoxRoam\*\cookies.sqlite", "$FirefoxRoam\*\cookies.sqlite-wal", "$FirefoxRoam\*\cookies.sqlite-shm") }
            @{ Name = "Session";        ReportCategory = "Mozilla Firefox"; Type = "Files"; Paths = @("$FirefoxRoam\*\sessionstore-backups\*", "$FirefoxRoam\*\sessionstore.jsonlz4") }
            @{ Name = "Saved Form History"; ReportCategory = "Mozilla Firefox"; Type = "Files"; Paths = @("$FirefoxRoam\*\formhistory.sqlite") }
            @{ Name = "Compact Databases";   ReportCategory = "Mozilla Firefox"; Type = "Files"; Paths = @("$FirefoxRoam\*\*.sqlite-wal", "$FirefoxRoam\*\*.sqlite-shm") }
            @{ Name = "Bookmarks Backup"; ReportCategory = "Mozilla Firefox"; Type = "Special"; Action = {
                    $bytes = 0L; $files = 0
                    $profiles = Get-ChildItem -Path $FirefoxRoam -Directory -ErrorAction SilentlyContinue
                    foreach ($p in $profiles) {
                        $backupDir = Join-Path $p.FullName "bookmarkbackups"
                        if (Test-Path $backupDir) {
                            $all = Get-ChildItem -Path $backupDir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
                            if ($all -and $all.Count -gt 1) {
                                $toRemove = $all | Select-Object -Skip 1
                                foreach ($f in $toRemove) {
                                    $bytes += $f.Length
                                    $files += 1
                                    if (-not $Script:DryRun) {
                                        Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
                                    }
                                }
                            }
                        }
                    }
                    return @{ Bytes = $bytes; Files = $files }
                }
            }
        )
    }

    @{
        Heading = "Windows Explorer"
        Items = @(
            @{ Name = "Recent Documents"; Type = "Special"; Action = {
                    $r1 = Remove-CleanupTarget -Paths @("$env:APPDATA\Microsoft\Windows\Recent\*.lnk")
                    $r2 = Clear-RegistryTree -RegPaths @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs") -Recurse
                    return @{ Bytes = $r1.Bytes; Files = ($r1.Files + $r2) }
                }
            }
            @{ Name = "Run (in Start Menu)";   Type = "Registry"; RegPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"); Recurse = $false }
            @{ Name = "Other Explorer MRUs";   Type = "Registry"; RegPaths = @(
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
                ); Recurse = $true
            }
            @{ Name = "Thumbnail Cache";   Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db", "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db") }
            @{ Name = "Taskbar Jump Lists"; Type = "Files"; Paths = @("$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*", "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*") }
        )
    }

    @{
        Heading = "System"
        Items = @(
            @{ Name = "Empty Recycle Bin"; Type = "Special"; SelfAttributesDrive = $true; Action = {
                    $totalBytes = 0L; $totalFiles = 0
                    try { $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue } catch { $drives = $null }
                    foreach ($d in $drives) {
                        $rbPath = Join-Path $d.DeviceID '$Recycle.Bin'
                        if (Test-Path $rbPath) {
                            try {
                                $files = Get-ChildItem -Path $rbPath -Recurse -Force -File -ErrorAction SilentlyContinue
                                if ($files) {
                                    $sum = $files | Measure-Object -Property Length -Sum
                                    if ($sum.Sum) { $totalBytes += $sum.Sum }
                                    $totalFiles += $sum.Count
                                    Add-DriveBytes -Drive $d.DeviceID -Bytes $sum.Sum
                                }
                            } catch { }
                        }
                    }
                    if (-not $Script:DryRun) {
                        try { Clear-RecycleBin -Force -ErrorAction SilentlyContinue } catch { }
                    }
                    return @{ Bytes = $totalBytes; Files = $totalFiles }
                }
            }
            @{ Name = "Temporary Files"; Type = "Files"; Paths = @("$env:TEMP\*", "$env:WINDIR\Temp\*") }
            @{ Name = "Clipboard"; Type = "Special"; Action = {
                    if (-not $Script:DryRun) {
                        try { Set-Clipboard -Value ([string]::Empty) -ErrorAction SilentlyContinue } catch { }
                        try { cmd /c "echo off | clip" } catch { }
                    }
                    return @{ Bytes = 0; Files = 0 }
                }
            }
            @{ Name = "Memory Dumps"; Type = "Files"; Paths = @("$env:WINDIR\Minidump\*", "$env:WINDIR\MEMORY.DMP", "$env:LOCALAPPDATA\CrashDumps\*") }
            @{ Name = "Chkdsk File Fragments"; Type = "Special"; SelfAttributesDrive = $true; Action = {
                    $totalBytes = 0L; $totalFiles = 0
                    try { $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue } catch { $drives = $null }
                    foreach ($d in $drives) {
                        $pattern = Join-Path $d.DeviceID 'FOUND.*'
                        $res = Remove-CleanupTarget -Paths @($pattern)
                        $totalBytes += $res.Bytes
                        $totalFiles += $res.Files
                        if ($res.Bytes -gt 0) { Add-DriveBytes -Drive $d.DeviceID -Bytes $res.Bytes }
                    }
                    return @{ Bytes = $totalBytes; Files = $totalFiles }
                }
            }
            @{ Name = "Windows Log Files"; Type = "Files"; Paths = @("$env:WINDIR\Logs\CBS\*.log", "$env:WINDIR\*.log", "$env:WINDIR\Logs\*") }
            @{ Name = "Windows Event Trace Logs"; Type = "Files"; Paths = @("$env:WINDIR\System32\LogFiles\WMI\*.etl", "$env:WINDIR\System32\LogFiles\WMI\RtBackup\*.etl") }
            @{ Name = "Windows Error Reporting"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\WER\*", "$env:ProgramData\Microsoft\Windows\WER\*") }
            @{ Name = "DNS Cache"; Type = "Special"; Action = {
                    if (-not $Script:DryRun) {
                        try { ipconfig /flushdns | Out-Null } catch { }
                    }
                    return @{ Bytes = 0; Files = 0 }
                }
            }
            @{ Name = "Windows Widgets"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Packages\MicrosoftWindows.Client.WebExperience_*\LocalCache\*") }
            @{ Name = "Start Menu Shortcuts"; Type = "Special"; Action = {
                    Remove-BrokenShortcuts -Folders @(
                        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
                        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
                    )
                }
            }
            @{ Name = "Desktop Shortcuts"; Type = "Special"; Action = {
                    Remove-BrokenShortcuts -Folders @(
                        "$env:USERPROFILE\Desktop",
                        "$env:PUBLIC\Desktop"
                    )
                }
            }
            @{ Name = "Driver Installation Log Files"; Type = "Files"; Paths = @("$env:WINDIR\inf\setupapi*.log") }
            @{ Name = "Windows Delivery Optimization"; Type = "Files"; Paths = @("$env:WINDIR\SoftwareDistribution\DeliveryOptimization\Cache\*") }
            @{ Name = "Windows Notifications"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\Notifications\wpndatabase.db") }
            @{ Name = "Network Data Usage"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\NetworkUsage\*") }
            @{ Name = "Windows Web Cache"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\WebCache\*") }
            @{ Name = "Windows Update Download Cache"; Type = "Special"; Action = {
                    $stoppedServices = @()
                    if (-not $Script:DryRun) {
                        foreach ($svc in @("wuauserv", "usosvc", "bits")) {
                            try {
                                $s = Get-Service -Name $svc -ErrorAction SilentlyContinue 
                                if ($s -and $s.Status -eq 'Running') {
                                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
                                    $stoppedServices += $svc
                                }
                            } catch { }
                        }
                    }
                    try {
                        $result = Remove-CleanupTarget -Paths @("$env:WINDIR\SoftwareDistribution\Download\*","$env:ProgramData\USOPrivate\*","$env:ProgramData\USOShared\*")
                    } finally {
                        # Always try to restart whatever we stopped, even if cleaning failed.
                        foreach ($svc in $stoppedServices) {
                            try { Start-Service -Name $svc -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null } catch { }
                        }
                    }
                    return $result
                }
            }
            @{ Name = "Previous Windows Installation (Windows.old)"; Type = "Special"; Action = {
                    $path = "$env:SystemDrive\Windows.old"
                    if (-not (Test-Path $path)) { return @{ Bytes = 0; Files = 0 } }

                    $bytes = 0L; $count = 0
                    try {
                        $files = Get-ChildItem -Path $path -Recurse -Force -File -ErrorAction SilentlyContinue
                        if ($files) {
                            $sum = $files | Measure-Object -Property Length -Sum
                            if ($sum.Sum) { $bytes = $sum.Sum }
                            $count = $sum.Count
                        }
                    } catch { }

                    if (-not $Script:DryRun -and (Test-IsAdmin)) {
                        try {
                            & takeown.exe /F $path /A /R /D Y 2>$null | Out-Null
                            & icacls.exe $path /grant "Administrators:F" /T 2>$null | Out-Null
                            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                        } catch { }
                    }
                    return @{ Bytes = $bytes; Files = $count }
                }
            }
            @{ Name = "Windows Upgrade Temp Files"; Type = "Files"; Paths = @(
                    "$env:SystemDrive\`$WINDOWS.~BT\*",
                    "$env:SystemDrive\`$Windows.~WS\*",
                    "$env:WINDIR\Panther\*"
                )
            }
        )
    }

    @{
        Heading = "Advanced"
        Items = @(
            @{ Name = "Windows Event Logs"; Type = "Special"; Action = {
                    $before = Get-ChildItem -Path "$env:WINDIR\System32\winevt\Logs\*.evtx" -ErrorAction SilentlyContinue
                    $beforeBytes = 0L
                    if ($before) {
                        $sum = $before | Measure-Object -Property Length -Sum
                        if ($sum.Sum) { $beforeBytes = $sum.Sum }
                    }
                    $count = 0
                    if (-not $Script:DryRun) {
                        try {
                            $logs = & wevtutil.exe el 2>$null
                            foreach ($log in $logs) {
                                try { & wevtutil.exe cl "$log" 2>$null; $count++ } catch { continue }
                            }
                        } catch { }
                    }
                    return @{ Bytes = $beforeBytes; Files = $count }
                }
            }
            @{ Name = "Old Prefetch data"; Type = "Files"; Paths = @("$env:WINDIR\Prefetch\*.pf") }
            @{ Name = "Menu Order Cache"; Type = "Registry"; RegPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder"); Recurse = $true }
            @{ Name = "Tray Notifications Cache"; Type = "Special"; Action = {
                    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\TrayNotify"
                    $count = 0
                    if (Test-Path $path) {
                        $props = (Get-Item -Path $path -Force -ErrorAction SilentlyContinue).Property
                        foreach ($name in @('IconStreams', 'PastIconsStream')) {
                            if ($props -contains $name) {
                                $count++
                                if (-not $Script:DryRun) {
                                    try { Remove-ItemProperty -Path $path -Name $name -Force -ErrorAction SilentlyContinue } catch { }
                                }
                            }
                        }
                    }
                    return @{ Bytes = 0; Files = $count }
                }
            }
            @{ Name = "Window Size/Location Cache"; Type = "Registry"; RegPaths = @(
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU",
                    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
                    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
                ); Recurse = $true
            }
            @{ Name = "Environment Path"; Type = "Special"; Action = {
                    $removed = 0
                    foreach ($scope in @('Machine', 'User')) {
                        try {
                            $raw = [Environment]::GetEnvironmentVariable('Path', $scope)
                            if (-not $raw) { continue }
                            $parts = $raw.Split(';') | Where-Object { $_ -ne '' }
                            $seen = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
                            $deduped = New-Object System.Collections.Generic.List[string]
                            $localRemoved = 0
                            foreach ($p in $parts) {
                                $trimmed = $p.TrimEnd('\')
                                if ($seen.Add($trimmed)) {
                                    $deduped.Add($p)
                                } else {
                                    $localRemoved++
                                }
                            }
                            $removed += $localRemoved
                            if ($localRemoved -gt 0 -and -not $Script:DryRun) {
                                $newVal = [string]::Join(';', $deduped)
                                try { [Environment]::SetEnvironmentVariable('Path', $newVal, $scope) } catch { }
                            }
                        } catch { continue }
                    }
                    return @{ Bytes = 0; Files = $removed }
                }
            }
            @{ Name = "User Assist History"; Type = "Registry"; RegPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"); Recurse = $true }
            @{ Name = "Custom Files and Folders"; Type = "Files"; Paths = $CustomCleanupPaths }
            @{ Name = "WebDAV Cache"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\WebDav Client Cache\*") }
        )
    }

    @{
        Heading = "Windows Store"
        Items = @(
            @{ Name = "Bing News";       Type = "Files"; Paths = @("$env:LOCALAPPDATA\Packages\Microsoft.BingNews_*\LocalCache\*") }
            @{ Name = "Microsoft To Do"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Packages\Microsoft.Todos_*\LocalCache\*") }
            @{ Name = "Photos Temp Files"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Packages\Microsoft.Windows.Photos_*\LocalCache\Temp\*") }
            @{ Name = "Snip & Sketch";   Type = "Files"; Paths = @("$env:LOCALAPPDATA\Packages\Microsoft.ScreenSketch_*\LocalCache\*") }
            @{ Name = "Sticky Notes";    Type = "Files"; Paths = @("$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_*\LocalCache\Temp\*") }
        )
    }

    @{
        Heading = "Applications"
        Items = @(
            @{ Name = "Apple Install Files";        Type = "Files"; Paths = @("$env:ProgramData\Apple\Installer Cache\*", "$env:LOCALAPPDATA\Apple Computer\Installer Cache\*") }
            @{ Name = "Microsoft OneDrive";         Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\OneDrive\logs\*", "$env:LOCALAPPDATA\Microsoft\OneDrive\setup\logs\*") }
            @{ Name = "MS Office Picture Manager";  Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Office\PictureManager\*") }
            @{ Name = "Microsoft Teams Cache"; Type = "Special"; Action = {
                    # Multi-user aware: when this runs as SYSTEM (e.g. via ManageEngine),
                    # $env:APPDATA/$env:LOCALAPPDATA point at the SYSTEM profile, not the
                    # real end users, so this loops over every profile under C:\Users instead.
                    $patterns = @()
                    try {
                        $userDirs = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
                        foreach ($u in $userDirs) {
                            $patterns += "$($u.FullName)\AppData\Roaming\Microsoft\Teams\Cache\*"
                            $patterns += "$($u.FullName)\AppData\Roaming\Microsoft\Teams\GPUCache\*"
                            $patterns += "$($u.FullName)\AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage\*"
                            $patterns += "$($u.FullName)\AppData\Local\Packages\MSTeams_*\LocalCache\*"
                        }
                    } catch { }
                    return Remove-CleanupTarget -Paths $patterns
                }
            }
            @{ Name = "Adobe Cache"; Type = "Special"; Action = {
                    $patterns = @()
                    try {
                        $userDirs = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
                        foreach ($u in $userDirs) {
                            $patterns += "$($u.FullName)\AppData\Local\Adobe\CameraRaw\Cache\*"
                            $patterns += "$($u.FullName)\AppData\Roaming\Adobe\Common\Media Cache Files\*"
                            $patterns += "$($u.FullName)\AppData\Roaming\Adobe\Common\Media Cache\*"
                        }
                    } catch { }
                    return Remove-CleanupTarget -Paths $patterns
                }
            }
        )
    }

    @{
        Heading = "Internet"
        Items = @(
            @{ Name = "Internet Download Manager"; Type = "Files"; Paths = @("$env:APPDATA\IDM\*.tmp", "$env:LOCALAPPDATA\IDM\*") }
            @{ Name = "Microsoft Family Safety";   Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Family Safety\*") }
        )
    }

    @{
        Heading = "Multimedia"
        Items = @(
            @{ Name = "Clipchamp - Video Editor"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\Packages\Clipchamp.Clipchamp_*\LocalCache\Local\Temp\*") }
            @{ Name = "Windows Media Player";      Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Media Player\*", "$env:APPDATA\Microsoft\Media Player\*.wmdb") }
        )
    }

    @{
        Heading = "Utilities"
        Items = @(
            @{ Name = "7-Zip";                       Type = "Files"; Paths = @("$env:TEMP\7z*") }
            @{ Name = "Windows Client Temp Files";   Type = "Files"; Paths = @("$env:WINDIR\Temp\*") }
            @{ Name = "Windows Defender";             Type = "Files"; Paths = @("$env:ProgramData\Microsoft\Windows Defender\Scans\History\*") }
        )
    }

    @{
        Heading = "Windows"
        Items = @(
            @{ Name = "DirectX Shader Cache"; Type = "Files"; Paths = @("$env:LOCALAPPDATA\D3DSCache\*") }
            @{ Name = "Game Explorer";        Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\GameExplorer\*") }
            @{ Name = "MS Search";            Type = "Files"; Paths = @("$env:LOCALAPPDATA\Microsoft\Windows\ConnectedSearch\*") }
            @{ Name = "RegEdit"; Type = "Special"; Action = {
                    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"
                    $count = 0
                    if (Test-Path $path) {
                        $props = (Get-Item -Path $path -Force -ErrorAction SilentlyContinue).Property
                        if ($props -contains 'LastKey') {
                            $count = 1
                            if (-not $Script:DryRun) {
                                try { Remove-ItemProperty -Path $path -Name 'LastKey' -Force -ErrorAction SilentlyContinue } catch { }
                            }
                        }
                    }
                    return @{ Bytes = 0; Files = $count }
                }
            }
            @{ Name = "Remote Desktop"; Type = "Registry"; RegPaths = @(
                    "HKCU:\Software\Microsoft\Terminal Server Client\Default",
                    "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
                ); Recurse = $true
            }
            # The two items below only run when the script is started with
            # -DisableTelemetry. They are policy/behavior changes, not junk
            # removal, so they are opt-in rather than part of routine cleanup
            # (important if this is pushed to many machines via ManageEngine).
            @{ Name = "Disable Consumer Features and Activity History"; Type = "Special"; Action = {
                    if (-not $Script:DisableTelemetry) { return @{ Bytes = 0; Files = 0 } }
                    $regs = @(
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableConsumerFeatures"; Value = 1 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableActivityFeed"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "UploadUserActivities"; Value = 0 }
                    )
                    $count = 0
                    foreach ($r in $regs) {
                        if (Set-RegValue -Path $r.Path -Name $r.Name -Value $r.Value -Type "DWord") { $count++ }
                    }
                    return @{ Bytes = 0; Files = $count }
                }
            }
            @{ Name = "Disable Telemetry"; Type = "Special"; Action = {
                    if (-not $Script:DisableTelemetry) { return @{ Bytes = 0; Files = 0 } }
                    $count = 0

                    $tasks = @(
                        "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                        "Microsoft\Windows\Application Experience\ProgramDataUpdater",
                        "Microsoft\Windows\Autochk\Proxy",
                        "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                        "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
                        "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
                        "Microsoft\Windows\Feedback\Siuf\DmClient",
                        "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
                        "Microsoft\Windows\Windows Error Reporting\QueueReporting",
                        "Microsoft\Windows\Application Experience\MareBackup",
                        "Microsoft\Windows\Application Experience\StartupAppTask",
                        "Microsoft\Windows\Application Experience\PcaPatchDbTask",
                        "Microsoft\Windows\Maps\MapsUpdateTask"
                    )
                    foreach ($t in $tasks) {
                        if (Disable-ScheduledTaskByPath -FullPath $t) { $count++ }
                    }

                    $regs = @(
                        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
                        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "ContentDeliveryAllowed"; Value = 0 },
                        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "OemPreInstalledAppsEnabled"; Value = 0 },
                        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEnabled"; Value = 0 },
                        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEverEnabled"; Value = 0 },
                        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 },
                        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SystemPaneSuggestionsEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name = "DisabledByGroupPolicy"; Value = 1 },
                        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1 },
                        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"; Name = "DODownloadMode"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name = "DODownloadMode"; Value = 0 },
                        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name = "fAllowToGetHelp"; Value = 0 },
                        @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData"; Value = 1 },
                        @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"; Name = "EnableFeeds"; Value = 0 }
                    )
                    foreach ($r in $regs) {
                        if (Set-RegValue -Path $r.Path -Name $r.Name -Value $r.Value -Type "DWord") { $count++ }
                    }

                    if (-not $Script:DryRun) {
                        try { & bcdedit.exe /set "{current}" bootmenupolicy Legacy | Out-Null; $count++ } catch { }

                        # NOTE: an earlier version of this item also wiped the entire
                        # HKLM:\SOFTWARE\Policies\Microsoft\Edge key to remove the
                        # "Managed by your organization" banner. That step was removed
                        # because the new "Edge Debloat Tweaks" item (below) sets 18
                        # policies back under that same key, which would re-trigger the
                        # banner immediately after wiping it. If removing the banner
                        # matters more to you than the Edge debloat policies, disable
                        # the Edge Debloat Tweaks item instead and re-add the wipe here.

                        try {
                            $ramKB = (Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue | Measure-Object -Property Capacity -Sum).Sum / 1KB
                            if ($ramKB -gt 0) {
                                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value ([int]$ramKB) -Force -ErrorAction SilentlyContinue
                                $count++
                            }
                        } catch { }

                        try {
                            $autoLoggerDir  = "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger"
                            $autoLoggerFile = Join-Path $autoLoggerDir "AutoLogger-Diagtrack-Listener.etl"
                            if (Test-Path $autoLoggerFile) {
                                Remove-Item -Path $autoLoggerFile -Force -ErrorAction SilentlyContinue
                            }
                            if (Test-Path $autoLoggerDir) {
                                & icacls.exe "$autoLoggerDir" /deny "SYSTEM:(OI)(CI)F" 2>$null | Out-Null
                                $count++
                            }
                        } catch { }

                        try {
                            Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
                            $count++
                        } catch { }
                    }

                    return @{ Bytes = 0; Files = $count }
                }
            }
            @{ Name = "Remove Bloatware Apps"; Type = "Special"; Action = {
                    if (-not $Script:DisableTelemetry) { return @{ Bytes = 0; Files = 0 } }
                    $appxList = @(
                        "Microsoft.AppConnector", "Microsoft.BingFinance", "Microsoft.BingNews",
                        "Microsoft.BingSports", "Microsoft.BingTranslator", "Microsoft.BingFoodAndDrink",
                        "Microsoft.BingHealthAndFitness", "Microsoft.BingTravel", "Microsoft.MinecraftUWP",
                        "Microsoft.MicrosoftSolitaireCollection", "Microsoft.News", "Microsoft.SkypeApp",
                        "Microsoft.Wallet", "Microsoft.Whiteboard", "*EclipseManager*", "*ActiproSoftwareLLC*",
                        "*Duolingo-LearnLanguagesforFree*", "*PandoraMediaInc*", "*CandyCrush*",
                        "*BubbleWitch3Saga*", "*Wunderlist*", "*Flipboard*", "*Twitter*", "*Facebook*",
                        "*Royal Revolt*", "*Sway*", "*Speed Test*", "*Viber*", "*Netflix*",
                        "*LinkedInforWindows*", "*HiddenCityMysteryofShadows*", "*Hulu*", "*HiddenCity*",
                        "*Microsoft.Advertising.Xaml*"
                    )
                    $count = 0
                    foreach ($pkg in $appxList) {
                        try {
                            $found = Get-AppxPackage -Name $pkg -AllUsers -ErrorAction SilentlyContinue
                            if ($found) {
                                $count += ($found | Measure-Object).Count
                                if (-not $Script:DryRun) {
                                    $found | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                                }
                            }
                        } catch { continue }
                    }
                    return @{ Bytes = 0; Files = $count }
                }
            }
            @{ Name = "Edge Debloat Tweaks"; Type = "Special"; Action = {
                    if (-not $Script:DisableTelemetry) { return @{ Bytes = 0; Files = 0 } }
                    $edgeTweaks = @(
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"; Name = "CreateDesktopShortcutDefault"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeEnhanceImagesEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "PersonalizationReportingEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "ShowRecommendationsEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "HideFirstRunExperience"; Value = 1 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "UserFeedbackAllowed"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "ConfigureDoNotTrack"; Value = 1 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "AlternateErrorPagesEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeCollectionsEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeFollowEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeShoppingAssistantEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "MicrosoftEdgeInsiderPromotionEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "ShowMicrosoftRewards"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "WebWidgetAllowed"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "DiagnosticData"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeAssetDeliveryServiceEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "CryptoWalletEnabled"; Value = 0 },
                        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "WalletDonationEnabled"; Value = 0 }
                    )
                    $count = 0
                    foreach ($t in $edgeTweaks) {
                        if (Set-RegValue -Path $t.Path -Name $t.Name -Value $t.Value -Type "DWord") { $count++ }
                    }
                    return @{ Bytes = 0; Files = $count }
                }
            }
        )
    }
)

# ===========================================================================
# Main execution
# ===========================================================================

Clear-Host
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  System Cleanup Utility" -ForegroundColor Cyan
if ($Script:DryRun) {
    Write-Host "  Mode: DRY RUN - nothing will be deleted, sizes only" -ForegroundColor Yellow
}
if ($Script:DisableTelemetry) {
    Write-Host "  Mode: Telemetry/Consumer-Features disabling ENABLED" -ForegroundColor Yellow
}
Write-Host "===============================================================" -ForegroundColor Cyan
if (-not (Test-IsAdmin)) {
    Write-Host "  WARNING: Not running as Administrator. Some items (Event Logs," -ForegroundColor Yellow
    Write-Host "  other users' Recycle Bin, Delivery Optimization cache, machine" -ForegroundColor Yellow
    Write-Host "  PATH cleanup, SSD TRIM) will be skipped automatically." -ForegroundColor Yellow
}
Write-Host ""

$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$BeforeSnapshot = Get-FixedDriveSnapshot

foreach ($category in $Categories) {
    $heading = $category.Heading
    $items   = $category.Items
    $total   = $items.Count
    if ($total -eq 0) { continue }

    $headingBytes = 0L
    $headingFiles = 0
    $color = Get-HeadingColor -Heading $heading

    Write-HeadingProgress -Heading $heading -PercentComplete 0 -Color $color
    for ($i = 0; $i -lt $total; $i++) {
        $item = $items[$i]

        try {
            $res = Invoke-CleanupItem -Item $item
        } catch {
            $res = @{ Bytes = 0; Files = 0 }
        }
        if (-not $res) { $res = @{ Bytes = 0; Files = 0 } }

        $headingBytes += $res.Bytes
        $headingFiles += $res.Files

        $selfAttrib = $false
        if ($item.ContainsKey('SelfAttributesDrive')) { $selfAttrib = $item.SelfAttributesDrive }
        if (-not $selfAttrib) {
            Add-DriveBytes -Drive $env:SystemDrive -Bytes $res.Bytes
        }

        $reportCategory = $heading
        if ($item.ContainsKey('ReportCategory')) { $reportCategory = $item.ReportCategory }

        $Script:Results.Add([PSCustomObject]@{
            Category = $reportCategory
            Item     = $item.Name
            Bytes    = $res.Bytes
            Files    = $res.Files
        })

        $pct = [int][math]::Round((($i + 1) / $total) * 100)
        Write-HeadingProgress -Heading $heading -PercentComplete $pct -Color $color
    }
    Write-Host ""
    $Script:TotalBytesCleaned += $headingBytes
}

$Stopwatch.Stop()
$AfterSnapshot = Get-FixedDriveSnapshot

# --- SSD TRIM ---
$TrimResults = @()
if (-not $Script:DryRun) {
    Write-Host ""
    Write-Host "Running TRIM on SSD volumes..." -ForegroundColor Cyan
    $MediaMap = Get-DriveMediaTypeMap
    $TrimResults = Invoke-SsdTrim -MediaMap $MediaMap -DriveLetters ($AfterSnapshot.Keys | Sort-Object)
}

# --- Build drive report ---
$DriveReport = @()
foreach ($driveLetter in ($BeforeSnapshot.Keys | Sort-Object)) {
    $before = $BeforeSnapshot[$driveLetter]
    $after  = $AfterSnapshot[$driveLetter]
    if (-not $after) { continue }

    $cleanedTracked = 0L
    $shortLetter = $driveLetter
    if ($Script:BytesByDrive.ContainsKey($driveLetter)) {
        $cleanedTracked = $Script:BytesByDrive[$driveLetter]
    }

    $diff      = $after.Free - $before.Free
    $usedAfter = $after.Total - $after.Free

    $DriveReport += [PSCustomObject]@{
        Drive      = $driveLetter
        TotalStr   = Format-Size $before.Total
        UsedStr    = Format-Size $usedAfter
        BeforeStr  = Format-Size $before.Free
        CleanedStr = Format-Size $cleanedTracked
        DiffStr    = Format-Size $diff
        DiffRaw    = $diff
    }
}

# ===========================================================================
# Final report
# ===========================================================================

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Green
if ($Script:DryRun) {
    Write-Host ("  DRY RUN COMPLETE - ({0:N3} seconds)" -f $Stopwatch.Elapsed.TotalSeconds) -ForegroundColor Yellow
    Write-Host ("  Would clean approximately: {0}" -f (Format-Size $Script:TotalBytesCleaned)) -ForegroundColor Yellow
} else {
    Write-Host ("  CLEANING COMPLETE - ({0:N3} seconds)" -f $Stopwatch.Elapsed.TotalSeconds) -ForegroundColor Green
    #Write-Host ("  Total Space Cleaned: {0}" -f (Format-Size $Script:TotalBytesCleaned)) -ForegroundColor Green
}
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Advanced Report" -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------------------" -ForegroundColor DarkGray

$shown = $Script:Results | Where-Object { $_.Bytes -gt 0 -or $_.Files -gt 0 }

if ($shown) {
    foreach ($r in $shown) {
        $rowColor = Get-HeadingColor -Heading $r.Category
        $label = "{0} - {1}" -f $r.Category, $r.Item

        Write-Host -NoNewline ("  {0,-50}" -f $label) -ForegroundColor $rowColor
        Write-Host -NoNewline (" {0,12}" -f (Format-Size $r.Bytes)) -ForegroundColor Green
        Write-Host (" {0,6} files" -f $r.Files) -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host ("=" * 77) -ForegroundColor DarkGray
    Write-Host -NoNewline ("  {0,-50}" -f "Total Space Cleaned:") -ForegroundColor Green
	Write-Host -NoNewline (" {0,12}" -f (Format-Size $Script:TotalBytesCleaned)) -ForegroundColor Green
	Write-Host ""
    Write-Host ("=" * 77) -ForegroundColor DarkGray
}
else {
    Write-Host "  Nothing required cleaning." -ForegroundColor DarkGray
}

if ($TrimResults.Count -gt 0) {
    Write-Host ""
    Write-Host "SSD TRIM Results" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------------------------------" -ForegroundColor DarkGray
    foreach ($t in $TrimResults) {
        $tColor = [ConsoleColor]::Yellow
        if ($t.Status -like "*completed*") { $tColor = [ConsoleColor]::Green }
        elseif ($t.Status -like "*failed*") { $tColor = [ConsoleColor]::Red }
        Write-Host ("  {0} : {1}" -f $t.Drive, $t.Status) -ForegroundColor $tColor
    }
}

# ===========================================================================
# PowerShell 7 Setup, Recall toggle, Laptop hibernation defaults
# (opt-in only: -SetupPwsh7 / -DisableRecall / -EnableRecall / -LaptopMode)
# ===========================================================================

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  PowerShell 7 Setup" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Invoke-Pwsh7Setup
Disable-WindowsRecall
Set-LaptopHibernationDefaults
if ($Script:EnableRecall)  { Enable-WindowsRecall }

# ===========================================================================
# Final Result
# ===========================================================================

Write-Host ""
Write-Host "==============================" -ForegroundColor White
Write-Host " FINAL RESULT" -ForegroundColor Cyan
Write-Host (" Total disk space freed: {0}" -f (Format-Size $Script:TotalBytesCleaned)) -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor White
if ($Script:TotalBytesCleaned -eq 0) {
    Write-Host ""
    Write-Host "Nothing significant found to clean." -ForegroundColor DarkYellow
}

foreach ($d in ($DriveReport | Sort-Object Drive)) {
    $diffColor = [ConsoleColor]::Green
    $label = "Freed"
    if ($d.DiffRaw -lt 0) { $diffColor = [ConsoleColor]::Red; $label = "Used" }

    $afterFreeStr = $d.BeforeStr
    if ($AfterSnapshot.ContainsKey($d.Drive)) {
        $afterFreeStr = Format-Size $AfterSnapshot[$d.Drive].Free
    }

    Write-Host ""
    Write-Host ("Drive {0}" -f $d.Drive) -ForegroundColor White
    Write-Host ("  Before Cleanup - Free Space: {0}" -f $d.BeforeStr)
    Write-Host ("  After Cleanup  - Free Space: {0}" -f $afterFreeStr)
    Write-Host -NoNewline ("  Difference     - {0}: " -f $label)
    Write-Host (Format-Size ([math]::Abs($d.DiffRaw))) -ForegroundColor $diffColor
}

Write-Host ""
Write-Host "------------------------------" -ForegroundColor DarkGray

$sumOfDifferences = 0L
foreach ($d in $DriveReport) { $sumOfDifferences += $d.DiffRaw }

$avgUsedPercent = 0
try {
    $disksNow = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    $pcts = @()
    foreach ($dk in $disksNow) {
        if ($dk.Size -gt 0) { $pcts += (($dk.Size - $dk.FreeSpace) / $dk.Size) * 100 }
    }
    if ($pcts.Count -gt 0) { $avgUsedPercent = ($pcts | Measure-Object -Average).Average }
} catch { }

Write-Host ""
Write-Host "[Summary Comparison]" -ForegroundColor White
Write-Host -NoNewline "  Reported per-drive freed space         : "
Write-Host (Format-Size $sumOfDifferences) -ForegroundColor Yellow
Write-Host -NoNewline "  Total deleted file size (tracked)      : "
Write-Host (Format-Size $Script:TotalBytesCleaned) -ForegroundColor Cyan
Write-Host -NoNewline "  Difference (if any)                    : "
Write-Host (Format-Size ($Script:TotalBytesCleaned - $sumOfDifferences)) -ForegroundColor Gray
Write-Host ("  Avg. Drive Utilization After Cleanup   : {0:N1} %" -f $avgUsedPercent) -ForegroundColor DarkCyan
Write-Host "------------------------------" -ForegroundColor DarkGray

Show-DriveStatusReport

Write-Host ""
Write-Host "==============================" -ForegroundColor White
Write-Host "System cleaned" -ForegroundColor DarkYellow
Write-Host "==============================" -ForegroundColor White
if ($Script:DisableTelemetry -and -not $Script:DryRun) {
    Write-Host "A restart is recommended (telemetry/policy and SSD TRIM changes need a restart to fully apply)." -ForegroundColor Yellow
}

Write-Host ""