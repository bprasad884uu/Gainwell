<## Ensure PowerShell Runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}#>
# Increase simultaneous connections and reduce Expect:100-continue overhead
[System.Net.ServicePointManager]::DefaultConnectionLimit = 1000
[System.Net.ServicePointManager]::Expect100Continue = $false

$ErrorActionPreference = "Stop"

# ---------- Config (fill these) ----------
$isoUrl_EN_US  = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_English_x64.iso?t=f6f81e9b-6ebe-4068-9f0d-68b4d88a830e&P1=1765463315&P2=601&P3=2&P4=0NSBN4kg12t8Oz2AlhIHwtqC6ImMsW6H%2bK%2fsj8mv08eOI5hK78dR%2bywcJX4XkoLtMOQSHtBg5jolYdF8jwzxrKsAOBLQmPBhEJKaqljM0YXUuE7TSvGid9%2ftqehCrggISJFPIXRgvCX2y779K8JjC%2feua5zjCyU7uqwbZqEoGvXHuakf0yqFNZLYht%2bBWFIFK0%2bdXo6UH4ZS2uTAz5DsRgsiJb%2f1RDLyEi7CilSDRG5%2bMuX7Cs49fdfTw8yvesjvt4Cc6zp5mL%2f6W%2fNfg1s82jJr07%2fB7%2fkcqIy73DdGmSIGZr1HQlXLKVfIqOSr58p5YZvX4%2bsVmvamNOgaHGcJ7g%3d%3d"
$isoUrl_EN_GB  = "h"

# Minimum free space for temp selection (40 GB default)
$MinimumTempBytes = (40 * 1024 * 1024 * 1024)

# ---------- Detect Installed Language ----------
$locale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''
switch ($locale) {
    "en-GB" { $languageName = "English (UK)"; $isoUrl = $isoUrl_EN_GB; $destinationName = "Win11_25H2_ENGB.iso" }
    "en-US" { $languageName = "English (US)"; $isoUrl = $isoUrl_EN_US; $destinationName = "Win11_25H2_ENUS.iso" }
    default { $languageName = $locale; Write-Warning "Unsupported/unknown language ($locale). Defaulting to en-US."; $isoUrl = $isoUrl_EN_US; $destinationName = "Win11_25H2.iso" }
}
Write-Host "Detected Language: $languageName"

# --- Choose Temp location: prefer C: if it has >= MinimumBytes, otherwise find another drive ---
function Select-TempRoot {
    param([long]$MinimumBytes = (40 * 1024 * 1024 * 1024))
    try {
        $envTempRoot = [System.IO.Path]::GetPathRoot($env:TEMP)
        if ($envTempRoot) {
            $deviceId = $envTempRoot.TrimEnd('\')
            $logical = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID = '$deviceId'" -ErrorAction SilentlyContinue
            if ($logical -and $logical.FreeSpace -ge $MinimumBytes) { return $env:TEMP.TrimEnd('\') }
        }
    } catch { }

    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Sort-Object -Property DeviceID
    foreach ($d in $drives) {
        if ($d.FreeSpace -ge $MinimumBytes) {
            $root = "$($d.DeviceID)\"
            $candidateTemp = Join-Path -Path $root -ChildPath "Temp"
            try {
                if (-not (Test-Path $candidateTemp)) { New-Item -Path $candidateTemp -ItemType Directory -Force | Out-Null }
                $testFile = Join-Path $candidateTemp ".__writetest.tmp"
                Set-Content -Path $testFile -Value "ok" -ErrorAction Stop
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                return $candidateTemp.TrimEnd('\')
            } catch { continue }
        }
    }
    return $env:TEMP.TrimEnd('\')
}

$TempRoot = Select-TempRoot -MinimumBytes $MinimumTempBytes
if ($TempRoot -match "^[A-Za-z]:$") {
    $TempRoot = Join-Path $TempRoot "Temp"
    if (-not (Test-Path $TempRoot)) { New-Item -Path $TempRoot -ItemType Directory -Force | Out-Null }
}
Write-Host "`nUsing temp root: $TempRoot"
$destination = Join-Path -Path $TempRoot -ChildPath $destinationName

# ---------- Helpers ----------
function Format-Size { param([long]$bytes)
    if ($bytes -ge 1GB) { "{0:N2} GB" -f ($bytes / 1GB) }
    elseif ($bytes -ge 1MB) { "{0:N2} MB" -f ($bytes / 1MB) }
    elseif ($bytes -ge 1KB) { "{0:N2} KB" -f ($bytes / 1KB) } else { "$bytes B" }
}
function Format-Speed { param([double]$bytesPerSecond)
    if ($bytesPerSecond -ge 1GB) { "{0:N2} GB/s" -f ($bytesPerSecond / 1GB) }
    elseif ($bytesPerSecond -ge 1MB) { "{0:N2} MB/s" -f ($bytesPerSecond / 1MB) }
    elseif ($bytesPerSecond -ge 1KB) { "{0:N2} KB/s" -f ($bytesPerSecond / 1KB) } else { "{0:N2} B/s" -f $bytesPerSecond }
}
function Format-ETA { param([double]$seconds)
    if ($seconds -lt 0 -or [double]::IsNaN($seconds)) { return "Unknown" }
    $s = [math]::Round($seconds)
    $h = [math]::Floor($s / 3600); $m = [math]::Floor(($s % 3600) / 60); $sec = $s % 60
    $parts = @(); if ($h -gt 0) { $parts += "${h}h" }; if ($m -gt 0) { $parts += "${m}m" }; $parts += "${sec}s"
    return ($parts -join ' ')
}

# ---------- Download with resume support (32 parallel, speed-based reallocation by blocks) ----------
function Download-WithResume {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [int]$MaxParallel = 32,
        [int]$AttemptsPerPart = 3,
        [long]$BlockSizeBytes = (16 * 1024 * 1024)  # 16 MB per block
    )

    if (-not ("System.Net.Http.HttpClient" -as [type])) {
        Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue
    }

    # Block file name == metadata (start/end ranges encoded)
    function Get-BlockPath {
        param(
            [string]$SegmentFolder,
            [string]$BaseName,
            [int]   $Index,
            [long]  $Start,
            [long]  $End
        )
        $name = "{0}.blk{1:D6}_{2:D016}_{3:D016}.part" -f $BaseName, $Index, $Start, $End
        return (Join-Path $SegmentFolder $name)
    }

    Write-Host "`nPreparing download:`n"

    $tmpFolder = [System.IO.Path]::GetDirectoryName($OutFile)
    if (-not (Test-Path $tmpFolder)) { New-Item -Path $tmpFolder -ItemType Directory -Force | Out-Null }

    # IDM-style segment folder: Temp\DwnlData\<FileNameWithoutExt>
    $segmentRoot   = Join-Path $tmpFolder "DwnlData"
    $baseNameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($OutFile)
    $segmentFolder = Join-Path $segmentRoot $baseNameNoExt

    if (-not (Test-Path $segmentFolder)) {
        New-Item -Path $segmentFolder -ItemType Directory -Force | Out-Null
    }

    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [System.TimeSpan]::FromHours(4)

    try {
        # ---- Probe server for length + ranges ----
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, $Url)
        try {
            $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
        } catch {
            $req.Dispose()
            $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Url)
            $req.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new(0,0)
            $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
        }

        $acceptRanges = $false
        if ($resp.Headers.Contains("Accept-Ranges")) {
            $val = ($resp.Headers.GetValues("Accept-Ranges") | Select-Object -First 1)
            if ($val -match "bytes") { $acceptRanges = $true }
        } elseif ($resp.Content.Headers.ContentRange -ne $null -and $resp.Content.Headers.ContentRange.Unit -eq "bytes") {
            $acceptRanges = $true
        }

        $remoteLength = $null
        if ($resp.Content.Headers.ContentLength -ne $null) {
            $remoteLength = [long]$resp.Content.Headers.ContentLength
        } elseif ($resp.Content.Headers.ContentRange -ne $null -and $resp.Content.Headers.ContentRange.Length -ne $null) {
            $remoteLength = [long]$resp.Content.Headers.ContentRange.Length
        }

        $resp.Dispose()

        if (-not $remoteLength -or $remoteLength -le 0) {
            throw "Could not determine remote file size."
        }

        if (-not $acceptRanges) {
            throw "Server does not support ranged requests. Parallel download not possible."
        }

        Write-Host "Server supports ranges. Size: $(Format-Size $remoteLength). MaxParallel: $MaxParallel`n"

        # If final ISO exists and size exact match -> skip
        if (Test-Path $OutFile) {
            $existingLength = (Get-Item $OutFile).Length
            if ($existingLength -eq $remoteLength) {
                Write-Host "File already present with correct size. Skipping download."
                return
            } else {
                Write-Host "Existing ISO size differs; removing ISO but keeping any block parts for resume."
                Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
            }
        }

        # ---------- Build block list ----------
        if ($BlockSizeBytes -lt 1024*1024) { $BlockSizeBytes = 1024*1024 } # minimum 1 MB
        $blocks = @()
        $blockIndex = 0
        $totalBlocks = [math]::Ceiling($remoteLength / $BlockSizeBytes)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutFile)

        for ($start = 0; $start -lt $remoteLength; $start += $BlockSizeBytes) {
            $end = [long]($start + $BlockSizeBytes - 1)
            if ($end -ge $remoteLength) { $end = [long]($remoteLength - 1) }

            $expectedSize = [long]($end - $start + 1)
            $path = Get-BlockPath -SegmentFolder $segmentFolder -BaseName $baseName -Index $blockIndex -Start $start -End $end

            $existing = 0
            $completed = $false

            if (Test-Path $path) {
                $existing = (Get-Item $path).Length
                if ($existing -gt $expectedSize) {
                    # corrupt / oversize -> reset
                    Remove-Item $path -Force -ErrorAction SilentlyContinue
                    $existing  = 0
                    $completed = $false
                } elseif ($existing -ge $expectedSize) {
                    $completed = $true
                }
            }

            $blocks += [pscustomobject]@{ Index = $blockIndex; Start = [long]$start; End = [long]$end; ExpectedSize = $expectedSize; Path = $path; Existing = $existing; Completed = $completed }
            $blockIndex++
        }

        # Resume check: if all blocks exist and match size, stitch only
        $allComplete = $true
        foreach ($b in $blocks) {
            if (-not $b.Completed) { $allComplete = $false; break }
        }

        # ---------- Parallel download using runspace pool ----------
        $minThreads = 1
        $maxThreads = [int]([System.Math]::Max([double]1, [double]$MaxParallel))
        $rsp = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($minThreads, $maxThreads)
        $rsp.ThreadOptions = "ReuseThread"
        $rsp.Open()

        $jobs = @()

        if (-not $allComplete) {
            foreach ($b in $blocks) {
                if ($b.Completed -or $b.ExpectedSize -le 0) { continue }

                $ps = [System.Management.Automation.PowerShell]::Create()
                $ps.RunspacePool = $rsp

                $script = {
                    param($Url, $path, $start, $end, $existing, $idx, $attempts)

                    try {
                        if (-not ("System.Net.Http.HttpClient" -as [type])) {
                            Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue
                        }
                        $try = 0
                        while ($true) {
                            $try++
                            try {
                                $resumeStart = [long]($start + $existing)
                                if ($resumeStart -gt $end) {
                                    return @{ Index = $idx; Success = $true; Error = $null }
                                }

                                $clientInner = [System.Net.Http.HttpClient]::new()
                                $clientInner.Timeout = [System.TimeSpan]::FromHours(4)

                                $reqInner = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Url)
                                $reqInner.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($resumeStart, $end)

                                $respInner = $clientInner.SendAsync($reqInner, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
                                if ($respInner.StatusCode -ne [System.Net.HttpStatusCode]::PartialContent -and
                                    $respInner.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                                    throw "HTTP $($respInner.StatusCode) $($respInner.ReasonPhrase)"
                                }

                                $stream = $respInner.Content.ReadAsStreamAsync().Result

                                if ($existing -gt 0 -and (Test-Path $path)) {
                                    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                                    $fs.Seek(0, 'End') | Out-Null
                                } else {
                                    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                                }

                                $buffer = New-Object byte[] (8 * 1024 * 1024) # 8MB buffer
                                while (($r = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                                    $fs.Write($buffer, 0, $r)
                                }

                                $fs.Close()
                                $stream.Close()
                                $respInner.Dispose()
                                $clientInner.Dispose()

                                return @{ Index = $idx; Success = $true; Error = $null }
                            } catch {
                                $err = $_.ToString()
                                if ($try -ge $attempts) {
                                    if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
                                    return @{ Index = $idx; Success = $false; Error = $err }
                                } else {
                                    Start-Sleep -Seconds (2 * $try)
                                    continue
                                }
                            }
                        }
                    } catch {
                        if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
                        return @{ Index = $idx; Success = $false; Error = $_.ToString() }
                    }
                }

                $async = $ps.AddScript($script).AddArgument($Url).AddArgument($b.Path).AddArgument($b.Start).AddArgument($b.End).AddArgument($b.Existing).AddArgument($b.Index).AddArgument($AttemptsPerPart).BeginInvoke()

                $jobs += [pscustomobject]@{
                    PS = $ps
                    Async = $async
                    Block = $b
                }
            }

            # ---------- Progress loop ----------
            $lastTotal = 0
            $lastTime = (Get-Date).AddSeconds(-1)
            $avgSpeedSamples = New-Object System.Collections.Queue
            $maxSamples = 5

            while ($true) {
                $now = Get-Date
                $totalDownloaded = 0

                foreach ($b in $blocks) {
                    $len = 0
                    if ($b.Path -and (Test-Path $b.Path)) {
                        $len = (Get-Item $b.Path).Length
                    }
                    if ($len -ge $b.ExpectedSize) { $b.Completed = $true }
                    $totalDownloaded += $len
                }

                $deltaBytes = $totalDownloaded - $lastTotal
                $deltaTime = ($now - $lastTime).TotalSeconds
                if ($deltaTime -lt 0.5) { $deltaTime = 0.5 }
                $instantSpeed = if ($deltaTime -gt 0) { $deltaBytes / $deltaTime } else { 0 }

                $avgSpeedSamples.Enqueue($instantSpeed)
                if ($avgSpeedSamples.Count -gt $maxSamples) { [void]$avgSpeedSamples.Dequeue() }
                $avgSpeed = ($avgSpeedSamples | Measure-Object -Average).Average
                if (-not $avgSpeed) { $avgSpeed = 0 }

                $remainingBytes = [System.Math]::Max([double]0, [double]($remoteLength - $totalDownloaded))
                $eta = if ($remainingBytes -le 0) {
                    "0s"
                } elseif ($avgSpeed -gt 0) {
                    Format-ETA ($remainingBytes / $avgSpeed)
                } else {
                    "Unknown"
                }

                $progressPct = if ($remoteLength -gt 0) {
                    [math]::Round(($totalDownloaded / $remoteLength) * 100, 2)
                } else { 0 }

                if ($progressPct -gt 100) { $progressPct = 100 }
                if ($progressPct -lt 0)   { $progressPct = 0 }

                $downloadedText = "$(Format-Size $totalDownloaded) / $(Format-Size $remoteLength) ($progressPct`%)"
                $speedText = "$(Format-Speed $avgSpeed)"
                $etaText = $eta

                Write-Host -NoNewline "`rDownloaded: $downloadedText | Speed: $speedText | ETA: $etaText   "

                $lastTotal = $totalDownloaded
                $lastTime = $now

                $allDone = $true
                foreach ($j in $jobs) {
                    if (-not $j.Async.IsCompleted) { $allDone = $false; break }
                }
                if ($allDone) { break }

                Start-Sleep -Seconds 1
            }
            Write-Host ""

            # ---------- Collect results ----------
            $errors = @()
            foreach ($j in $jobs) {
                try {
                    $res = $j.PS.EndInvoke($j.Async)
                    $j.PS.Dispose()

                    $blk = $j.Block
                    $actualLen = 0
                    if ($blk.Path -and (Test-Path $blk.Path)) {
                        $actualLen = (Get-Item $blk.Path).Length
                    }

                    if ($actualLen -lt $blk.ExpectedSize) {
                        $errors += "Block $($blk.Index) too small: expected $(Format-Size $($blk.ExpectedSize)), actual $(Format-Size $actualLen)"
                    }

                    if ($res -and $res.Success -ne $true) {
                        $errors += "Block $($blk.Index) error: $($res.Error)"
                    }
                } catch {
                    $blk = $j.Block
                    $actualLen = 0
                    if ($blk.Path -and (Test-Path $blk.Path)) {
                        $actualLen = (Get-Item $blk.Path).Length
                    }
                    if ($actualLen -lt $blk.ExpectedSize) {
                        $errors += "Block $($blk.Index) runspace failure: $_"
                    }
                }
            }

            if ($errors.Count -gt 0) {
                throw "One or more blocks failed: $($errors -join '; ')"
            }
        }

        try { $rsp.Close(); $rsp.Dispose() } catch {}

        # Final verify: sab blocks present + size OK?
        foreach ($b in $blocks) {
            $len = 0
            if ($b.Path -and (Test-Path $b.Path)) {
                $len = (Get-Item $b.Path).Length
            }
            if ($len -lt $b.ExpectedSize) {
                throw "Block $($b.Index) incomplete even after download. Run again to resume."
            }
        }

        # ---------- Stitch blocks into final file (with progress bar) ----------
        Write-Host "`nStitching parts into final file..."

        $blocksSorted = $blocks | Sort-Object Start
        $totalToWrite = 0
        foreach ($b in $blocksSorted) {
            if ($b.Path -and (Test-Path $b.Path)) {
                $totalToWrite += (Get-Item $b.Path).Length
            }
        }

        if ($totalToWrite -le 0) {
            Write-Warning "No block files found to stitch."
            return
        }

        $outStream = [System.IO.File]::Open(
            $OutFile,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )

        $written  = 0
        $barWidth = 50
        $emptyBar = "[" + "".PadRight($barWidth, ' ') + "]"
        Write-Host -NoNewline $emptyBar

        foreach ($b in $blocksSorted) {
            $pf = $b.Path
            if (-not ($pf -and (Test-Path $pf))) { continue }

            $inStream = [System.IO.File]::Open(
                $pf,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            )

            $buf = New-Object byte[] (16 * 1024 * 1024) # 16MB buffer
            while (($r = $inStream.Read($buf, 0, $buf.Length)) -gt 0) {
                $outStream.Write($buf, 0, $r)
                $written += $r

                if ($totalToWrite -gt 0) {
                    $ratio = [double]$written / [double]$totalToWrite
                    if ($ratio -lt 0) { $ratio = 0 }
                    if ($ratio -gt 1) { $ratio = 1 }

                    $filled = [int]([math]::Floor($ratio * $barWidth))
                    if ($filled -lt 0) { $filled = 0 }
                    if ($filled -gt $barWidth) { $filled = $barWidth }

                    if ($filled -ge $barWidth) {
                        $barBody = "".PadRight($barWidth, '=')
                    } else {
                        $eqCount = $filled
                        if ($eqCount -lt 0) { $eqCount = 0 }
                        $spaces = $barWidth - $eqCount - 1
                        if ($spaces -lt 0) { $spaces = 0 }

                        $barBody = "".PadRight($eqCount, '=') + ">" + "".PadRight($spaces, ' ')
                    }

                    $bar = "[" + $barBody + "]"
                    Write-Host -NoNewline ("`r" + $bar)
                }
            }

            $inStream.Close()
            Remove-Item $pf -Force -ErrorAction SilentlyContinue
        }

        $outStream.Close()

        $finalBarBody = "".PadRight($barWidth, '=')
        $finalBar = "[" + $finalBarBody + "]"
        Write-Host -NoNewline ("`r" + $finalBar)
        Write-Host ""

        # Delete DwnlData\<filename> folder, and if DwnlData is empty, remove it as well
        try {
            if (Test-Path $segmentFolder) {
                Remove-Item $segmentFolder -Recurse -Force -ErrorAction SilentlyContinue
            }

            if (Test-Path $segmentRoot) {
                $remaining = Get-ChildItem $segmentRoot -Recurse -ErrorAction SilentlyContinue
                if (-not $remaining) {
                    Remove-Item $segmentRoot -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Write-Warning "Failed to cleanup DwnlData folder: $_"
        }

        Write-Host "`nDownload complete: $OutFile"
    }
    catch {
        throw "Download error: $_"
    }
    finally {
        if ($client) { $client.Dispose() }
    }
}

# ---------- Step 0: If file exists, try mount to verify; otherwise download with resume ----------
$downloadSuccess = $false
if (Test-Path $destination) {
    Write-Host "`nFile already exists: $destination"
    Write-Host "`nAttempting to mount to verify integrity..."
    try {
        $null = Mount-DiskImage -ImagePath $destination -ErrorAction Stop -PassThru
        $null = Dismount-DiskImage -ImagePath $destination -ErrorAction SilentlyContinue
        Write-Host "`nISO mounted and dismounted successfully. Integrity OK."
        $downloadSuccess = $true
    } catch {
        Write-Warning "Existing ISO failed to mount. Will re-download/resume."
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
    }
}

if (-not $downloadSuccess) {
    try {
        Write-Host "`nStarting download..."
        # Fixed 32 segments behaviour. MaxParallel = 32 by default, but you can pass a lower value.
        Download-WithResume -Url $isoUrl -OutFile $destination -MaxParallel 32
    } catch {
        Write-Error "Download flow failed: $_"
        exit 1
    }
}

# ---------- Step 2: Mount ISO (clean unmount first) ----------
Write-Host "`nUnmounting any ISO images previously mounted..."
$volumes = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }

foreach ($volume in $volumes) {
    try {
        $devicePath = "\\.\$($volume.DriveLetter):"
        Write-Host "`nAttempting to dismount image mounted at: $devicePath"
        $null = Dismount-DiskImage -DevicePath $devicePath -ErrorAction Stop
        Write-Host "`nSuccessfully dismounted: $devicePath"
    } catch {
        Write-Warning "`nFailed to dismount: $devicePath. Error: $_"
    }
}

$isoPath = Get-ChildItem -Path ($TempRoot + '\') -Filter "Win11*.iso" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
if (-not $isoPath -and (Test-Path $destination)) { $isoPath = $destination }
if (-not $isoPath) { Write-Host "`nNo ISO file found in Temp Folder ($TempRoot)." -ForegroundColor Red; exit 1 }

Write-Host "`nISO found: $isoPath"
try {
    $null = Mount-DiskImage -ImagePath $isoPath -ErrorAction Stop -PassThru
    Start-Sleep -Seconds 2
    $vol = Get-DiskImage -ImagePath $isoPath | Get-Volume -ErrorAction SilentlyContinue
    if ($vol -and $vol.DriveLetter) {
        $driveLetter = $vol.DriveLetter
        Write-Host "Mounted at $driveLetter`:"
    } else { Write-Warning "Mounted but couldn't detect drive letter." }
} catch {
    Write-Error "Failed to mount ISO: $_"; exit 1
}

$setupPath = "$driveLetter`:\setup.exe"
if (-not (Test-Path $setupPath)) { Write-Error "setup.exe not found on ISO. Exiting."; exit 1 }

# ---------- Step 3: Windows 11 upgrade (Silent Install) ----------
# Get Manufacturer
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
Write-Host "`nDetected System Manufacturer: $manufacturer"

# CPU lists (WhyNotWin11)
$intelListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsIntel.txt"
$amdListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsAMD.txt"
$qualcommListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsQualcomm.txt"

# Get raw CPU name
$cpu = Get-CimInstance -ClassName Win32_Processor
$rawCpuName = $cpu.Name.Trim()

# Extract clean CPU model string
if ($rawCpuName -match "Core\(TM\)\s+i[3579]-\S+") {
    $cleanCpuName = $matches[0]
} elseif ($rawCpuName -match "Core\s+i[3579]-\S+") {
    $cleanCpuName = $matches[0] -replace "Core", "Core(TM)"
} elseif ($rawCpuName -match "AMD\s+Ryzen\s+\d+\s+\d{4}") {
    $cleanCpuName = $matches[0] -replace "^AMD\s+", ""
} elseif ($rawCpuName -match "AMD\s+Ryzen\s+\S+") {
    $cleanCpuName = $matches[0]
} elseif ($rawCpuName -match "Qualcomm\s+\S+") {
    $cleanCpuName = $matches[0]
} elseif ($rawCpuName -match "Xeon\(R\)\s+CPU\s+([A-Za-z0-9\-]+)") {
    $cleanCpuName = "Xeon " + $matches[1]
} else {
    $cleanCpuName = ""
}
if (-not $cleanCpuName) {
    Write-Host "`nCould not extract a matching CPU model from '$rawCpuName'" -ForegroundColor Yellow
    $cleanCpuName = $rawCpuName
}

# Load System.Net.Http.dll for PowerShell 5.1 if needed
if (-not ("System.Net.Http.HttpClient" -as [type])) { Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue }

# Download CPU lists
try {
    $hc = New-Object System.Net.Http.HttpClient
    $intelList = ($hc.GetStringAsync($intelListUrl).Result -split "`n") | ForEach-Object { $_.Trim() }
    $amdList = ($hc.GetStringAsync($amdListUrl).Result -split "`n") | ForEach-Object { $_.Trim() }
    $qualList = ($hc.GetStringAsync($qualcommListUrl).Result -split "`n") | ForEach-Object { $_.Trim() }
    $hc.Dispose()
} catch {
    Write-Warning "Failed to download processor support lists. Proceeding without list-based CPU check."
    $intelList = @(); $amdList = @(); $qualList = @()
}

# Determine manufacturer and check support
$cpuSupported = $false
switch -Regex ($cpu.Manufacturer) {
    "Intel"    { $cpuSupported = $intelList -contains $cleanCpuName }
    "AMD"      { $cpuSupported = $amdList -contains $cleanCpuName }
    "Qualcomm" { $cpuSupported = $qualList -contains $cleanCpuName }
    default    { Write-Host "`nUnknown manufacturer: $($cpu.Manufacturer)" }
}

# Function to check TPM 2.0
function Check-TPM {
    try {
        $tpm = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
        if ($tpm -and $tpm.SpecVersion) { return $tpm.SpecVersion -match "2.0" }
    } catch {}
    return $false
}

# Check architecture and speed
$cpu64Bit = ($cpu.AddressWidth -eq 64)
$cpuSpeedGHz = [math]::Round(($cpu.MaxClockSpeed / 1000), 2)
$cpuSpeedCompatible = $cpuSpeedGHz -ge 1

# Secure Boot status
function Get-SecureBootStatus {
    try {
        if (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            return [bool](Confirm-SecureBootUEFI)
        } else {
            $msinfo = Get-CimInstance -Namespace root\WMI -Class MS_SystemInformation -ErrorAction SilentlyContinue
            if ($msinfo -and $msinfo.SecureBoot -ne $null) { return [bool]$msinfo.SecureBoot }
            $cs = Get-CimInstance -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($cs -and $cs.SecureBootState -ne $null) { return [bool]$cs.SecureBootState }
        }
    } catch {}
    return $false
}
# Get Secure Boot Status
$secureBootEnabled = Get-SecureBootStatus

# Check TPM 2.0 Support
$tpmCompatible = Check-TPM

# Display results
Write-Host "`nWindows 11 Compatibility Check" -ForegroundColor Cyan
Write-Host "-----------------------------------"
Write-Host "`nProcessor: $rawCpuName"

# Architecture Check
if ($cpu64Bit) {
    Write-Host "`n64-bit CPU: Compatible" -ForegroundColor Green
} else {
    Write-Host "`n64-bit CPU: Not Compatible" -ForegroundColor Red
}

# CPU Speed Check
if ($cpuSpeedCompatible) {
    Write-Host "`nCPU Speed: $cpuSpeedGHz GHz (Compatible)" -ForegroundColor Green
} else {
    Write-Host "`nCPU Speed: $cpuSpeedGHz GHz (Not Compatible)" -ForegroundColor Red
}

# Secure Boot Check
if ($secureBootEnabled) {
    Write-Host "`nSecure Boot Enabled: Yes" -ForegroundColor Green
} else {
    Write-Host "`nSecure Boot Enabled: No" -ForegroundColor Red
}

# TPM 2.0 Check
if ($tpmCompatible) {
    Write-Host "`nTPM 2.0 Support: Yes" -ForegroundColor Green
} else {
    Write-Host "`nTPM 2.0 Support: No" -ForegroundColor Red
}

# CPU Support Check
if ($cpuSupported) {
    Write-Host "`nCPU Compatibility: $rawCpuName is supported" -ForegroundColor Green
} else {
    Write-Host "`nCPU Compatibility: $rawCpuName is NOT supported" -ForegroundColor Red
}

# Collect incompatibilities
$incompatibilityReasons = @()
if (-not $cpu64Bit) { $incompatibilityReasons += "CPU is not 64-bit" }
if (-not $cpuSpeedCompatible) { $incompatibilityReasons += "CPU speed is less than 1 GHz" }
if (-not $secureBootEnabled) { $incompatibilityReasons += "Secure Boot is not enabled" }
if (-not $tpmCompatible) { $incompatibilityReasons += "TPM 2.0 is not supported or not enabled" }
if (-not $cpuSupported) { $incompatibilityReasons += "Unsupported processor: $rawCpuName" }

# Define full bypass key set
$allBypassKeys = @(
    @{Path="HKLM:\SYSTEM\Setup\MoSetup"; Name="AllowUpgradesWithUnsupportedTPMOrCPU"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassTPMCheck"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassSecureBootCheck"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassRAMCheck"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassStorageCheck"; Value=1},
    @{Path="HKLM:\SYSTEM\Setup\LabConfig"; Name="BypassCPUCheck"; Value=1}
)

# Decide which bypasses are required (conservative)
$requiredBypasses = @()
if (-not $tpmCompatible) {
    $requiredBypasses += $allBypassKeys | Where-Object { $_.Name -in @("AllowUpgradesWithUnsupportedTPMOrCPU","BypassTPMCheck") }
}
if (-not $secureBootEnabled) {
    $requiredBypasses += $allBypassKeys | Where-Object { $_.Name -eq "BypassSecureBootCheck" }
}
if (-not $cpu64Bit -or -not $cpuSpeedCompatible -or -not $tpmCompatible) {
    $requiredBypasses += $allBypassKeys | Where-Object { $_.Name -in @("BypassCPUCheck","AllowUpgradesWithUnsupportedTPMOrCPU") }
}
if ($incompatibilityReasons.Count -gt 0) {
    $requiredBypasses += $allBypassKeys | Where-Object { $_.Name -in @("BypassRAMCheck","BypassStorageCheck") }
}
$requiredBypasses = $requiredBypasses | Select-Object -Unique

# Apply required bypasses and track which applied
$appliedBypasses = @()
if ($requiredBypasses.Count -gt 0) {
    Write-Host "`nApplying required registry bypasses..." -ForegroundColor Yellow
    foreach ($b in $requiredBypasses) {
        try {
            New-Item -Path $b.Path -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $b.Path -Name $b.Name -Type DWord -Value $b.Value -Force
            $appliedBypasses += $b.Name
            Write-Host " - Applied $($b.Name)"
        } catch {
            Write-Warning "Failed to apply $($b.Name): $_"
        }
    }
} else {
    Write-Host "`nNo bypasses required; system looks compatible." -ForegroundColor Green
}

# Decide whether to use /product server only if ALL bypass keys were applied
$allNames = $allBypassKeys | ForEach-Object { $_.Name } | Sort-Object
$appliedNow = $appliedBypasses | Sort-Object
$useProductServer = $false
if ($allNames -and ($allNames -eq $appliedNow)) {
    $useProductServer = $true
    Write-Host "`nAll bypass keys applied." -ForegroundColor Cyan
}

# Build installer args conditionally
if ($useProductServer) {
    $installArgs = "/product server /auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable /noreboot"
} else {
    $installArgs = "/auto upgrade /quiet /eula accept /dynamicupdate disable /telemetry disable /noreboot"
}

# Start Windows 11 Upgrade
Write-Host "`nStarting Windows 11 upgrade..."
try {
    $proc = Start-Process -FilePath $setupPath -ArgumentList $installArgs -PassThru
    Write-Host "Setup started (PID: $($proc.Id))."
} catch {
    Write-Error "Failed to start setup: $_"; exit 1
}

# Path to the setup log file and monitoring
$logPath = 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log'
$setupFolder = 'C:\$WINDOWS.~BT'

if (Test-Path $logPath) { Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue }

function Is-SetupRunning {
    $names = @('setupprep','setuphost','setup')
    foreach ($n in $names) { if (Get-Process -Name $n -ErrorAction SilentlyContinue) { return $true } }
    return $false
}

Write-Host "`nYour PC will restart several times. This might take a while.`n" -ForegroundColor Green
$spinner = ('\','|','/','-'); $spinnerIndex = 0; $currentPercent = 0

while ($true) {
    Start-Sleep -Milliseconds 500
    $setupRunning = Is-SetupRunning
    $folderExists = Test-Path $setupFolder
    $logExists = Test-Path $logPath

    if (-not $logExists -and -not $folderExists -and -not $setupRunning) {
        Write-Host "`nNo setup activity detected. Exiting..." -ForegroundColor Yellow
        break
    }

    if ($logExists) {
        try {
            $content = Get-Content $logPath -Tail 300 -ErrorAction SilentlyContinue
            $progressLines = $content | Where-Object { $_ -match "Overall progress: \[(\d+)%\]" }
            if ($progressLines) {
                $lastLine = $progressLines[-1]
                if ($lastLine -match "Overall progress: \[(\d+)%\]") { $currentPercent = [int]$Matches[1] }
            }
        } catch {}
    }

    $spinnerChar = $spinner[$spinnerIndex % $spinner.Length]
    Write-Host -NoNewline "`r$spinnerChar $currentPercent% complete    "
    $spinnerIndex++

    if ($currentPercent -ge 100) {
        Write-Host "`nUpgrade completed! Your PC will restart in a few moments." -ForegroundColor Green
        break
    }
}

# Cleanup: unmount ISO
Write-Host "`nUnmounting ISO..."
try { $null = Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue } catch { Write-Warning "Failed to dismount ISO: $_" }

Write-Host "`nWindows 11 upgrade process finished..."
Write-Host "`nRebooting System..."
Restart-Computer -Force
