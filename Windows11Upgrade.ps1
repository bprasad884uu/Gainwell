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
$isoUrl_EN_US  = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_English_x64.iso?t=a25f67f8-f98b-478f-82bb-20ead3118c6a&P1=1763740004&P2=601&P3=2&P4=YTVN%2bSxGEBW%2fMCwawobzl06gxIAq8KOAykrJP%2fqatA3kArSbYpDummjHm6lAkfd%2bF0zYctO%2flxaLWTTP6XSmlrgRcq4tqSh7S1U7uHp%2b%2bUX3hPHwCri%2fNTtXm%2bLNXeIN%2fKftRqa0TSq81PrUh3x1RPBW%2fN2IXdsBf%2fDmauTs1ztCw1RxmJsMythw1Sh2TEwrxD94pXV3w%2fO115x5HfnKMSYX8oiOe5ocs2QGms8aDyTrMLuZ0fN0%2bSg68vYmAXq%2b8dQm7%2bqXw46BHosj8to25bhfExGqoaqw73C63D52zOmt5lH8VWOI5YeUVmOP77bpce3%2fhIQk46sNDgsLwC1TRQ%3d%3d"
$isoUrl_EN_GB  = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_EnglishInternational_x64.iso?t=165a975b-f0be-4fad-94b4-c1ee8cc59fde&P1=1763739996&P2=601&P3=2&P4=ua9CW7OoBSO%2fckhBMQnHmV0OPeVqAna%2fAx5ihtE86ja%2fP8gLqQCjVVVxniMQwzKDAkM39PI5F7qVWh1eSbgtapuV52uxozx6%2bbKQ80%2fW3Dt6FkkJA96T48rBt3umCxkesRXUG9cF4otUBdqppbb2rjF8kC8xsMHc435YUeaUAaECNdgKG6%2blUvlcOYewi%2b%2fjudoYC59vA2S1ioyaCt%2b6luZDY%2ff3fGxhL16wKLVtdY0cWMIsnya4BvwTWPDP5I2EE2K22bGYUwK5islrbays3bLH28CfjBoxvQw7P4OkcO6HYthudR%2b4VNqy%2bRnBgSIF1tLUYIuuqP5x%2bGEdy7JF0w%3d%3d"

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
    param([long]$MinimumBytes = (20 * 1024 * 1024 * 1024))
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

# ---------- JSON-based segment verification helper ----------
function Test-SegmentJson {
    param(
        [Parameter(Mandatory=$true)][string]$OutFile,
        [switch]$Silent
    )

    $metaPath = "$OutFile.segmentmeta.json"

    if (-not (Test-Path $metaPath)) {
        Write-Warning "Meta file not found: $metaPath"
        return $false
    }

    $meta  = Get-Content $metaPath -Raw | ConvertFrom-Json
    $allOk = $true

    foreach ($p in $meta.Parts) {
        $expected = [long]$p.ExpectedSize
        $actual   = 0
        if ($p.Path -and (Test-Path $p.Path)) {
            $actual = (Get-Item $p.Path).Length
        }

        $p.BytesDownloaded = $actual
        if ($expected -gt 0 -and $actual -ge $expected) {
            $p.Completed = $true
        } else {
            $p.Completed = $false
            $allOk = $false
        }
    }

    # Update meta file on disk
    $meta | ConvertTo-Json -Depth 6 | Set-Content -Path $metaPath -Encoding UTF8

    if (-not $Silent) {
        $meta.Parts |
            Select-Object Index,
                          @{n='BytesDownloaded';e={[long]$_.BytesDownloaded}},
                          @{n='ExpectedSize';e={[long]$_.ExpectedSize}},
                          Completed |
            Format-Table -AutoSize

        if ($allOk) {
            Write-Host "`nAll segments complete according to JSON + file sizes."
        } else {
            Write-Warning "`nSome segments are incomplete. Next run will resume remaining parts."
        }
    }

    return $allOk
}

# ---------- Download with resume support (runspace-based segmented downloader) ----------
function Download-WithResume {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [int]$MaxParallel = 32,
        [long]$SegmentMinBytes = (20 * 1024 * 1024), # kept but ignored for fixed 32 segments
        [int]$AttemptsPerPart = 3
    )

    if (-not ("System.Net.Http.HttpClient" -as [type])) {
        Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue
    }

    Write-Host "`nPreparing download:`n"
    $tmpFolder = [System.IO.Path]::GetDirectoryName($OutFile)
    if (-not (Test-Path $tmpFolder)) { New-Item -Path $tmpFolder -ItemType Directory -Force | Out-Null }

    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [System.TimeSpan]::FromHours(4)

    try {
        # Probe server for range support and length (HEAD preferred, fallback to ranged GET probe)
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
        if ($resp.Content.Headers.ContentLength -ne $null) { $remoteLength = [long]$resp.Content.Headers.ContentLength }
        elseif ($resp.Content.Headers.ContentRange -ne $null -and $resp.Content.Headers.ContentRange.Length -ne $null) {
            $remoteLength = [long]$resp.Content.Headers.ContentRange.Length
        }

        $resp.Dispose()

        # If remote length unknown but ranges supported, try small GET to get length
        if (($remoteLength -eq $null) -and $acceptRanges) {
            try {
                $probe = $client.SendAsync([System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Url), [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
                if ($probe.Content.Headers.ContentLength -ne $null) { $remoteLength = [long]$probe.Content.Headers.ContentLength }
                $probe.Dispose()
            } catch {}
        }

        # ================= SINGLE-STREAM RESUME BRANCH =================
        if (-not $acceptRanges -or -not $remoteLength -or $remoteLength -le 0) {
            Write-Host "`nServer does not support ranged requests or remote length unknown — using single-stream resume with larger buffer."
            $start = 0
            if (Test-Path $OutFile) {
                try { $start = (Get-Item $OutFile).Length } catch { $start = 0 }
                if ($start -gt 0) { Write-Host "`nPartial file detected: $(Format-Size $start). Resuming..." }
            }

            $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
            if ($start -gt 0) { $request.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($start, $null) }

            $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
            if ($response.StatusCode -eq [System.Net.HttpStatusCode]::RequestedRangeNotSatisfiable) {
                Write-Warning "Server says requested range not satisfiable. Removing partial and retrying full download."
                Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
                $start = 0
                $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
                $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
            }
            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK -and $response.StatusCode -ne [System.Net.HttpStatusCode]::PartialContent) {
                throw "Download failed: $($response.StatusCode) $($response.ReasonPhrase)"
            }

            $content = $response.Content
            $stream = $content.ReadAsStreamAsync().Result
            if ($start -eq 0) {
                $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            } else {
                $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                $fs.Seek($start, 'Begin') | Out-Null
            }

            $bufferSize = 20 * 1024 * 1024  # 20MB buffer for high throughput
            $buffer = New-Object byte[] $bufferSize
            $downloadedThisSession = 0
            $sessionStart = Get-Date

            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fs.Write($buffer, 0, $bytesRead)
                $downloadedThisSession += $bytesRead
                $downloadedTotal = $start + $downloadedThisSession
                $elapsed = (Get-Date) - $sessionStart
                $speed = if ($elapsed.TotalSeconds -gt 0) { $downloadedThisSession / $elapsed.TotalSeconds } else { 0 }

                if ($remoteLength -gt 0 -and $speed -gt 0) {
                    $remaining = $remoteLength - $downloadedTotal
                    $etaSeconds = $remaining / $speed
                    $progress = ($downloadedTotal / $remoteLength) * 100
                    $etaFormatted = Format-ETA $etaSeconds
                } else {
                    $progress = 0
                    $etaFormatted = "Unknown"
                }
                Write-Host -NoNewline "`rDownloaded: $(Format-Size $downloadedTotal) / $(Format-Size $remoteLength) ($([math]::Round($progress,2))%) | Speed: $(Format-Speed $speed) | ETA: $etaFormatted   "
            }

            Write-Host "`nDownload finished: $OutFile"
            $stream.Close(); $content.Dispose(); $fs.Close(); $response.Dispose()
            return
        }

        # ================= SEGMENTED PARALLEL DOWNLOAD BRANCH =================
        Write-Host "`nServer supports ranges. Using segmented parallel download. Size: $(Format-Size $remoteLength). MaxParallel: $MaxParallel`n"

        # JSON metadata path
        $metaPath = "$OutFile.segmentmeta.json"
        $meta     = $null

        # Try load existing meta for resume
        if (Test-Path $metaPath) {
            try { $meta = Get-Content $metaPath -Raw | ConvertFrom-Json } catch { $meta = $null }
        }

        # If meta exists but size OR segment layout changed -> wipe parts + meta
        if ($meta -and ([long]$meta.RemoteLength -ne $remoteLength -or [int]$meta.SegmentCount -ne 32)) {
            if ($meta.Parts) {
                foreach ($p in $meta.Parts) {
                    if ($p.Path -and (Test-Path $p.Path)) {
                        Remove-Item $p.Path -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            Remove-Item $metaPath -Force -ErrorAction SilentlyContinue
            $meta = $null
        }

        # If final ISO exists but size mismatched, delete final only (parts stay for resume if compatible meta)
        if (Test-Path $OutFile) {
            $existingLength = (Get-Item $OutFile).Length
            if ($existingLength -eq $remoteLength -and $meta -and [int]$meta.SegmentCount -eq 32) {
                Write-Host "`nFile already present and size matches remote. Skipping download."
                return
            } else {
                Write-Host "`nExisting ISO size differs or layout changed; removing ISO but keeping compatible parts for resume (if any)."
                Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
            }
        }

        $segmentCount = $null
        $segmentSize  = $null
        $partFiles    = $null

        if ($meta) {
            # Resume layout from old meta (must already be 32)
            $segmentCount = [int]$meta.SegmentCount
            $segmentSize  = [long]$meta.SegmentSize
            $partFiles    = @($meta.Parts | Sort-Object Index | ForEach-Object { $_.Path })
        } else {
            # Fresh layout: ALWAYS 32 segments (IDM-style fixed)
            $segmentCount = 32
            if ($segmentCount -lt 1) { $segmentCount = 1 }

            # Make sure segmentSize at least 1 byte (for safety)
            $segmentSize = [long][math]::Floor(([double]$remoteLength) / [double]$segmentCount)
            if ($segmentSize -lt 1) { $segmentSize = 1 }

            $partFiles   = for ($i = 0; $i -lt $segmentCount; $i++) { "$OutFile.part$i" }

            # Build fresh meta
            $meta = [pscustomobject]@{
                Url          = $Url
                RemoteLength = $remoteLength
                SegmentCount = $segmentCount
                SegmentSize  = $segmentSize
                Parts        = @()
            }

            for ($i = 0; $i -lt $segmentCount; $i++) {
                $startByte = [long]($i * $segmentSize)
                if ($i -eq ($segmentCount - 1)) {
                    $endByte = [long]($remoteLength - 1)
                } else {
                    $endByte = [long]((($i + 1) * $segmentSize) - 1)
                }

                if ($startByte -gt $endByte) {
                    $expectedSize    = 0
                    $bytesDownloaded = 0
                    $completed       = $true
                } else {
                    $partFile        = $partFiles[$i]
                    $expectedSize    = [long]($endByte - $startByte + 1)
                    $bytesDownloaded = 0
                    $completed       = $false

                    if (Test-Path $partFile) {
                        $bytesDownloaded = (Get-Item $partFile).Length
                        if ($bytesDownloaded -ge $expectedSize) {
                            $completed = $true
                        }
                    }
                }

                $meta.Parts += [pscustomobject]@{
                    Index           = $i
                    Path            = $partFiles[$i]
                    Start           = $startByte
                    End             = $endByte
                    ExpectedSize    = $expectedSize
                    BytesDownloaded = $bytesDownloaded
                    Completed       = $completed
                }
            }

            $meta | ConvertTo-Json -Depth 6 | Set-Content -Path $metaPath -Encoding UTF8
        }

        # create runspace pool
        $minThreads = 1
        $maxThreads = [int]([System.Math]::Max([double]1, [double]$MaxParallel))
        $rsp = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($minThreads, $maxThreads)
        $rsp.ThreadOptions = "ReuseThread"
        $rsp.Open()

        $powershellList = @()
        for ($i = 0; $i -lt $segmentCount; $i++) {
            $partMeta         = $meta.Parts | Where-Object { $_.Index -eq $i }
            $startByte        = [long]$partMeta.Start
            $endByte          = [long]$partMeta.End
            $partFile         = $partMeta.Path
            $expectedPartSize = [long]$partMeta.ExpectedSize

            if ($expectedPartSize -le 0 -or $startByte -gt $endByte) {
                $partMeta.Completed       = $true
                $partMeta.BytesDownloaded = 0
                continue
            }

            # Always trust actual length from disk for resume
            $existingLength = 0
            if ($partFile -and (Test-Path $partFile)) {
                $existingLength = (Get-Item $partFile).Length
            }

            # If part is larger than expected, reset it
            if ($existingLength -gt $expectedPartSize) {
                Write-Warning "Segment $i part file larger than expected. Resetting this part."
                Remove-Item $partFile -Force -ErrorAction SilentlyContinue
                $existingLength = 0
            }

            # Skip if already full
            if ($expectedPartSize -gt 0 -and $existingLength -ge $expectedPartSize) {
                $partMeta.Completed       = $true
                $partMeta.BytesDownloaded = $existingLength
                continue
            }

            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $rsp

            $script = {
                param($Url, $partFile, $startByte, $endByte, $index, $attempts, $alreadyDownloaded)
                try {
                    if (-not ("System.Net.Http.HttpClient" -as [type])) { Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue }
                    $h = [System.Net.Http.HttpClient]::new()
                    $h.Timeout = [System.TimeSpan]::FromHours(4)

                    $try = 0
                    while ($true) {
                        $try++
                        try {
                            $resumeStart = [long]($startByte + $alreadyDownloaded)
                            if ($resumeStart -gt $endByte) {
                                $h.Dispose()
                                return @{
                                    Index   = $index
                                    Success = $true
                                    Error   = $null
                                    Part    = $partFile
                                }
                            }

                            $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Url)
                            $req.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($resumeStart, $endByte)
                            $resp = $h.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
                            if ($resp.StatusCode -ne [System.Net.HttpStatusCode]::PartialContent -and $resp.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                                throw "HTTP $($resp.StatusCode) $($resp.ReasonPhrase)"
                            }
                            $stream = $resp.Content.ReadAsStreamAsync().Result

                            if ($alreadyDownloaded -gt 0 -and (Test-Path $partFile)) {
                                $fs = [System.IO.File]::Open($partFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                                $fs.Seek(0, 'End') | Out-Null
                            } else {
                                $fs = [System.IO.File]::Open($partFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                            }
                            $buffer = New-Object byte[] (8 * 1024 * 1024) # 8MB buffer
                            while (($r = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                                $fs.Write($buffer, 0, $r)
                            }
                            $fs.Close()
                            $stream.Close(); $resp.Dispose(); $h.Dispose()
                            return @{ Index = $index; Success = $true; Error = $null; Part = $partFile }
                        } catch {
                            $err = $_.ToString()
                            if ($try -ge $attempts) {
                                # Final failure for this segment: delete part so next run cleanly redownloads
                                if (Test-Path $partFile) { Remove-Item $partFile -Force -ErrorAction SilentlyContinue }
                                if ($h) { $h.Dispose() }
                                return @{ Index = $index; Success = $false; Error = $err; Part = $partFile }
                            } else {
                                Start-Sleep -Seconds (2 * $try)
                                continue
                            }
                        }
                    }
                } catch {
                    # Outer unexpected failure: also delete part
                    if (Test-Path $partFile) { Remove-Item $partFile -Force -ErrorAction SilentlyContinue }
                    return @{ Index = $index; Success = $false; Error = $_.ToString(); Part = $partFile }
                }
            }

            $ps.AddScript($script).AddArgument($Url).AddArgument($partFile).AddArgument($startByte).AddArgument($endByte).AddArgument($i).AddArgument($AttemptsPerPart).AddArgument($existingLength) | Out-Null
            $async = $ps.BeginInvoke()
            $powershellList += [PSCustomObject]@{ PS = $ps; Async = $async; Index = $i; PartFile = $partFile; ExpectedSize = $expectedPartSize }
        }

        # Monitor progress with smoothed speed and ETA
        $lastTotal = 0
        $lastTime = (Get-Date).AddSeconds(-1)  # initialize a second earlier to avoid tiny delta
        $avgSpeedSamples = New-Object System.Collections.Queue
        $maxSamples = 5

        while ($true) {
            $now = Get-Date
            $totalDownloaded = 0
            for ($i = 0; $i -lt $meta.Parts.Count; $i++) {
                $pf  = $meta.Parts[$i].Path
                $len = 0
                if ($pf -and (Test-Path $pf)) {
                    $len = (Get-Item $pf).Length
                    $totalDownloaded += $len
                }

                $metaPart = $meta.Parts[$i]
                $metaPart.BytesDownloaded = $len
                if ($metaPart.ExpectedSize -gt 0 -and $len -ge $metaPart.ExpectedSize) {
                    $metaPart.Completed = $true
                } else {
                    $metaPart.Completed = $false
                }
            }

            # Write meta to disk so you can inspect status any time
            $meta | ConvertTo-Json -Depth 6 | Set-Content -Path $metaPath -Encoding UTF8
            $deltaBytes = $totalDownloaded - $lastTotal
            $deltaTime = ($now - $lastTime).TotalSeconds
            if ($deltaTime -lt 0.5) { $deltaTime = 0.5 }  # clamp to avoid huge spikes
            $instantSpeed = if ($deltaTime -gt 0) { $deltaBytes / $deltaTime } else { 0 }

            $avgSpeedSamples.Enqueue($instantSpeed)
            if ($avgSpeedSamples.Count -gt $maxSamples) { [void]$avgSpeedSamples.Dequeue() }
            $avgSpeed = ($avgSpeedSamples | Measure-Object -Average).Average
            if (-not $avgSpeed) { $avgSpeed = 0 }

            # Use double for Math.Max to avoid Int32 overload selection
            $remainingBytes = [System.Math]::Max([double]0, [double]($remoteLength - $totalDownloaded))
            if ($remainingBytes -le 0) {
                # Fully downloaded -> ETA 0s
                $eta = "0s"
            } elseif ($avgSpeed -gt 0) {
                $eta = Format-ETA ($remainingBytes / $avgSpeed)
            } else {
                $eta = "Unknown"
            }

            $progressPct = if ($remoteLength -gt 0) {
                [math]::Round(($totalDownloaded / $remoteLength) * 100, 2)
            } else { 0 }

            if ($progressPct -gt 100) { $progressPct = 100 }
            if ($progressPct -lt 0)   { $progressPct = 0 }

            # Primary formatted line
            $downloadedText = "$(Format-Size $totalDownloaded) / $(Format-Size $remoteLength) ($progressPct`%)"
            $speedText = "$(Format-Speed $avgSpeed)"
            $etaText = $eta

            Write-Host -NoNewline "`rDownloaded: $downloadedText | Speed: $speedText | ETA: $etaText   "

            $lastTotal = $totalDownloaded
            $lastTime = $now

            # completion check
            $allDone = $true
            foreach ($entry in $powershellList) { if (-not $entry.Async.IsCompleted) { $allDone = $false; break } }
            if ($allDone) { break }

            Start-Sleep -Seconds 1
        }
        Write-Host ""

        # Collect results + size checks (only trust file sizes)
        $errors = @()
        foreach ($entry in $powershellList) {
            try {
                # EndInvoke just to ensure runspace finishes; ignore its output
                try { $null = $entry.PS.EndInvoke($entry.Async) } catch {}
                try { $entry.PS.Dispose() } catch {}

                $actualLen = 0
                if (Test-Path $entry.PartFile) {
                    $actualLen = (Get-Item $entry.PartFile).Length
                }

                if ($actualLen -lt $entry.ExpectedSize) {
                    $errors += "Part too small: $($entry.PartFile) - expected >= $(Format-Size $($entry.ExpectedSize)), actual $(Format-Size $actualLen)"
                }
            } catch {
                $actualLen = 0
                if (Test-Path $entry.PartFile) { $actualLen = (Get-Item $entry.PartFile).Length }
                if ($actualLen -lt $entry.ExpectedSize) { $errors += "Part error: $($entry.PartFile) - $_" }
            }
        }

        try { $rsp.Close(); $rsp.Dispose() } catch {}

        if ($errors.Count -gt 0) {
            throw "One or more segment downloads failed: $($errors -join '; ')"
        }

        # JSON + file-size verify before merge
        if (-not (Test-SegmentJson -OutFile $OutFile -Silent)) { throw "Some segments are incomplete according to JSON; aborting merge. Run the script again to resume." }

        # Concatenate parts into final file
        Write-Host "`nStitching parts into final file..."

        $partsSorted  = $meta.Parts | Sort-Object Index
        $totalToWrite = 0

        foreach ($p in $partsSorted) {
            if ($p.Path -and (Test-Path $p.Path)) {
                $totalToWrite += (Get-Item $p.Path).Length
            }
        }

        if ($totalToWrite -le 0) {
            Write-Warning "No part files found to stitch."
            return
        }

        $outStream = [System.IO.File]::Open(
            $OutFile,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )

        $written   = 0
        $barWidth  = 50  # [==================================================]

        $emptyBar = "[" + "".PadRight($barWidth, ' ') + "]"
        Write-Host -NoNewline $emptyBar

        foreach ($p in $partsSorted) {
            $pf = $p.Path
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

                # Progress bar update
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
        $finalBar     = "[" + $finalBarBody + "]"
        Write-Host -NoNewline ("`r" + $finalBar)
        Write-Host ""  # new line

        if (Test-Path $metaPath) { Remove-Item $metaPath -Force -ErrorAction SilentlyContinue }

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
#Write-Host "`nRebooting System..."
# Restart-Computer -Force
