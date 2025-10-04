<## Ensure PowerShell Runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}#>

# ---------- Config (fill these) ----------
$isoUrl_EN_US  = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_English_x64.iso?t=49bc1e21-229a-4d13-938f-ce1228bd0221&P1=1759599910&P2=601&P3=2&P4=ZM1EGR90ndsJZfuuMiywYiGiXTCvHy3%2bMkgs60YFUzCFjU9KVsGUiKqn9wPzew8VqIrwCClHlCbUsX4kS2r4ENoeR1nowxq08LHheK4YCVJDhYL5wsonsylK3%2bpQ9aNAZgigZ3WRtOW1M%2bw8S4ZHVrDF0tGb4BAH6QNIx4Sal8Q8a%2fjHktvntqkCQ%2fb4cl3DNp9e6TkWtqMGsJ3fuRafgzSJTWpBaTJxTVs2AFk5tIYCjbOgSQmw%2fy45BRlIlkOIRSRnnFfXsRmAnshrGBNd1XvZvIvlZsmZZUZ2S6n%2bYuwYf55FVZeWRnrlwCb6KM39sxotRB9V4%2btn5JD1%2f7wbJQ%3d%3d"
$isoUrl_EN_GB  = "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_EnglishInternational_x64.iso?t=6a1a0fe6-3811-4547-90d6-eb8b9f480fb0&P1=1759599900&P2=601&P3=2&P4=KP9R2Hki4lvfivX3WTulRZbMaBCCXNHbzgfHvP87pcoRzcf2Er7Z9A3%2fZzXE%2bO1m0S5oaPVM4I%2bhgU1z5ImwHNS%2bWXiyEVEL36kmt3S6UoHXvl6j%2f5VlUHMeFa3KN92b66Jj9sXrJDC0D6xvtS1mPYmV6KuqB70XR6%2be%2fKKXv87cKpQx1zYzqxJJrP2CQ3OrNKDxLZv9XI1DscOLl8qCFjpFUni1YlNbJPTXk42mAjmLwqhMy2auEyy6s1t1YBApf5Bj1WtIox6QFCCs7B2PxcV0yhLU3RuZConeLSPEacB5bDqTqXvP%2fc%2bgom1GJ2FFuw8bGNLDSac3GgdyQQSJwQ%3d%3d"

# Provide either a SHA256 hex string or a URL that returns the hash. Leave empty ("") to skip verification.
$Checksum = ""

# Minimum free space for temp selection (20 GB default)
$MinimumTempBytes = (20 * 1024 * 1024 * 1024)

# ---------- Detect Installed Language ----------
$locale = (dism /online /get-intl | Where-Object { $_ -match '^Installed language\(s\):' }) -replace '.*:\s*',''
switch ($locale) {
    "en-GB" { $languageName = "English (UK)"; $isoUrl = $isoUrl_EN_GB; $destinationName = "Win11_25H2_ENGB.iso" }
    "en-US" { $languageName = "English (US)"; $isoUrl = $isoUrl_EN_US; $destinationName = "Win11_25H2_ENUS.iso" }
    default { $languageName = $locale; Write-Warning "Unsupported/unknown language ($locale). Defaulting to en-US."; $isoUrl = $isoUrl_EN_US; $destinationName = "Win11_25H2.iso" }
}
Write-Host "Detected Language: $languageName - Selected ISO URL: $($isoUrl -replace '^(https?://).*','$1...')"

# --- Choose Temp location: prefer C: if it has >= MinimumBytes, otherwise find another drive ---
function Select-TempRoot {
    param([long]$MinimumBytes = (20 * 1024 * 1024 * 1024))

    # 1) Prefer C: drive explicitly
    try {
        $cRoot = "C:\"
        if (Test-Path $cRoot) {
            $cLogical = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID = 'C:'" -ErrorAction SilentlyContinue
            if ($cLogical -and $cLogical.DriveType -eq 3 -and $cLogical.FreeSpace -ge $MinimumBytes) {
                # Use existing user temp on C: if exists and usable, otherwise create Temp under C: if necessary
                try {
                    $userTemp = $env:TEMP
                    if ($userTemp -and ([System.IO.Path]::GetPathRoot($userTemp) -ieq "C:\") -and (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID = 'C:'" -ErrorAction SilentlyContinue).FreeSpace -ge $MinimumBytes) {
                        return $env:TEMP.TrimEnd('\')
                    } else {
                        $candidate = Join-Path -Path $cRoot -ChildPath "Temp"
                        if (-not (Test-Path $candidate)) { New-Item -Path $candidate -ItemType Directory -Force | Out-Null }
                        # quick write test
                        $testFile = Join-Path $candidate ".__writetest.tmp"
                        Set-Content -Path $testFile -Value "ok" -ErrorAction Stop
                        Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                        return $candidate.TrimEnd('\')
                    }
                } catch {
                    # fall through to scanning other drives if any error
                }
            }
        }
    } catch {
        # ignore and continue to next step
    }

    # 2) Fallback: scan other local fixed drives for free space (DriveType 3)
    try {
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Sort-Object -Property DeviceID
        foreach ($d in $drives) {
            # Skip C: since we already tried it
            if ($d.DeviceID -ieq "C:") { continue }
            if ($d.FreeSpace -ge $MinimumBytes) {
                $root = "$($d.DeviceID)\"
                $candidateTemp = Join-Path -Path $root -ChildPath "Temp"
                try {
                    if (-not (Test-Path $candidateTemp)) { New-Item -Path $candidateTemp -ItemType Directory -Force | Out-Null }
                    # quick write test
                    $testFile = Join-Path $candidateTemp ".__writetest.tmp"
                    Set-Content -Path $testFile -Value "ok" -ErrorAction Stop
                    Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                    return $candidateTemp.TrimEnd('\')
                } catch {
                    # can't create/write on this drive — skip to next
                    continue
                }
            }
        }
    } catch {
        # ignore and fallback to env:TEMP
    }

    # 3) Final fallback: use $env:TEMP even if it may be on another drive or has less space
    try {
        if ($env:TEMP) { return $env:TEMP.TrimEnd('\') }
    } catch {}

    # 4) If all else fails, return C:\Temp (attempt to create)
    try {
        $final = "C:\Temp"
        if (-not (Test-Path $final)) { New-Item -Path $final -ItemType Directory -Force | Out-Null }
        return $final.TrimEnd('\')
    } catch {
        # Last resort
        return "C:\"
    }
}

$TempRoot = Select-TempRoot -MinimumBytes $MinimumTempBytes
if ($TempRoot -match "^[A-Za-z]:$") {
    $TempRoot = Join-Path $TempRoot "Temp"
    if (-not (Test-Path $TempRoot)) { New-Item -Path $TempRoot -ItemType Directory -Force | Out-Null }
}
Write-Host "Using temp root: $TempRoot"
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

# ---------- SHA256 helpers ----------
function Resolve-ChecksumString { param($checksumOrUrl)
    if (-not $checksumOrUrl -or $checksumOrUrl.Trim() -eq "") { return $null }
    if ($checksumOrUrl -match '^https?://') {
        try {
            if (-not ("System.Net.Http.HttpClient" -as [type])) { Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue }
            $hc = New-Object System.Net.Http.HttpClient
            $txt = $hc.GetStringAsync($checksumOrUrl).Result
            $hc.Dispose()
            if ($txt) { return ($txt.Trim() -split '\s+')[0].Trim() }
        } catch { Write-Warning "Failed to fetch checksum from URL: $_"; return $null }
    } else { return $checksumOrUrl.Trim() }
    return $null
}
function Verify-FileSHA256 { param($filePath, $expectedHex)
    if (-not (Test-Path $filePath)) { throw "File not found: $filePath" }
    if (-not $expectedHex) { Write-Host "No checksum supplied; skipping verification."; return $true }
    Write-Host "Verifying SHA256..."
    $hash = Get-FileHash -Path $filePath -Algorithm SHA256
    $computed = $hash.Hash.ToLowerInvariant(); $expected = $expectedHex.Trim().ToLowerInvariant()
    if ($computed -eq $expected) { Write-Host "SHA256 verification passed."; return $true } else { Write-Warning "SHA256 mismatch! Expected: $expected`nActual:   $computed"; return $false }
}

# ---------- Probe helper: pick best parallel part count ----------
function Probe-ChooseParts {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [int]$MaxCandidate = 16,
        [int[]]$Candidates = @(4,8,12),
        [int]$SampleBytes = 64 * 1024,   # 64 KB per probe job
        [int]$TimeoutSeconds = 6
    )

    if (-not ("System.Net.Http.HttpClient" -as [type])) {
        Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue
    }

    # Quick HEAD to check Accept-Ranges and remote size
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        try { $handler.MaxConnectionsPerServer = 16 } catch {}
        $hc = New-Object System.Net.Http.HttpClient($handler)
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, $Url)
        $resp = $hc.SendAsync($req).Result
    } catch {
        try { $resp = $hc.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result } catch { if ($hc) { $hc.Dispose() }; return 1 }
    }

    if ($resp.StatusCode -ge [System.Net.HttpStatusCode]::BadRequest) { if ($hc) { $hc.Dispose() }; return 1 }

    $acceptRanges = $false
    if ($resp.Headers.Contains("Accept-Ranges")) {
        $vals = $resp.Headers.GetValues("Accept-Ranges") -join ","
        if ($vals -match "bytes") { $acceptRanges = $true }
    }
    $remoteLength = $null
    if ($resp.Content.Headers.ContentLength -ne $null) { $remoteLength = [long]$resp.Content.Headers.ContentLength }

    # if no ranges or tiny remote, don't probe
    if (-not $acceptRanges -or -not $remoteLength -or $remoteLength -le $SampleBytes * 4) {
        if ($hc) { $hc.Dispose() }
        return 1
    }

    $candidates = $Candidates | Where-Object { $_ -le $MaxCandidate } | Sort-Object
    if (-not $candidates) { $candidates = @(4) }

    $results = @()

    foreach ($cand in $candidates) {
        if ($cand * $SampleBytes -gt $remoteLength) {
            $actualCand = [math]::Max(1, [math]::Floor($remoteLength / $SampleBytes))
        } else {
            $actualCand = $cand
        }

        $tmpParts = for ($i=0; $i -lt $actualCand; $i++) { Join-Path -Path $env:TEMP -ChildPath ("probe_part_{0}_{1}.tmp" -f $cand, $i) }

        $jobs = @()
        $startTime = Get-Date
        for ($i=0; $i -lt $actualCand; $i++) {
            $maxStart = [math]::Max(0, $remoteLength - $SampleBytes - 1)
            $offset = Get-Random -Minimum 0 -Maximum ([int]$maxStart)
            $end = $offset + $SampleBytes - 1

            $script = {
                param($Url, $start, $end, $outPath, $timeoutSec)
                if (-not ("System.Net.Http.HttpClient" -as [type])) { Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue }
                $handler = New-Object System.Net.Http.HttpClientHandler
                try { $handler.MaxConnectionsPerServer = [int]8 } catch {}
                $client = New-Object System.Net.Http.HttpClient($handler)
                $client.Timeout = [System.TimeSpan]::FromSeconds($timeoutSec)
                try {
                    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
                    $req.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($start, $end)
                    $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
                    if ($resp.StatusCode -eq [System.Net.HttpStatusCode]::PartialContent -or $resp.StatusCode -eq [System.Net.HttpStatusCode]::OK) {
                        $stream = $resp.Content.ReadAsStreamAsync().Result
                        $fs = [System.IO.File]::Open($outPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                        $buffer = New-Object byte[] 8192
                        $total = 0
                        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                            $fs.Write($buffer, 0, $read)
                            $total += $read
                        }
                        $fs.Close(); $stream.Close(); $resp.Dispose()
                        $client.Dispose()
                        return @{ Status='OK'; Bytes=$total }
                    } else {
                        $resp.Dispose()
                        $client.Dispose()
                        return @{ Status='Error'; Bytes=0 }
                    }
                } catch {
                    try { $client.Dispose() } catch {}
                    return @{ Status='Error'; Bytes=0 }
                }
            }

            $job = Start-ThreadJob -ArgumentList $Url, $offset, $end, $tmpParts[$i], $TimeoutSeconds -ScriptBlock $script
            $jobs += @{ Job=$job; Path=$tmpParts[$i] }
        }

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            $allDone = $true
            foreach ($j in $jobs) { if ($j.Job.State -eq 'Running') { $allDone = $false; break } }
            if ($allDone) { break }
            Start-Sleep -Milliseconds 100
        }

        $totalBytes = 0
        foreach ($j in $jobs) {
            try {
                $res = Receive-Job -Job $j.Job -Keep -ErrorAction SilentlyContinue
                if ($res -and $res.Bytes) { $totalBytes += [int]$res.Bytes }
            } catch {}
            try { if (Test-Path $j.Path) { Remove-Item -Path $j.Path -Force -ErrorAction SilentlyContinue } } catch {}
            try { if ($j.Job.State -eq 'Running') { Stop-Job -Job $j.Job -Force -ErrorAction SilentlyContinue } } catch {}
            try { Remove-Job -Job $j.Job -Force -ErrorAction SilentlyContinue } catch {}
        }

        $elapsed = (Get-Date) - $startTime
        $seconds = [math]::Max(0.001, $elapsed.TotalSeconds)
        $speed = $totalBytes / $seconds  # bytes/sec

        $results += @{ Candidate = $cand; Actual = $actualCand; Bytes = $totalBytes; Sec = $seconds; Speed = $speed }
    }

    if ($hc) { $hc.Dispose() }

    if (-not $results) { return 1 }

    $best = $results | Sort-Object -Property Speed -Descending | Select-Object -First 1
    $chosen = [int]$best.Candidate

    if ($chosen -lt 1) { $chosen = 1 }
    if ($chosen -gt $MaxCandidate) { $chosen = $MaxCandidate }

    return $chosen
}

# ---------- Single-connection resume fallback function used by the parallel downloader.
function Download-WithResumeSingle {
    param([string]$Url, [string]$OutFile, [int]$BufferSize = 4 * 1024 * 1024)

    if (-not ("System.Net.Http.HttpClient" -as [type])) {
        Add-Type -Path "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue
    }
    $handler = New-Object System.Net.Http.HttpClientHandler
    try { $handler.MaxConnectionsPerServer = 16 } catch {}
    $client = New-Object System.Net.Http.HttpClient($handler)

    $start = 0
    if (Test-Path $OutFile) {
        try { $start = (Get-Item $OutFile).Length } catch { $start = 0 }
        if ($start -gt 0) { Write-Host "Partial file detected. Size: $(Format-Size $start). Attempting resume..." }
    }

    $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
    if ($start -gt 0) { $request.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($start, $null) }

    $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
    if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK -and $response.StatusCode -ne [System.Net.HttpStatusCode]::PartialContent) {
        throw "Download failed: $($response.StatusCode) $($response.ReasonPhrase)"
    }

    $remoteLength = $response.Content.Headers.ContentLength
    $totalLength = if ($remoteLength -ne $null) { $start + [long]$remoteLength } else { -1 }

    if ($start -eq 0) {
        $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    } else {
        $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $fs.Seek($start, 'Begin') | Out-Null
    }

    $stream = $response.Content.ReadAsStreamAsync().Result
    $buffer = New-Object byte[] $BufferSize
    $downloadedThisSession = 0
    $sessionStart = Get-Date
    while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $fs.Write($buffer, 0, $bytesRead)
        $downloadedThisSession += $bytesRead
        $downloadedTotal = $start + $downloadedThisSession

        $elapsed = (Get-Date) - $sessionStart
        $speed = if ($elapsed.TotalSeconds -gt 0) { $downloadedThisSession / $elapsed.TotalSeconds } else { 0 }

        if ($totalLength -gt 0 -and $speed -gt 0) {
            $remaining = $totalLength - $downloadedTotal
            $etaSeconds = $remaining / $speed
            $progress = ($downloadedTotal / $totalLength) * 100
            $etaFormatted = Format-ETA $etaSeconds
            Write-Host -NoNewline "`rDownloaded: $(Format-Size $downloadedTotal) / $(Format-Size $totalLength) ($([math]::Round($progress,2))%) | Speed: $(Format-Speed $speed) | ETA: $etaFormatted   "
        } else {
            Write-Host -NoNewline "`rDownloaded: $(Format-Size $downloadedTotal) | Speed: $(Format-Speed $speed) | ETA: Unknown   "
        }
    }

    $stream.Close(); $fs.Close(); $response.Dispose(); $client.Dispose()
    Write-Host "`nDownload finished: $OutFile"
    return $true
}

# ---------- Download-WithResume (parallel ranged downloader with probe + fallbacks) ----------
function Download-WithResume {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [int]$Parts = 0,                 # 0 = auto-probe and choose
        [int]$BufferSize = 4 * 1024 * 1024,  # per-download buffer (4 MiB)
        [int]$MaxRetriesPerPart = 3
    )

    # If caller asked for auto-probe (Parts=0), run probe to choose parts
    if ($Parts -le 0) {
        try {
            $probeMax = 16
            $candidates = @(4,8,12)
            $recommended = Probe-ChooseParts -Url $Url -MaxCandidate $probeMax -Candidates $candidates
            if ($recommended -and $recommended -gt 0) { $Parts = $recommended } else { $Parts = 4 }
            Write-Host "Auto-probe selected $Parts parallel parts."
        } catch {
            $Parts = 4
            Write-Warning "Probe failed; falling back to $Parts parts."
        }
    }

    # Prepare temp part files directory
    $outDir = Split-Path -Parent $OutFile
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }

    $partPrefix = "$OutFile.part"
    $globalStartTime = Get-Date

    # Query headers to verify ranges supported and get content length
    try {
        if (-not ("System.Net.Http.HttpClient" -as [type])) {
            Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue
        }
        $handler = New-Object System.Net.Http.HttpClientHandler
        try { $handler.MaxConnectionsPerServer = [int]16 } catch {}
        $hc = New-Object System.Net.Http.HttpClient($handler)
        $headReq = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Head, $Url)
        $headResp = $hc.SendAsync($headReq).Result
    } catch {
        try { $headResp = $hc.SendAsync((New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url))).Result } catch { throw "Failed to obtain remote headers: $_" }
    }

    if ($headResp.StatusCode -ge [System.Net.HttpStatusCode]::BadRequest) {
        throw "Failed to reach URL: $($headResp.StatusCode) $($headResp.ReasonPhrase)"
    }

    $acceptRanges = $false
    if ($headResp.Headers.Contains("Accept-Ranges")) {
        $vals = $headResp.Headers.GetValues("Accept-Ranges") -join ","
        if ($vals -match "bytes") { $acceptRanges = $true }
    }
    $contentLength = $null
    if ($headResp.Content.Headers.ContentLength -ne $null) { $contentLength = [long]$headResp.Content.Headers.ContentLength }

    if (-not $contentLength) {
        try {
            $resp = $hc.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
            if ($resp.Content.Headers.ContentLength -ne $null) { $contentLength = [long]$resp.Content.Headers.ContentLength }
            if (-not $acceptRanges -and $resp.Headers.Contains("Accept-Ranges")) {
                $vals = $resp.Headers.GetValues("Accept-Ranges") -join ","
                if ($vals -match "bytes") { $acceptRanges = $true }
            }
            $resp.Dispose()
        } catch {}
    }

    # If we don't have content length or ranges are not supported, throw so caller can fallback to BITS/single
    if (-not $contentLength -or -not $acceptRanges) {
        if ($hc) { $hc.Dispose() }
        throw "Server does not support ranged downloads (or length unknown)."
    }

    Write-Host "Remote file size: $(Format-Size $contentLength). Using $Parts parallel parts."

    # Build ranges
    $partSize = [math]::Floor($contentLength / $Parts)
    $ranges = @()
    for ($i = 0; $i -lt $Parts; $i++) {
        $start = $i * $partSize
        if ($i -eq ($Parts - 1)) { $end = $contentLength - 1 } else { $end = ($start + $partSize - 1) }
        $ranges += @{ Index = $i; Start = [long]$start; End = [long]$end; Path = "$partPrefix$i" }
    }

    # For each part, if a part file exists, determine bytes already present and adjust start
    foreach ($p in $ranges) {
        if (Test-Path $p.Path) {
            try {
                $len = (Get-Item $p.Path).Length
                $fullLen = $p.End - $p.Start + 1
                if ($len -ge $fullLen) {
                    Write-Host "Part $($p.Index) already complete (skipping)."
                    $p.State = 'Complete'; $p.Current = $len; continue
                } elseif ($len -gt 0) {
                    $p.Current = $len
                    $p.Start = $p.Start + $len
                    Write-Host "Resuming part $($p.Index): already have $(Format-Size $len). New range: $($p.Start)-$($p.End)"
                } else {
                    $p.Current = 0
                }
            } catch { $p.Current = 0 }
        } else {
            $p.Current = 0
        }
        $p.State = 'Pending'
    }

    # Start thread-jobs to download parts concurrently
    $jobs = @()
    foreach ($p in $ranges) {
        if ($p.State -eq 'Complete') { continue }
        $script = {
            param($Url, $start, $end, $outPath, $bufferSize, $maxRetries, $index)

            if (-not ("System.Net.Http.HttpClient" -as [type])) {
                Add-Type -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\System.Net.Http.dll" -ErrorAction SilentlyContinue
            }
            $handler = New-Object System.Net.Http.HttpClientHandler
            try { $handler.MaxConnectionsPerServer = [int]8 } catch {}
            $client = New-Object System.Net.Http.HttpClient($handler)
            $attempt = 0
            $succeeded = $false

            while (-not $succeeded -and $attempt -lt $maxRetries) {
                $attempt++
                try {
                    # Prepare request with Range header
                    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
                    $rangeHeader = [System.Net.Http.Headers.RangeHeaderValue]::new($start, $end)
                    $req.Headers.Range = $rangeHeader

                    $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
                    if ($resp.StatusCode -eq [System.Net.HttpStatusCode]::PartialContent -or $resp.StatusCode -eq [System.Net.HttpStatusCode]::OK) {
                        $stream = $resp.Content.ReadAsStreamAsync().Result
                        # Open file for append (create if needed)
                        $fs = [System.IO.File]::Open($outPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                        $fs.Seek(0, 'End') | Out-Null

                        $buffer = New-Object byte[] $bufferSize
                        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                            $fs.Write($buffer, 0, $read)
                        }

                        $fs.Close(); $stream.Close(); $resp.Dispose()
                        $succeeded = $true
                        $client.Dispose()
                        return @{ Index = $index; Status = 'OK' }
                    } else {
                        $resp.Dispose()
                        throw "Unexpected status code: $($resp.StatusCode)"
                    }
                } catch {
                    Start-Sleep -Seconds (2 * $attempt)
                    # retry
                }
            }

            $client.Dispose()
            return @{ Index = $index; Status = 'Failed' }
        }

        $job = Start-ThreadJob -ArgumentList $Url, $p.Start, $p.End, $p.Path, $BufferSize, $MaxRetriesPerPart, $p.Index -ScriptBlock $script
        $jobs += @{ Job = $job; Part = $p }
    }

    # Monitor progress by polling part sizes and compute ETA
    $sessionStart = Get-Date
    while ($true) {
        # Gather sizes
        $downloaded = 0
        foreach ($p in $ranges) {
            if (Test-Path $p.Path) {
                try { $downloaded += (Get-Item $p.Path).Length } catch {}
            }
        }
        $elapsed = (Get-Date) - $sessionStart
        $speedSession = if ($elapsed.TotalSeconds -gt 0) { $downloaded / $elapsed.TotalSeconds } else { 0 }
        $progress = ($downloaded / $contentLength) * 100
        $remaining = $contentLength - $downloaded
        $eta = if ($speedSession -gt 0) { [math]::Round($remaining / $speedSession) } else { -1 }
        $etaFormatted = if ($eta -ge 0) { (if ($eta -ge 3600) { '{0}h {1}m {2}s' -f ([math]::Floor($eta/3600)), ([math]::Floor(($eta%3600)/60)), ($eta%60) } elseif ($eta -ge 60) { '{0}m {1}s' -f ([math]::Floor($eta/60)), ($eta%60) } else { '{0}s' -f $eta }) } else { "Unknown" }

        Write-Host -NoNewline "`rProgress: $([math]::Round($progress,2))% | Downloaded: $(Format-Size $downloaded) / $(Format-Size $contentLength) | Speed(sess): $(Format-Speed $speedSession) | ETA: $etaFormatted     "

        # Check jobs: collect results and mark completed
        $allDone = $true
        foreach ($entry in $jobs) {
            $j = $entry.Job
            if ($j.State -eq 'Completed' -or $j.State -eq 'Failed' -or $j.State -eq 'Stopped') {
                if (-not $entry.Collected) {
                    $res = Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue
                    if ($res) {
                        if ($res.Status -ne 'OK') {
                            Write-Host "`nPart $($entry.Part.Index) failed to complete."
                            foreach ($rem in $jobs) { if ($rem.Job.State -eq 'Running') { Stop-Job -Job $rem.Job -Force -ErrorAction SilentlyContinue } }
                            throw "One or more part downloads failed. Aborting."
                        } else {
                            $entry.Collected = $true
                        }
                    } else {
                        try {
                            $wantLen = ($entry.Part.End - $entry.Part.Start + 1) + $entry.Part.Current
                            $actual = (Get-Item $entry.Part.Path).Length
                            if ($actual -ge $wantLen) { $entry.Collected = $true } else { Write-Host "`nPart $($entry.Part.Index) might be incomplete." }
                        } catch {}
                    }
                }
            } else {
                $allDone = $false
            }
        }

        if ($allDone) { break }
        Start-Sleep -Seconds 1
    }

    # Merge parts
    Write-Host "`nMerging parts..."
    try {
        $outFs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        foreach ($p in $ranges | Sort-Object Index) {
            $partPath = $p.Path
            if (-not (Test-Path $partPath)) { throw "Missing part file: $partPath" }
            $fsPart = [System.IO.File]::OpenRead($partPath)
            $buffer = New-Object byte[] (4 * 1024 * 1024)
            while (($read = $fsPart.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $outFs.Write($buffer, 0, $read)
            }
            $fsPart.Close()
        }
        $outFs.Close()
    } catch {
        throw "Failed to merge parts: $_"
    }

    foreach ($p in $ranges) { try { Remove-Item -Path $p.Path -Force -ErrorAction SilentlyContinue } catch {} }

    $totalElapsed = (Get-Date) - $globalStartTime
    $avgSpeed = if ($totalElapsed.TotalSeconds -gt 0) { (Get-Item $OutFile).Length / $totalElapsed.TotalSeconds } else { 0 }
    Write-Host "`nDownload complete: $OutFile | Avg speed: $(Format-Speed $avgSpeed) | Time: $([math]::Round($totalElapsed.TotalSeconds))s"

    if ($hc) { $hc.Dispose() }
    return $true
}

# ---------- Step 0: If file exists, try mount to verify; otherwise download with resume & verify ----------
$downloadSuccess = $false
if (Test-Path $destination) {
    Write-Host "`nFile already exists: $destination"
    Write-Host "Attempting to mount to verify integrity..."
    try {
        $null = Mount-DiskImage -ImagePath $destination -ErrorAction Stop -PassThru
        $null = Dismount-DiskImage -ImagePath $destination -ErrorAction SilentlyContinue
        Write-Host "ISO mounted and dismounted successfully. Integrity OK."
        $downloadSuccess = $true
    } catch {
        Write-Warning "Existing ISO failed to mount. Will re-download/resume."
        Remove-Item $destination -Force -ErrorAction SilentlyContinue
    }
}

if (-not $downloadSuccess) {
    try {
        Write-Host "`nAttempting parallel ranged download (preferred)..."
        try {
            Download-WithResume -Url $isoUrl -OutFile $destination -Parts 0
            $usedMethod = "parallel"
        } catch {
            Write-Warning "Parallel ranged downloader failed: $_"
            Write-Host "Attempting Windows BITS transfer as a fallback..."
            try {
                if (-not (Get-Command -Name Start-BitsTransfer -ErrorAction SilentlyContinue)) {
                    throw "BITS not available in this environment."
                }
                try { if (Test-Path $destination) { Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue } } catch {}
                Start-BitsTransfer -Source $isoUrl -Destination $destination -TransferType Download -Description "Win11 ISO download via BITS" -Priority Foreground
                $usedMethod = "bits"
                Write-Host "BITS transfer completed."
            } catch {
                Write-Warning "BITS transfer failed: $_"
                Write-Host "Falling back to single-connection resume downloader..."
                try {
                    Download-WithResumeSingle -Url $isoUrl -OutFile $destination
                    $usedMethod = "single"
                } catch {
                    Write-Error "All download methods failed: $_"
                    throw "Download failed via parallel, BITS, and single methods."
                }
            }
        }

        if (-not (Test-Path $destination)) {
            Write-Error "Download completed but destination file not found: $destination"
            exit 1
        }

        Write-Host "Download completed using method: $usedMethod"

        $expected = Resolve-ChecksumString -checksumOrUrl $Checksum
        if ($expected) {
            $ok = Verify-FileSHA256 -filePath $destination -expectedHex $expected
            if (-not $ok) {
                Write-Warning "Checksum verification failed. Removing file and aborting."
                Remove-Item $destination -Force -ErrorAction SilentlyContinue
                throw "Checksum mismatch"
            }
        } else {
            Write-Host "No checksum configured; skipping SHA256 verification."
        }
    } catch {
        Write-Error "Download/verify flow failed: $_"
        exit 1
    }
}

# ---------- Step 2: Mount ISO (clean unmount first) ----------
Write-Host "`nUnmounting any ISO images previously mounted..."
try {
    $mounted = Get-DiskImage | Where-Object { $_.ImagePath -ne $null }
    foreach ($mi in $mounted) { try { Dismount-DiskImage -ImagePath $mi.ImagePath -ErrorAction SilentlyContinue } catch {} }
} catch {}

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
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
Write-Host "`nDetected System Manufacturer: $manufacturer"

# CPU lists (WhyNotWin11)
$intelListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsIntel.txt"
$amdListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsAMD.txt"
$qualcommListUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsQualcomm.txt"

# Get raw CPU name
$cpu = Get-CimInstance -ClassName Win32_Processor
$rawCpuName = $cpu.Name.Trim()

# Extract clean CPU model string (keep original extraction logic)
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
$secureBootEnabled = Get-SecureBootStatus
$tpmCompatible = Check-TPM

# Display results
Write-Host "`nWindows 11 Compatibility Check" -ForegroundColor Cyan
Write-Host "-----------------------------------"
Write-Host "`nProcessor: $rawCpuName"
Write-Host "`n64-bit CPU: " + (if ($cpu64Bit) { "Yes" } else { "No" })
Write-Host "CPU Speed: $cpuSpeedGHz GHz"
Write-Host "Secure Boot Enabled: " + (if ($secureBootEnabled) { "Yes" } else { "No" })
Write-Host "TPM 2.0 Support: " + (if ($tpmCompatible) { "Yes" } else { "No" })
Write-Host "CPU Support (known-list): " + (if ($cpuSupported) { "Yes" } else { "No" })

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
            Write-Host " - Applied $($b.Name) at $($b.Path)"
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
    Write-Host "`nAll bypass keys applied. /product server will be used." -ForegroundColor Cyan
} else {
    Write-Host "`nNot all bypass keys were applied. /product server will NOT be used." -ForegroundColor Cyan
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
