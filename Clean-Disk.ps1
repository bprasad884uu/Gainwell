<# 
.SYNOPSIS
    Deep Disk Cleanup Script (ASCII Only, No GUI)
.DESCRIPTION
    Cleans system/user temp files, cache, logs, delivery optimization, etc.
    Includes optional SSD TRIM and DryRun mode.
.PARAMETER DryRun
    If specified, simulates deletions without actually removing files.
.PARAMETER TrimSSD
    If specified, optimizes all detected SSD drives.
.EXAMPLE
    .\DeepDiskCleanup.ps1 -DryRun
    .\DeepDiskCleanup.ps1 -TrimSSD
#>

param(
    [switch]$DryRun = $false,		# Set to $true to Enable DryRun by default
	[switch]$TrimSSDs = $true		# New: Perform TRIM on SSDs after cleanup
)

function Show-Banner {
@"
 ____  __  ____  _  _  __ _  _  _ 
(  _ \(  )/ ___)/ )( \(  ( \/ )( \
 ) _ ( )( \___ \) __ (/    /) \/ (
(____/(__)(____/\_)(_/\_)__)\____/
     BISHNU STYLE - DEEP CLEAN POWER MODE
"@ | Write-Host -ForegroundColor Cyan
}

function Show-ProgressBar {
    param (
        [int]$Current,
        [int]$Total,
        [string]$Message = "Cleaning"
    )

    if ($Total -eq 0) {
        #Write-Host "`r[>] No tasks to process. Skipping progress bar..." -ForegroundColor DarkGray
        return
    }

    $percent = [math]::Round(($Current / $Total) * 100)
    $barLength = 50
    $filledLength = [math]::Floor(($percent / 100) * $barLength)
    $bar = '=' * $filledLength + '>' + ' ' * ($barLength - $filledLength)
    Write-Host -NoNewline "`r[$bar] $percent% - $Message" -ForegroundColor Magenta
}

function Report-Drives {
    Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, 
    @{Name='TotalSize';Expression={[math]::Round($_.Size / 1GB, 2)}},
    @{Name='FreeSpace';Expression={[math]::Round($_.FreeSpace / 1GB, 2)}},
    @{Name='UsedSpace';Expression={[math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)}}
}

function Drive-Space {
    Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, 
    @{Name='TotalSize';Expression={[math]::Round($_.Size / 1GB, 2)}},
    @{Name='FreeSpace';Expression={[math]::Round($_.FreeSpace / 1GB, 2)}},
    @{Name='UsedSpace';Expression={[math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)}},
	@{Name='Used%';Expression={[math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1)}}
}

function Format-Size {
    param (
        [Parameter(Mandatory=$true)]
        [long]$size
    )
    
    if ($size -ge 1TB) { return "{0:N2} TB" -f ($size / 1TB) }
    if ($size -ge 1GB) { return "{0:N2} GB" -f ($size / 1GB) }
    if ($size -ge 1MB) { return "{0:N2} MB" -f ($size / 1MB) }
    if ($size -ge 1KB) { return "{0:N2} KB" -f ($size / 1KB) }
    return "$size bytes"
}

function Report-Drive-Space {
    Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $drive = $_

        # Calculate percentage used and free
        $usedPercent = [math]::Round((($drive.Size - $drive.FreeSpace) / $drive.Size) * 100, 1)
        $freePercent = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 1)

        # Assign status tags based on used space percentage
        if ($usedPercent -lt 80) {
            $statusTag = "[OK]"
            $statusColor = "Green"
        } elseif ($usedPercent -lt 90) {
            $statusTag = "[WARNING]"
            $statusColor = "Yellow"
        } else {
            $statusTag = "[CRITICAL]"
            $statusColor = "Red"
        }

        # Output with formatted sizes and status
        Write-Host "`nDeviceID  : $($drive.DeviceID)" -ForegroundColor Cyan
        Write-Host "TotalSize : $(Format-Size $drive.Size)" -ForegroundColor White
        Write-Host "FreeSpace : $(Format-Size $drive.FreeSpace)" -ForegroundColor Green
        Write-Host "UsedSpace : $(Format-Size ($drive.Size - $drive.FreeSpace))" -ForegroundColor Yellow

        # Used and Free percentages with appropriate coloring
        Write-Host "Used%     : " -NoNewline
        Write-Host "$usedPercent %" -ForegroundColor $statusColor

        Write-Host "Free%     : " -NoNewline
        Write-Host "$freePercent %" -ForegroundColor Green
				
		# Status with color
        Write-Host "`n[Status]   : " -NoNewline
        Write-Host "$statusTag" -ForegroundColor $statusColor
    }
}

function SSD-Optimize {
    $ssds = Get-PhysicalDisk | Where-Object { $_.MediaType -eq 'SSD' }

    if ($ssds.Count -eq 0) {
        Write-Host "`n[!] No SSD found." -ForegroundColor Red
        return
    }

    Write-Host "`n[+] SSD TRIM Optimization..." -ForegroundColor Cyan

    $totalDisks = $ssds.Count
    $index = 0

    foreach ($disk in $ssds) {
        $index++
        Show-ProgressBar -Current $index -Total $totalDisks -Message "Optimizing Disk"

        Write-Host "`nSSD found: $($disk.FriendlyName)" -ForegroundColor Yellow

        $trimStatus = fsutil behavior query DisableDeleteNotify
        if ($trimStatus -match 'DisableDeleteNotify = 0') {
            Write-Host "TRIM is already enabled." -ForegroundColor Green
        } else {
            Write-Host "Enabling TRIM..." -ForegroundColor Cyan
            fsutil behavior set DisableDeleteNotify 0 | Out-Null
            Write-Host "TRIM has been enabled." -ForegroundColor Green
        }

        $diskNumber = (Get-Disk | Where-Object { $_.FriendlyName -eq $disk.FriendlyName }).Number
        $partitions = Get-Partition -DiskNumber $diskNumber
        foreach ($partition in $partitions) {
            if ($partition.DriveLetter) {
                Write-Host "Performing manual TRIM on drive $($partition.DriveLetter)..." -ForegroundColor Cyan
                Optimize-Volume -DriveLetter $partition.DriveLetter -ReTrim
                Write-Host "`nManual TRIM completed on drive $($partition.DriveLetter)." -ForegroundColor Green
            }
        }
    }

    Write-Host "`nSSD optimization completed." -ForegroundColor Cyan
}

$beforeCleanUp = Report-Drives

$global:startTime = Get-Date
Show-Banner

function Remove-JunkFiles {
    param(
        [string[]]$Paths,
        [string]$SectionName
    )

    $totalFreed = 0
    $startTime = Get-Date
    $totalItems = 0
    $currentItem = 0
    $items = @()  # Initialize the items array

    Write-Host "`n=== [$SectionName] ===" -ForegroundColor Cyan

    # Accumulate items before processing
    foreach ($path in $Paths) {
        if (Test-Path $path) {
            try {
                $items += Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Access denied: $path"
            }
        }
    }

    $totalItems = $items.Count

    foreach ($item in $items) {
        $currentItem++
        Show-ProgressBar -Current $currentItem -Total $totalItems -Message "Removing: $SectionName"
        try {
            $size = 0
            if (-not $item.PSIsContainer) {
                $size = $item.Length
            }
            if ($DryRun) {
                Write-Host "`r(DryRun) Would delete: $($item.FullName)           " -ForegroundColor Gray -NoNewline
                $totalFreed += $size
            } else {
                #Write-Host "`rFile Deleted: $($item.FullName)           " -ForegroundColor DarkGray -NoNewline
                Remove-Item $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
                $totalFreed += $size
            }
        } catch {
            Write-Warning "`nCould not delete: $($item.FullName)"
        }

        #Start-Sleep -Milliseconds 100  # Adding slight delay for progress bar smoothness
    }

    $duration = (Get-Date) - $startTime
    $freedMB = [math]::Round($totalFreed / 1MB, 2)
    if (-not $DryRun) {
        Write-Host "`n-- Freed $freedMB MB in section '$SectionName' (Time taken: $("{0:N2}" -f $duration.TotalSeconds) sec)" -ForegroundColor Green
    }

    return $totalFreed
}

if (-not $DryRun) {
    Write-Host "`n==> Stopping Windows Update service..." -ForegroundColor Yellow
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
	Stop-Service usosvc -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

$totalCleaned = 0

# User directories cleanup with progress
$userDirs = Get-ChildItem "C:\Users" -Directory
$totalUserDirs = $userDirs.Count
$currentUserDir = 0
$totalCleaned = 0

foreach ($user in $userDirs) {
    $currentUserDir++
    $userProfile = $user.FullName

    # User-specific temporary/cache locations
    $userPaths = @(
        "$userProfile\AppData\Local\Temp",
        "$userProfile\AppData\Roaming\Microsoft\Windows\Recent",
        "$userProfile\AppData\Local\Microsoft\Windows\Explorer", # Thumbnails
        "$userProfile\AppData\Local\Microsoft\Windows\INetCache",
        "$userProfile\AppData\Local\Microsoft\Edge\User Data\Default\Cache",
        "$userProfile\AppData\Local\Google\Chrome\User Data\Default\Cache",
        "$userProfile\AppData\Local\Mozilla\Firefox\Profiles",
        "$userProfile\AppData\Local\D3DSCache" # DirectX Shader Cache
    )

    # Common app cache/bloat folders (Teams, OneDrive, Adobe, etc.)
    $knownAppCaches = @(
        "$userProfile\AppData\Roaming\Microsoft\Teams\Cache",
        "$userProfile\AppData\Roaming\Microsoft\Teams\GPUCache",
        "$userProfile\AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage",
        "$userProfile\AppData\Local\Microsoft\OneDrive\logs",
        "$userProfile\AppData\Local\Adobe\CameraRaw\Cache",
        "$userProfile\AppData\Roaming\Adobe\Common\Media Cache Files",
        "$userProfile\AppData\Roaming\Adobe\Common\Media Cache"
    )

    # Combine paths
    $allPathsToClean = $userPaths + $knownAppCaches

    foreach ($path in $allPathsToClean) {
        Show-ProgressBar -Current $currentUserDir -Total $totalUserDirs -Message "Cleaning: $path"
        $totalCleaned += Remove-JunkFiles -Paths @($path) -SectionName "User/App Cache: $path"
    }
}
$systemPaths = @(
    "C:\Windows\Temp",
    "C:\Windows\Logs",
    "C:\Windows\Prefetch",
    "C:\Windows\SoftwareDistribution\Download",
    "C:\Windows\SoftwareDistribution\DataStore",
    "C:\Windows\System32\LogFiles",
    "C:\ProgramData\Microsoft\Windows Defender\Scans\History",
    "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache",
    "C:\Windows\Panther",
    "C:\$WINDOWS.~BT",
    "C:\$Windows.~WS",
    "C:\Windows.old",
    "C:\ProgramData\USOPrivate\UpdateStore",
    "C:\ProgramData\Microsoft\Windows\WER",
    "C:\ProgramData\Microsoft\Diagnosis",
    "C:\Program Files\rempl",
    "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp",
    "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp",
    "C:\Windows\DeliveryOptimization",
    "C:\Windows\Downloaded Program Files",
    "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Projects"
)

$totalSystemPaths = $systemPaths.Count
$currentSystemPath = 0

foreach ($path in $systemPaths) {
    $currentSystemPath++
    Show-ProgressBar -Current $currentSystemPath -Total $totalSystemPaths -Message "Cleaning System Paths:  $path"

    # Special handling for Windows.old
    if ($path -eq "C:\Windows.old" -and (Test-Path $path) -and -not $DryRun) {
        try {
            takeown /F $path /A /R /D Y | Out-Null
            icacls $path /grant Administrators:F /T | Out-Null
			Remove-Item -Path "C:\Windows.old" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Failed to reset permissions for $path ($($_.Exception.Message))" -ForegroundColor Red
        }
    }

    $totalCleaned += Remove-JunkFiles -Paths @($path) -SectionName "System Cleanup: $path"
}

function Clear-RecycleBin {
    $start = Get-Date
    $freed = 0
    $totalItems = 0
    $currentItem = 0

    # Get all filesystem drives
    $drives = Get-PSDrive -PSProvider FileSystem

    # First pass: Count total items in all recycle bins for progress tracking
    foreach ($drive in $drives) {
        $recyclePath = Join-Path $drive.Root '$Recycle.Bin'
        if (Test-Path $recyclePath) {
            try {
                $items = Get-ChildItem -Path $recyclePath -Recurse -Force -ErrorAction SilentlyContinue
                $totalItems += $items.Count
            } catch {
                Write-Host "Failed to count items in: $recyclePath ($($_.Exception.Message))" -ForegroundColor Yellow
            }
        }
    }

    # Second pass: Delete or simulate deletion
    foreach ($drive in $drives) {
        $recyclePath = Join-Path $drive.Root '$Recycle.Bin'
        if (Test-Path $recyclePath) {
            try {
                $itemsToDelete = Get-ChildItem -Path $recyclePath -Recurse -Force -ErrorAction SilentlyContinue
                $beforeSize = ($itemsToDelete | Measure-Object -Property Length -Sum).Sum

                if ($DryRun) {
                    Write-Host "(DryRun) Would delete: $recyclePath" -ForegroundColor Gray
                    $freed += $beforeSize
                } else {
                    foreach ($item in $itemsToDelete) {
                        try {
                            Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                            if ($item.PSIsContainer) {
                                # Folders have no length
                                $freed += 0
                            } else {
                                $freed += ($item.Length | ForEach-Object { $_ -as [int64] })
                            }
                        } catch {
								if (-not $_.Exception.Message.Contains("because it does not exist")) {
									Write-Host "Failed to delete item: $($item.FullName) ($($_.Exception.Message))" -ForegroundColor Yellow
									}
								}
                        $currentItem++
                        $percentComplete = if ($totalItems -gt 0) { ($currentItem / $totalItems) * 100 } else { 100 }
                        Write-Progress -PercentComplete $percentComplete -Activity "Cleaning Recycle Bin" -Status "Deleting items..." -CurrentOperation "$currentItem of $totalItems"
                    }
                    Write-Host "`nDeleted: $recyclePath" -ForegroundColor DarkGray
                }
            } catch {
                Write-Host "`nFailed to delete from: $recyclePath ($($_.Exception.Message))" -ForegroundColor Yellow
            }
        }
    }

    # Refresh Recycle Bin UI (only if not a dry run)
    if (-not $DryRun) {
        try {
            $shell = New-Object -ComObject Shell.Application
            $shell.NameSpace(0x0a).Self.InvokeVerb("R&efresh")
        } catch {
            Write-Host "`nCould not refresh Recycle Bin UI" -ForegroundColor Yellow
        }

        $time = (Get-Date) - $start
        $freedMB = [math]::Round($freed / 1MB, 2)
        Write-Host "`n-- Freed $freedMB MB in section 'Recycle Bin' (Time taken: $("{0:N2}" -f $time.TotalSeconds) sec)" -ForegroundColor Green
    }

    return $freed
}

$totalCleaned += Clear-RecycleBin

if (-not $DryRun) {
    Write-Host "`n==> Restarting Windows Update service..." -ForegroundColor Yellow
    Start-Service wuauserv -ErrorAction SilentlyContinue
	Start-Service usosvc -ErrorAction SilentlyContinue	
}

if ($TrimSSDs) {
    SSD-Optimize
}

$totalMB = [math]::Round($totalCleaned / 1MB, 2)
Write-Host "`n==============================" -ForegroundColor White
if ($DryRun) {
    Write-Host " DRY RUN COMPLETE - No files were deleted" -ForegroundColor Yellow
    Write-Host " Potential space to free: $totalMB MB" -ForegroundColor Yellow
} else {
    Write-Host " CLEANUP COMPLETE" -ForegroundColor Cyan
    Write-Host " Total disk space freed: $totalMB MB" -ForegroundColor Cyan
}
Write-Host "==============================" -ForegroundColor White

if ($totalMB -eq 0 -and -not $DryRun) {
    Write-Host "`nNothing significant found to clean." -ForegroundColor DarkYellow
}

$afterCleanup = Drive-Space

# Show the Before and After available space
foreach ($before in $beforeCleanup) {
    $after = $afterCleanup | Where-Object { $_.DeviceID -eq $before.DeviceID }
    if ($after) {
        $beforeFree = [decimal]$before.FreeSpace
        $afterFree  = [decimal]$after.FreeSpace
        $diff       = $afterFree - $beforeFree
        $absDiff    = [math]::Abs($diff)

        $label = if ($diff -lt 0) { "Used" } else { "Freed" }

        if ($absDiff -lt 1) {
            $diffValue = [math]::Round($absDiff * 1024, 1)
            $unit = "MB"
        } else {
            $diffValue = [math]::Round($absDiff, 3)
            $unit = "GB"
        }

        Write-Host "`nDrive $($before.DeviceID):"
        Write-Host " Before Cleanup - Free Space: $beforeFree GB"
        Write-Host " After Cleanup  - Free Space: $afterFree GB"
        Write-Host " Difference     - ${label}: $diffValue $unit`n"
    }
}
# Optional: Summarize drive-reported differences
$sumOfDifferences = 0
foreach ($before in $beforeCleanup) {
    $after = $afterCleanup | Where-Object { $_.DeviceID -eq $before.DeviceID }
    if ($after) {
        $diff = [decimal]$after.FreeSpace - [decimal]$before.FreeSpace
        $sumOfDifferences += $diff * 1024  # Convert GB diff to MB
    }
}

Write-Host "`n------------------------------" -ForegroundColor DarkGray

$sumOfDifferences = [math]::Round($sumOfDifferences, 2)
$avgUsedPercent = ($afterCleanup | Measure-Object -Property 'Used%' -Average).Average
Write-Host "`n[Summary Comparison]" -ForegroundColor White
Write-Host " Reported per-drive freed space : $sumOfDifferences MB" -ForegroundColor Yellow
Write-Host " Total deleted file size        : $totalMB MB" -ForegroundColor Cyan
Write-Host " Difference (if any)            : $([math]::Round($totalMB - $sumOfDifferences, 2)) MB" -ForegroundColor Gray
Write-Host " Avg. Drive Utilization After Cleanup : $([math]::Round($avgUsedPercent, 1))%" -ForegroundColor DarkCyan

Write-Host "`n------------------------------" -ForegroundColor DarkGray
Report-Drive-Space

$global:endTime = Get-Date
$elapsedTime = $global:endTime - $global:startTime

# Format elapsed time string based on non-zero values
$timeParts = @()
if ($elapsedTime.Hours -gt 0) {
    $timeParts += "$($elapsedTime.Hours) hour" + ($(if ($elapsedTime.Hours -ne 1) { "s" }))
}
if ($elapsedTime.Minutes -gt 0) {
    $timeParts += "$($elapsedTime.Minutes) minute" + ($(if ($elapsedTime.Minutes -ne 1) { "s" }))
}
if ($elapsedTime.Seconds -gt 0 -or $timeParts.Count -eq 0) {
    $timeParts += "$($elapsedTime.Seconds) second" + ($(if ($elapsedTime.Seconds -ne 1) { "s" }))
}
$elapsedStr = $timeParts -join ", "

Write-Host "`n==============================" -ForegroundColor White
Write-Host " Start Time : $($startTime.ToString('dd/MM/yyyy HH:mm:ss'))" -ForegroundColor Gray
Write-Host " End Time   : $($endTime.ToString('dd/MM/yyyy HH:mm:ss'))" -ForegroundColor Gray
Write-Host "`nSystem cleaned in: $elapsedStr" -ForegroundColor DarkYellow
Write-Host "==============================" -ForegroundColor White
