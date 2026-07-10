# ==========================
# Battery Information Script
# ==========================

$Static = Get-WmiObject -Class BatteryStaticData -Namespace "root\wmi" |
    Group-Object InstanceName -AsHashTable -AsString

$Status   = Get-CimInstance -Namespace "root\wmi" -Class BatteryStatus
$Capacity = Get-CimInstance -Namespace "root\wmi" -Class BatteryFullChargedCapacity

function Write-Cell {
    param(
        [string]$Text,
        [int]$Width,
        [string]$Color = $null
    )

    $Text = $Text.PadRight($Width)

    Write-Host " " -NoNewline

    if ($Color) {
        Write-Host $Text -NoNewline -ForegroundColor $Color
    }
    else {
        Write-Host $Text -NoNewline
    }

    Write-Host " " -NoNewline
}

foreach ($bat in $Capacity) {

    $status = $Status | Where-Object InstanceName -eq $bat.InstanceName

    $DesignedCapacity    = $Static[$bat.InstanceName].DesignedCapacity
    $FullChargedCapacity = $bat.FullChargedCapacity

    $CapacityPercent = [Math]::Round(($FullChargedCapacity * 100) / $DesignedCapacity,2)
    $BatteryLevel    = [Math]::Round(($status.RemainingCapacity * 100) / $FullChargedCapacity)

    if ($status.Charging) {
        $BatteryState = "Charging"
    }
    elseif ($status.PowerOnline -and $BatteryLevel -ge 99) {
        $BatteryState = "Fully Charged"
    }
    else {
        $BatteryState = "Discharging"
    }

    switch ($CapacityPercent) {
        {$_ -ge 80} {
            $Health = "Excellent"
            $Color  = "Green"
        }
        {$_ -ge 60} {
            $Health = "Good"
            $Color  = "Yellow"
        }
        {$_ -ge 30} {
            $Health = "Fair"
            $Color  = "DarkYellow"
        }
        default {
            $Health = "Poor"
            $Color  = "Red"
        }
    }

    $Border = "╔════════════════╦══════════════════╦════════════════╦════════════╗"
    $Middle = "╠════════════════╬══════════════════╬════════════════╬════════════╣"
    $Bottom = "╚════════════════╩══════════════════╩════════════════╩════════════╝"

    Write-Host ""
    Write-Host $Border -ForegroundColor Cyan

    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Cell "Battery Level" 14
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Cell "Battery Capacity" 16
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Cell "Battery State" 14
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Cell "Health" 10
    Write-Host "║" -ForegroundColor Cyan

    Write-Host $Middle -ForegroundColor Cyan

    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Cell "$BatteryLevel%" 14
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Cell ("{0:N2}%" -f $CapacityPercent) 16 $Color
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Cell $BatteryState 14
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Cell $Health 10 $Color
    Write-Host "║" -ForegroundColor Cyan

    Write-Host $Bottom -ForegroundColor Cyan
}