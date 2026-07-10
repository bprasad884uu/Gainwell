# ==========================
# Battery Information Script
# ==========================

$Static = Get-WmiObject -Class BatteryStaticData -Namespace "root\wmi" | Group-Object InstanceName -AsHashTable -AsString

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
	
    # Health & Color Logic
    if ($CapacityPercent -ge 80) {
        $Health = "Excellent"
        $Color  = $PSStyle.Foreground.Green
    }
    elseif ($CapacityPercent -ge 60) {
        $Health = "Good"
        $Color  = $PSStyle.Foreground.Yellow
    }
    elseif ($CapacityPercent -ge 30) {
        $Health = "Fair"
        $Color  = $PSStyle.Foreground.BrightYellow
    }
    else {
        $Health = "Poor"
        $Color  = $PSStyle.Foreground.Red
    }

    Write-Host "--------------------------------------------------------------"
    Write-Host "Battery Level : $BatteryLevel%"

    Write-Host "Capacity      : " -NoNewline
    Write-Host "$Color$CapacityPercent%$($PSStyle.Reset)"

    Write-Host "State         : $BatteryState"

    Write-Host "Health        : " -NoNewline
    Write-Host "$Color$Health$($PSStyle.Reset)"

    Write-Host "--------------------------------------------------------------"
}
