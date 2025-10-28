<# 
Disable-JavaAutoUpdate.ps1
Disables Oracle Java auto-update for both 32-bit and 64-bit on Windows.
Run as Administrator.
#>

# Stop on errors and show clear output
$ErrorActionPreference = "Stop"
Write-Host "== Java Auto-Update: Disable start =="

# --- Helper: create key and set DWORD safely ---
function Set-Dword {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [int]    $Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    Write-Host "Set $Path\$Name = $Value"
}

# --- Registry policy paths to cover both 64-bit and 32-bit views ---
$policyPaths = @(
    "HKLM:\SOFTWARE\JavaSoft\Java Update\Policy",                 # 64-bit view
    "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy",    # 32-bit view on 64-bit OS
    "HKLM:\SOFTWARE\Policies\JavaSoft\Java Update\Policy",       # AD/Local Policies - 64-bit
    "HKLM:\SOFTWARE\WOW6432Node\Policies\JavaSoft\Java Update\Policy" # Policies - 32-bit
)

# --- Disable auto updates via policy keys ---
foreach ($p in $policyPaths) {
    Set-Dword -Path $p -Name "EnableJavaUpdate" -Value 0
    Set-Dword -Path $p -Name "NotifyDownload"   -Value 0
    Set-Dword -Path $p -Name "NotifyInstall"    -Value 0
    # Some environments honor this too; set it off explicitly:
    Set-Dword -Path $p -Name "EnableAutoUpdateCheck" -Value 0
}

# --- Remove legacy Run entries (jusched) if present ---
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($rk in $runKeys) {
    if (Get-ItemProperty -Path $rk -Name "SunJavaUpdateSched" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $rk -Name "SunJavaUpdateSched" -Force
        Write-Host "Removed Run entry: $rk\SunJavaUpdateSched"
    }
}

# --- Disable any scheduled tasks related to Java Update ---
try {
    $javaTasks = Get-ScheduledTask | Where-Object {
        $_.TaskName -match "Java.*Update|Update.*Java|jusched|jucheck"
        -or $_.TaskPath -match "Java"
    }
    foreach ($t in $javaTasks) {
        Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Disabled Scheduled Task: $($t.TaskPath)$($t.TaskName)"
    }
} catch {
    Write-Host "ScheduledTask module not available or no tasks found. Continuing..."
}

# --- Kill any updater processes currently running ---
$procs = "jusched","jucheck"
foreach ($p in $procs) {
    Get-Process $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

Write-Host "== Java Auto-Update: Disable complete =="
