# Revert Nearby Sharing and Mobile Hotspot Restrictions
# Scope: All users (Machine-wide)
# Execution: Administrator / SYSTEM

$ErrorActionPreference = 'Stop'

try {
    # 1. Remove Nearby Sharing / Cross-device policy
    $SystemPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'

    if (Test-Path $SystemPolicy) {
        Remove-ItemProperty -Path $SystemPolicy -Name 'EnableCdp' -ErrorAction SilentlyContinue
    }

    # 2. Remove Mobile Hotspot / ICS policy
    $NetworkPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'

    if (Test-Path $NetworkPolicy) {
        Remove-ItemProperty -Path $NetworkPolicy -Name 'NC_ShowSharedAccessUI' -ErrorAction SilentlyContinue
    }

    # 3. Restore Mobile Hotspot service
    Set-Service -Name 'icssvc' -StartupType Manual

    # 4. Apply computer policies
    & gpupdate.exe /target:computer /force | Out-Null

    # 5. Verify
    $SystemValue = Get-ItemProperty -Path $SystemPolicy -Name 'EnableCdp' -ErrorAction SilentlyContinue
    $NetworkValue = Get-ItemProperty -Path $NetworkPolicy -Name 'NC_ShowSharedAccessUI' -ErrorAction SilentlyContinue
    $HotspotService = Get-CimInstance Win32_Service -Filter "Name='icssvc'"

    if ($null -eq $SystemValue.EnableCdp -and
        $null -eq $NetworkValue.NC_ShowSharedAccessUI -and
        $HotspotService.StartMode -eq 'Manual') {

        Write-Output 'Nearby Sharing: Restrictions Removed'
        Write-Output 'Mobile Hotspot: Restrictions Removed'
    }
    else {
        throw 'Revert verification failed.'
    }
}
catch {
    Write-Error "Revert failed: $($_.Exception.Message)"
    exit 1
}
