$paths = @(
 "HKLM:\SOFTWARE\JavaSoft\Java Update\Policy",
 "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy",
 "HKLM:\SOFTWARE\Policies\JavaSoft\Java Update\Policy",
 "HKLM:\SOFTWARE\WOW6432Node\Policies\JavaSoft\Java Update\Policy"
)
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    Set-ItemProperty -Path $p -Name "EnableJavaUpdate" -Value 1 -Type DWord
    Set-ItemProperty -Path $p -Name "EnableAutoUpdateCheck" -Value 1 -Type DWord
}
Get-ScheduledTask | Where-Object { $_.TaskName -match "Java.*Update|jusched|jucheck" -or $_.TaskPath -match "Java" } |
    Enable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
