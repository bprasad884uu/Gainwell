#==============================================
#Addition
#==============================================
$BaseDir  = "C:\Windows\System32\Acceleron\Appblocker"
$JsonPath = "$BaseDir\Blocked-apps.json"
$ExePath  = "$BaseDir\Appblocker.exe"

$json = Get-Content $JsonPath -Raw | ConvertFrom-Json

$json.apps += [PSCustomObject]@{
    name         = "UltraViewer"
    blockMessage = "UltraViewer has been blocked by your Administrator."
    matchType    = "ProcessName"
    matchValue   = "UltraViewer"
    adminExempt  = $false
}

$json | ConvertTo-Json -Depth 5 | Set-Content $JsonPath -Encoding UTF8 -Force

Get-Process -Name "Appblocker" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
Start-Process -FilePath $ExePath -WindowStyle Hidden

Write-Host "Done - UltraViewer blocked & AppBlocker restarted." -ForegroundColor Green


#==============================================
#Deletion
#==============================================
$BaseDir  = "C:\Windows\System32\Acceleron\Appblocker"
$JsonPath = "$BaseDir\Blocked-apps.json"
$ExePath  = "$BaseDir\Appblocker.exe"

$json = Get-Content $JsonPath -Raw | ConvertFrom-Json
$json.apps = $json.apps | Where-Object { $_.name -ne "TeamViewer" }
$json | ConvertTo-Json -Depth 5 | Set-Content $JsonPath -Encoding UTF8 -Force

Get-Process -Name "Appblocker" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
Start-Process -FilePath $ExePath -WindowStyle Hidden

Write-Host "Done - TeamViewer unblocked & AppBlocker restarted." -ForegroundColor Green