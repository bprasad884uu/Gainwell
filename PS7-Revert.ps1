# =================================================
# REVERT PowerShell redirect (pwsh -> 5.1)
# =================================================

$AllUsersProfile = "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1"

$MarkerStart = "# >>> PWSH REDIRECT START"
$MarkerEnd   = "# <<< PWSH REDIRECT END"

if (-not (Test-Path $AllUsersProfile)) {
    Write-Host "No All-Users PowerShell profile found. Nothing to revert." -ForegroundColor Yellow
    return
}

$content = Get-Content $AllUsersProfile -Raw

if ($content -notmatch [regex]::Escape($MarkerStart)) {
    Write-Host "No pwsh redirect block found. Already reverted." -ForegroundColor Green
    return
}

# Remove only the redirect block
$updated = [regex]::Replace(
    $content,
    "$MarkerStart[\s\S]*?$MarkerEnd",
    ""
).Trim()

Set-Content -Path $AllUsersProfile -Value $updated -Encoding UTF8

Write-Host "PowerShell redirect reverted successfully." -ForegroundColor Green
Write-Host "powershell -> Windows PowerShell 5.1 restored." -ForegroundColor Cyan
cmd
taskkill /im powershell.exe /f
taskkill /im pwsh.exe /f
powershell
