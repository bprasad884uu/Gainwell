# -------------------------
# Helper: Get pwsh version
# -------------------------
function Write-OK([string]$msg){ Write-Host "`n[OK] $msg" -ForegroundColor Green }
function Write-Info([string]$msg){ Write-Host "`n[..] $msg" -ForegroundColor Cyan }
function Write-Warn([string]$msg){ Write-Warning $msg }
function Write-Err([string]$msg){ Write-Host "`n[ERR] $msg" -ForegroundColor Red }

Write-Info "Reverting system-wide PowerShell redirect..."

$AllUsersProfile = "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1"
$MarkerStart = "# >>> PWSH REDIRECT START"
$MarkerEnd   = "# <<< PWSH REDIRECT END"

if (Test-Path $AllUsersProfile) {

    $content = Get-Content $AllUsersProfile -Raw

    if ($content -match [regex]::Escape($MarkerStart)) {

        $newContent = [regex]::Replace(
            $content,
            "$MarkerStart[\s\S]*?$MarkerEnd",
            ""
        ).Trim()

        if ([string]::IsNullOrWhiteSpace($newContent)) {
            Remove-Item $AllUsersProfile -Force
            Write-OK "Redirect removed and empty profile deleted."
        }
        else {
            Set-Content $AllUsersProfile $newContent
            Write-OK "Redirect block removed from All Users profile."
        }

    } else {
        Write-Info "No redirect block found. Nothing to revert."
    }

} else {
    Write-Info "All Users profile does not exist. Nothing to revert."
}
