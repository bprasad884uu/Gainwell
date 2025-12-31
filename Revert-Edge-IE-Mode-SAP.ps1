# ==========================================
# REVERT Edge IE Mode Configuration
# Removes Enterprise Mode policies & XML
# ==========================================

$XmlFolder = "C:\Edge"
$XmlFile   = "IE-Mode-Sites.xml"
$XmlPath   = Join-Path $XmlFolder $XmlFile

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

Write-Host "[INFO] Reverting Edge IE Mode configuration..." -ForegroundColor Cyan

# ---------- REMOVE REGISTRY POLICIES ----------
if (Test-Path $RegPath) {

    if (Get-ItemProperty -Path $RegPath -Name "InternetExplorerIntegrationLevel" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegPath -Name "InternetExplorerIntegrationLevel" -Force
        Write-Host "[OK] Removed InternetExplorerIntegrationLevel policy" -ForegroundColor Green
    }

    if (Get-ItemProperty -Path $RegPath -Name "InternetExplorerIntegrationSiteList" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegPath -Name "InternetExplorerIntegrationSiteList" -Force
        Write-Host "[OK] Removed Enterprise Mode Site List policy" -ForegroundColor Green
    }
}
else {
    Write-Host "[INFO] Edge policy registry path not found" -ForegroundColor Yellow
}

# ---------- REMOVE XML FILE ----------
if (Test-Path $XmlPath) {
    Remove-Item -Path $XmlPath -Force
    Write-Host "[OK] Deleted XML file: $XmlPath" -ForegroundColor Green
}
else {
    Write-Host "[INFO] XML file not found, nothing to delete" -ForegroundColor Yellow
}

# ---------- REMOVE FOLDER IF EMPTY ----------
if (Test-Path $XmlFolder) {
    if ((Get-ChildItem $XmlFolder | Measure-Object).Count -eq 0) {
        Remove-Item $XmlFolder -Force
        Write-Host "[OK] Removed folder: $XmlFolder" -ForegroundColor Green
    }
}

Write-Host "[DONE] All IE Mode changes reverted successfully" -ForegroundColor Green
Write-Host "[INFO] Close and reopen Microsoft Edge" -ForegroundColor Cyan
