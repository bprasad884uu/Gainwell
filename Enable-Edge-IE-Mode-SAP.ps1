# ==================================================
# Permanent IE Mode for SAP URLs (Microsoft Edge)
# Uses Enterprise Mode Site List (No Expiry)
# ==================================================

# ---------- CONFIG ----------
$XmlFolder = "C:\Edge"
$XmlFile   = "IE-Mode-Sites.xml"
$XmlPath   = Join-Path $XmlFolder $XmlFile

# SAP URLs (host + port is enough)
$Sites = @(
    "pc1tiplap1.tiplindia.com:8001",
    "pc1tiplap2.tiplindia.com:8002",
    "pc1tiplscs.tiplindia.com:8000",
    "pc1tipldb.tiplindia.com:8000",
    "tiplcrm.tiplindia.com:8100"
)

# ---------- CREATE FOLDER ----------
if (!(Test-Path $XmlFolder)) {
    New-Item -Path $XmlFolder -ItemType Directory -Force | Out-Null
}

# ---------- BUILD XML ----------
$SiteXml = foreach ($site in $Sites) {
@"
  <site url="$site">
    <compat-mode>IE9</compat-mode>
    <document-mode>9</document-mode>
    <open-in>IE11</open-in>
  </site>
"@
}

$XmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<site-list version="1">
$($SiteXml -join "`n")
</site-list>
"@

# ---------- WRITE XML ----------
$XmlContent | Out-File -FilePath $XmlPath -Encoding UTF8 -Force
Write-Host "[OK] Enterprise Mode XML created: $XmlPath" -ForegroundColor Green

# ---------- APPLY EDGE POLICIES ----------
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Enable IE Mode
Set-ItemProperty -Path $RegPath `
    -Name "InternetExplorerIntegrationLevel" `
    -Type DWord `
    -Value 1

# Set Enterprise Mode Site List path
Set-ItemProperty -Path $RegPath `
    -Name "InternetExplorerIntegrationSiteList" `
    -Type String `
    -Value "file:///C:/Edge/IE-Mode-Sites.xml"

Write-Host "[OK] IE Mode permanently enabled for both SAP sites" -ForegroundColor Green
Write-Host "[INFO] Close and reopen Microsoft Edge" -ForegroundColor Cyan
