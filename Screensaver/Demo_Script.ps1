Add-Type -AssemblyName System.Drawing

#=======================================
# STEP 1: Shared image and logo handling
#=======================================

function Convert-Base64ToImage {
    param([string]$Base64String)
    $bytes = [Convert]::FromBase64String($Base64String)
    $ms = New-Object System.IO.MemoryStream(,$bytes)
    return [System.Drawing.Image]::FromStream($ms)
}

# Detect extension from byte signature
function Get-ImageExtensionFromBytes {
    param ([byte[]]$Bytes)
    $hex = ($Bytes[0..7] | ForEach-Object { $_.ToString("X2") }) -join ""
    switch -regex ($hex) {
        '^FFD8'       { return ".jpg" }
        '^89504E47'   { return ".png" }
        '^47494638'   { return ".gif" }
        '^424D'       { return ".bmp" }
        '^52494646'   { return ".webp" }
        default       { return ".bin" }
    }
}

#========================================================
# STEP 2: Detect hostname, domain, and resolve company
#========================================================

$hostname = $env:COMPUTERNAME
$system = Get-WmiObject Win32_ComputerSystem
$domain = $system.Domain
$isDomainJoined = $system.PartOfDomain

# Dynamic company config
$CompanyConfig = @(
    @{ Name = "GCPL"; Domains = @("gainwellindia.com");       HostnamePatterns = @("GCPL") },
    @{ Name = "GEPL"; Domains = @("gainwellengineering.com"); HostnamePatterns = @("GEPL") },
    @{ Name = "RMSPL"; Domains = @();                         HostnamePatterns = @("RMSPL") },
	@{ Name = "ASPL"; Domains = @();                         HostnamePatterns = @("ASPL") },
	@{ Name = "Gainwell"; Domains = @();                         HostnamePatterns = @("Gainwell") }
)

# Company detection logic
$company = ""

# STEP 1: Prioritize hostname matching
foreach ($config in $CompanyConfig) {
    foreach ($pattern in $config.HostnamePatterns) {
        if ($hostname -match $pattern) {
            $company = $config.Name
            break
        }
    }
    if ($company) { break }
}

# STEP 2: Fallback to domain if hostname didn't match
if (-not $company -and $isDomainJoined) {
    foreach ($config in $CompanyConfig) {
        foreach ($knownDomain in $config.Domains) {
            if ($knownDomain.ToLower() -eq $domain.ToLower()) {
                $company = $config.Name
                break
            }
        }
        if ($company) { break }
    }
}

if (-not $company) {
    Write-Error "Unable to detect company from domain or hostname. Please check the Hostname or Domain. Exiting..."
    exit 1
}

#========================================
# STEP 3: Prepare and clean output folder
#========================================

$outputFolder = "C:\Windows\Web\Screensaver"
if (Test-Path $outputFolder) {
    Remove-Item "$outputFolder\*" -Force -Recurse
    Write-Host "Old files and folders deleted.`n"
} else {
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
    Write-Host "Folder created: $outputFolder`n"
}

#=======================================================
# STEP 4: Set your Base64 image strings for each company
#=======================================================

$base64BackgroundHI = @'
<PASTE BASE64 HINDI BACKGROUND IMAGE>
'@ -replace "`r`n", ""

$base64BackgroundENG = @'
<PASTE BASE64 ENGLISH BACKGROUND IMAGE>
'@ -replace "`r`n", ""

$base64LogoGCPL = @'
<PASTE BASE64 GCPL LOGO>
'@ -replace "`r`n", ""

$base64LogoGEPL = @'
<PASTE BASE64 GEPL LOGO>
'@ -replace "`r`n", ""

$base64LogoRMSPL = @'
<PASTE BASE64 RMSPL LOGO>
'@ -replace "`r`n", ""

$base64LogoASPL = @'
<PASTE BASE64 ASPL LOGO>
'@ -replace "`r`n", ""

$base64LogoGainwell = @'
<PASTE BASE64 Gainwell LOGO>
'@ -replace "`r`n", ""

##======================================================
# STEP 5: Merge logo with each background
#======================================================

function Generate-MergedImage {
    param (
        [string]$BackgroundBase64,
        [string]$LogoBase64,
        [string]$LangCode,
        [string]$Company
    )

    $background = Convert-Base64ToImage -Base64String $BackgroundBase64
    $logo = Convert-Base64ToImage -Base64String $LogoBase64

    $graphics = [System.Drawing.Graphics]::FromImage($background)
    $graphics.DrawImage($logo, 0, 0, $background.Width, $background.Height)

    $outputFile = Join-Path $outputFolder "$Company-$LangCode.jpg"
    
	# Set JPEG quality to 100%
    $jpegEncoder = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
                   Where-Object { $_.MimeType -eq "image/jpeg" }

    $encoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
    $qualityParam = [System.Drawing.Imaging.Encoder]::Quality
    $encoderParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter($qualityParam, 100L)

    $background.Save($outputFile, $jpegEncoder, $encoderParams)

    $graphics.Dispose()
    $background.Dispose()
    $logo.Dispose()

    Write-Host "`nImage Generated: $Company-$LangCode.jpg"
	
	# Show file size dynamically in KB or MB
	$fileInfo = Get-Item $outputFile
	$fileSizeBytes = $fileInfo.Length

	if ($fileSizeBytes -ge 1MB) {
		$fileSizeMB = [math]::Round($fileSizeBytes / 1MB, 2)
		Write-Host "`nFile Size: $fileSizeMB MB`n"
	} else {
		$fileSizeKB = [math]::Round($fileSizeBytes / 1KB, 2)
		Write-Host "`nFile Size: $fileSizeKB KB`n"
	}
}

# Company-to-logo mapping
$LogoMap = @{
    "GCPL" = $base64LogoGCPL
    "GEPL" = $base64LogoGEPL
	"RMSPL" = $base64LogoRMSPL
	"ASPL" = $base64LogoASPL
	"Gainwell" = $base64LogoGainwell
}

# Backgrounds for each language
$backgrounds = @{
    "HI"  = $base64BackgroundHI
    "ENG" = $base64BackgroundENG
}

#======================================================
# STEP 6: Generate for both languages
#======================================================

if ($LogoMap.ContainsKey($company)) {
    foreach ($lang in $backgrounds.Keys) {
        Generate-MergedImage -BackgroundBase64 $backgrounds[$lang] -LogoBase64 $LogoMap[$company] -LangCode $lang -Company $company
    }
} else {
    Write-Error "Logo for '$company' not found in mapping."
}
