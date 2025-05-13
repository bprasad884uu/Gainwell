# Function to check the installation of applications
function Get-ApplicationInstallation {
    param (
        [string]$AppName
    )

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regPath in $regPaths) {
        $appKey = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | Where-Object {
            $_.GetValue("DisplayName") -like "*$AppName*"
        }

        if ($appKey) {
            $appVersion = $appKey.GetValue("DisplayVersion")
            $architecture = if ($regPath -like "*WOW6432Node*") { "x86" } else { "x64" }
            return @{
                Installed = $true
                Version = $appVersion
                Architecture = $architecture
            }
        }
    }

    return @{ Installed = $false }
}

# Function to fetch the latest version of Mozilla products
function Get-LatestMozillaVersion {
    param (
        [string]$ProductName,
        [string]$Key
    )
    
    $apiUrl = "https://product-details.mozilla.org/1.0/$ProductName" 

    try {
        $jsonData = Invoke-WebRequest -Uri $apiUrl -UseBasicParsing | ConvertFrom-Json
        return $jsonData.$Key
    } catch {
        Write-Host "Failed to fetch the latest version for $ProductName. Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Download-LatestInstaller {
    param (
        [string]$Application,
        [string]$Architecture
    )

    $url = ""

    switch ($Application.ToLower()) {
        "firefox" {
            $url = if ($Architecture -eq "x64") {
                "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US"
            } else {
                "https://download.mozilla.org/?product=firefox-latest&os=win&lang=en-US"
            }
        }
        "firefox-esr" {
            $url = if ($Architecture -eq "x64") {
                "https://download.mozilla.org/?product=firefox-esr-latest-ssl&os=win64&lang=en-US"
            } else {
                "https://download.mozilla.org/?product=firefox-esr-latest-ssl&os=win&lang=en-US"
            }
        }
        "thunderbird" {
            $url = if ($Architecture -eq "x64") {
                "https://download.mozilla.org/?product=thunderbird-latest-SSL&os=win64&lang=en-US"
            } else {
                "https://download.mozilla.org/?product=thunderbird-latest-SSL&os=win&lang=en-US"
            }
        }
        "thunderbird-esr" {
            $url = if ($Architecture -eq "x64") {
                "https://download.mozilla.org/?product=thunderbird-esr-SSL&os=win64&lang=en-US"
            } else {
                "https://download.mozilla.org/?product=thunderbird-esr-SSL&os=win&lang=en-US"
            }
        }
        default {
            Write-Host "Invalid application name: $Application" -ForegroundColor Red
            return $null
        }
    }

    # Debug the constructed URL
    if ([string]::IsNullOrEmpty($url)) {
        Write-Host "Download URL is blank for $Application." -ForegroundColor Red
        return $null
    } else {
        Write-Host "Download $Application $Architecture Installer..." -ForegroundColor Green
    }

    # Construct the output file path
    $outputPath = "$env:TEMP\$Application" + "_$Architecture.exe"

    try {
        Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing
        return $outputPath
    } catch {
        Write-Host "Failed to download installer for $Application. Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


# Function to install the application
function Install-Application {
    param (
        [string]$InstallerPath
    )

    Start-Process -FilePath $InstallerPath -ArgumentList "/S /PreventRebootRequired=true" -Wait

    # Delete the installer after installation
    if (Test-Path -Path $InstallerPath) {
        Remove-Item -Path $InstallerPath -Force
    }
}

# Initialize flag for found applications
$mozillaProductFound = $false

Write-Host "Checking for Mozilla applications..."

$products = @(
    @{ DisplayName = "Mozilla Firefox"; DownloadName = "firefox"; Key = "LATEST_FIREFOX_VERSION"; Json = "firefox_versions.json" },
    @{ DisplayName = "Mozilla Firefox ESR"; DownloadName = "firefox-esr"; Key = "FIREFOX_ESR"; Json = "firefox_versions.json" },
    @{ DisplayName = "Mozilla Thunderbird"; DownloadName = "thunderbird"; Key = "LATEST_THUNDERBIRD_VERSION"; Json = "thunderbird_versions.json" },
    @{ DisplayName = "Mozilla Thunderbird ESR"; DownloadName = "thunderbird-esr"; Key = "LATEST_THUNDERBIRD_VERSION"; Json = "thunderbird_versions.json" }
)

foreach ($product in $products) {
    $info = Get-ApplicationInstallation -AppName $product.DisplayName
    if ($info.Installed) {
        $mozillaProductFound = $true  # Mark that at least one product is found
        $latestVersion = Get-LatestMozillaVersion -ProductName $product.Json -Key $product.Key
        if ($latestVersion) {
            if ($info.Version -eq $latestVersion) {
                Write-Host "$($product.DisplayName) is up to date (Version: $($info.Version), Architecture: $($info.Architecture))."
            } else {
                Write-Host "$($product.DisplayName) is outdated (Installed: $($info.Version), Architecture: $($info.Architecture), Latest: $latestVersion)."
                $installer = Download-LatestInstaller -Application $product.DownloadName -Architecture $info.Architecture
                if ($installer) {
                    Install-Application -InstallerPath $installer

                    # Recheck version after installation
                    $updatedInfo = Get-ApplicationInstallation -AppName $product.DisplayName
                    if ($updatedInfo.Version -eq $latestVersion) {
                        Write-Host "$($product.DisplayName) has been updated to version $($info.Version), Architecture: $($info.Architecture)."
                    } else {
                        Write-Host "$($product.DisplayName) is not able to update." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Installer file not found for $($product.DisplayName). Skipping installation." -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "Failed to determine the latest version of $($product.DisplayName)." -ForegroundColor Yellow
        }
    }
}

# Check if no Mozilla products were found and display message
if (-not $mozillaProductFound) {
    Write-Host "No Mozilla product found." -ForegroundColor Yellow
}
