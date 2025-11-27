<#
.SYNOPSIS
    Detects, installs, or upgrades the CrowdStrike Sensor Platform. 
    Systems belonging to Resurgent Mining Solutions Private Limited (RMSPL) are excluded.

.DESCRIPTION
    - Identifies the system’s company based on hostname first, then domain name.
    - Company detection uses a dynamic configuration list and prints both short code 
      and full company name (for example: ASPL (Acceleron Solutions Private Limited)).
    - If the detected company is Resurgent Mining Solutions Private Limited (RMSPL), 
      the script stops without installing or upgrading CrowdStrike.

    - Detects an existing CrowdStrike installation using:
        * Exact uninstall registry entry: "CrowdStrike Sensor Platform"
        * Fallback service check: CSFalconService executable version

    - If CrowdStrike is not installed:
        * Downloads WindowsSensor.exe (if not already present)
        * Installs silently using:
              /quiet /norestart CID=<customer-id> ProvNoWait=1

    - If CrowdStrike is already installed:
        * Script attempts to upgrade using the same EXE and arguments.
        * If upgrade fails, the script does not stop or throw errors.
          It simply reports the currently installed version.

    - All messages are informational only, using a consistent format like:
          [INFO]  ...
          [WARN]  ...
          [OK]    ...
#>

param(
    [string]$InstallerUrl  = "https://github.com/bprasad884uu/Gainwell/raw/refs/heads/main/Falcon/WindowsSensor.exe",
    [string]$InstallerPath = "$env:TEMP\WindowsSensor.exe",
    [switch]$ForceDownload = $false
)

function Info { param($m) Write-Output "[INFO]  $m" }
function Warn { param($m) Write-Output "[WARN]  $m" }
function OK   { param($m) Write-Output "[OK]    $m" }

# ---------------------------
# Company detection (with full names)
# ---------------------------
$system = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
$hostname = $system.HostName
$domain   = $system.DomainName

# If not domain joined, display workgroup as "Not joined (WORKGROUP)"
if ([string]::IsNullOrWhiteSpace($domain)) {
    $workgroup = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Workgroup
    $domain = "Not joined ($workgroup)"
    $isDomainJoined = $false
} else {
    $isDomainJoined = $true
}

$CompanyConfig = @(
    @{ Code = "GCPL"; FullName = "Gainwell Commosales Private Limited"; Domains = @("gainwellindia.com");        HostnamePatterns = @("GCPL") },
    @{ Code = "GEPL"; FullName = "Gainwell Engineering Private Limited"; Domains = @("gainwellengineering.com"); HostnamePatterns = @("GEPL") },
    @{ Code = "RMSPL";FullName = "Resurgent Mining Solutions Private Limited"; Domains = @();                      HostnamePatterns = @("RMSPL") },
    @{ Code = "GTPL"; FullName = "Gainwell Trucking Private Limited";     Domains = @();                      HostnamePatterns = @("GTPL") },
    @{ Code = "ASPL"; FullName = "Acceleron Solutions Private Limited";   Domains = @();                      HostnamePatterns = @("ASPL") },
    @{ Code = "TIL";  FullName = "Tractors India Limited";                Domains = @("tiplindia.com");       HostnamePatterns = @("TIL") },
    @{ Code = "GESPL";  FullName = "Gainwell Engineering Services Private Limited";                Domains = @();       HostnamePatterns = @("GESPL") }
	
)

$companyCode = ""
$companyFull = ""

# Hostname-first detection
foreach ($cfg in $CompanyConfig) {
    foreach ($p in $cfg.HostnamePatterns) {
        if ($hostname -match $p) {
            $companyCode = $cfg.Code
            $companyFull = $cfg.FullName
            break
        }
    }
    if ($companyCode) { break }
}

# Domain fallback
if (-not $companyCode -and $isDomainJoined) {
    foreach ($cfg in $CompanyConfig) {
        foreach ($d in $cfg.Domains) {
            if ($d.ToLower() -eq $domain.ToLower()) {
                $companyCode = $cfg.Code
                $companyFull = $cfg.FullName
                break
            }
        }
        if ($companyCode) { break }
    }
}

if ([string]::IsNullOrWhiteSpace($companyCode)) { 
    $companyCode = "UNKNOWN"
    $companyFull = ""
    Warn "Unknown hostname detected."
}

Info "Hostname: $hostname"
Info "Domain: $domain"
if ($companyFull) {
    Info "Company: $companyCode ($companyFull)"
} else {
    Info "Company: $companyCode"
}

# Exclude RMSPL
if ($companyCode -eq "RMSPL") {
    Warn "CrowdStrike installation is excluded for: Resurgent Mining Solutions Private Limited."
    return
}

# ---------------------------
# Detection: exact DisplayName
# ---------------------------
$ExpectedDisplayName = "CrowdStrike Sensor Platform"
function Get-CSInfo {
    $result = [PSCustomObject]@{
        Installed = $false
        DisplayName = $null
        DisplayVersion = $null
        DetectionDetails = @()
    }

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($p in $regPaths) {
        try {
            $items = Get-ChildItem -Path $p -ErrorAction SilentlyContinue
            foreach ($k in $items) {
                $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if ($props -and $props.DisplayName -and ($props.DisplayName -eq $ExpectedDisplayName)) {
                    $result.Installed = $true
                    $result.DisplayName = $props.DisplayName
                    $result.DisplayVersion = $props.DisplayVersion
                    $result.DetectionDetails += "Registry match in $p : $($props.PSChildName)"
                    return $result
                }
            }
        } catch {
            $result.DetectionDetails += "Registry read error ($p): $($_.Exception.Message)"
        }
    }

    # fallback: check service presence (best-effort)
    try {
        $svc = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
        if ($svc) {
            $result.DetectionDetails += "Service CSFalconService present (Status: $($svc.Status))"
            $exe = Get-ChildItem -Path "$env:ProgramFiles*", "$env:ProgramFiles(x86)*" -Recurse -Include "CSFalconService.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
            if ($exe) {
                try {
                    $ver = (Get-Item $exe).VersionInfo.ProductVersion
                    $result.Installed = $true
                    $result.DisplayName = "CrowdStrike (detected via service exe)"
                    $result.DisplayVersion = $ver
                    $result.DetectionDetails += "Executable found: $exe (Version: $ver)"
                } catch {
                    $result.DetectionDetails += "Could not read version from executable: $($_.Exception.Message)"
                }
            }
        }
    } catch {
        $result.DetectionDetails += "Service check error: $($_.Exception.Message)"
    }

    return $result
}

# ---------------------------
# Version helper (added)
# ---------------------------
function Convert-ToVersionObj {
    param([string]$verString)
    if ([string]::IsNullOrWhiteSpace($verString)) { return $null }
    # extract numeric version like 7.29.20108.0
    if ($verString -match '([0-9]+(\.[0-9]+)*)') {
        $num = $matches[1]
        try {
            return [version]$num
        } catch {
            # normalize to 4 parts
            $parts = $num.Split('.') | ForEach-Object { [int]$_ }
            while ($parts.Count -lt 4) { $parts += 0 }
            while ($parts.Count -gt 4) { $parts = $parts[0..3] }
            return [version]("$($parts -join '.')")
        }
    }
    return $null
}

$MinRequiredVersion = Convert-ToVersionObj "7.28"

# ---------------------------
# Ensure installer available
# ---------------------------
function Ensure-Installer {
    param($Url, $OutFile, $Force)
    if (-not $Force -and (Test-Path -LiteralPath $OutFile)) {
        Info "Installer already present at $OutFile"
        return $true
    }

    Info "Downloading installer from $Url to $OutFile ..."
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
        OK "Download finished."
        return $true
    } catch {
        Warn "Download failed: $($_.Exception.Message)"
        return $false
    }
}

# ---------------------------
# Run installer
# ---------------------------
$InstallArgs = '/quiet /norestart CID=48906A261FF14523938183CA12D77D9B-BE ProvNoWait=1'

function Run-Installer {
    param($ExePath, $Arguments)
    if (-not (Test-Path -LiteralPath $ExePath)) {
        Warn "Installer not found at $ExePath"
        return @{ Success = $false; ExitCode = -1 }
    }
    Info "Starting installer: `"$ExePath`" $Arguments"
    try {
        $p = Start-Process -FilePath $ExePath -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        $exit = $p.ExitCode
        Info "Installer exit code: $exit"
        return @{ Success = ($exit -eq 0); ExitCode = $exit }
    } catch {
        Warn "Installer start/execute failed: $($_.Exception.Message)"
        return @{ Success = $false; ExitCode = -2 }
    }
}

# ---------------------------
# Main flow
# ---------------------------
$cs = Get-CSInfo
if ($cs.Installed) {
    Info "CrowdStrike detected."
    Info "Version: $($cs.DisplayVersion)"

    # Determine if upgrade is required based on version
    $currentVerObj = Convert-ToVersionObj $cs.DisplayVersion
    $forceUpgradeByVersion = $false

    if ($currentVerObj -ne $null) {
        if ($currentVerObj -lt $MinRequiredVersion) {
            Info "Installed version ($currentVerObj) is below required $($MinRequiredVersion). Will upgrade."
            $forceUpgradeByVersion = $true
        }
    } else {
        Warn "Could not parse installed version. Proceeding with upgrade for safety."
        $forceUpgradeByVersion = $true
    }

    # Decide if we need the installer: either version forces it or user forced download
    $needInstaller = $forceUpgradeByVersion -or $ForceDownload
    $haveInstaller = $true
    if ($needInstaller) {
        $haveInstaller = Ensure-Installer -Url $InstallerUrl -OutFile $InstallerPath -Force:$ForceDownload
    } else {
        # If no need and no force, check if user provided a local installer path
        if (Test-Path -LiteralPath $InstallerPath) { $haveInstaller = $true } else { $haveInstaller = $false }
    }

    if (-not $haveInstaller) {
        if ($forceUpgradeByVersion -or $ForceDownload) {
            Warn "No installer available to perform required upgrade."
        } else {
            Info "CrowdStrike Falcon is already up to date. No action required."
        }
        return
    }

    # If upgrade not required and not forced, skip installer execution
    if (-not $forceUpgradeByVersion -and -not $ForceDownload) {
        OK "CrowdStrike Falcon is already up to date. No action required."
        return
    }

    # Proceed with upgrade
    Info "Attempting upgrade using installer..."
    $r = Run-Installer -ExePath $InstallerPath -Arguments $InstallArgs

    if ($r.Success) {
        OK "Upgrade completed (installer exit code 0)."
        $csNew = Get-CSInfo
        if ($csNew.Installed) {
            OK "Installed version: $($csNew.DisplayVersion)"
        } else {
            OK "Installed version: $($cs.DisplayVersion)"
        }
    } else {
        Warn "Upgrade returned non-success..."
        OK "Installed version remains: $($cs.DisplayVersion)"
    }

    return
}

# Not installed -> install
Info "CrowdStrike not detected. Preparing to install."

$dlOk = Ensure-Installer -Url $InstallerUrl -OutFile $InstallerPath -Force:$ForceDownload
if (-not $dlOk) {
    Warn "Installer download failed. Cannot proceed with installation. Exiting."
    return
}

$insRes = Run-Installer -ExePath $InstallerPath -Arguments $InstallArgs
if ($insRes.Success) {
    OK "Installation completed (installer exit code 0). Re-checking installation..."
    $post = Get-CSInfo
    if ($post.Installed) {
        OK "Installed version: $($post.DisplayVersion)"
    } else {
        OK "Installer returned success but registry/exe detection did not find expected DisplayName. Check service/installation manually."
    }
} else {
    Warn "Installation attempt returned non-success (exit code $($insRes.ExitCode) or failed to run)."
    $post = Get-CSInfo
    if ($post.Installed) {
        OK "However CrowdStrike now appears installed. Version: $($post.DisplayVersion)"
    } else {
        Warn "CrowdStrike still not detected after installation attempt."
    }
}
