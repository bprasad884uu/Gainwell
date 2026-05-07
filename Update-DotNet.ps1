#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# UTF-8 Output Fix
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [System.Text.UTF8Encoding]::new()

Clear-Host

# -----------------------------------
# Resolve winget.exe
# -----------------------------------
$winget = Get-ChildItem `
    "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller*\winget.exe" `
    -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $winget) {
    throw "winget.exe not found"
}

$winget = $winget.FullName

# -----------------------------------
# Runtime Families
# -----------------------------------
$Families = @(
    'Microsoft.DotNet.AspNetCore',
    'Microsoft.DotNet.DesktopRuntime',
    'Microsoft.DotNet.Runtime'
)

foreach ($family in $Families) {

    # -------------------------------------
    # Installed Packages
    # -------------------------------------
    $installedRaw = & $winget list $family --accept-source-agreements 2>$null

    $installed = @()

    foreach ($line in $installedRaw) {

        if ($line -match '(Microsoft\.DotNet\.\S+)\s+([\d]+(?:\.[\d]+)+)') {

            try {

                $installed += [PSCustomObject]@{
                    Id      = $Matches[1].Trim()
                    Version = [Version]$Matches[2].Trim()
                }

            } catch {}
        }
    }

    if (-not $installed) {
        continue
    }

    # -----------------------------------------
    # Search Latest Stable Version
    # -----------------------------------------
    $searchRaw = & $winget search $family --accept-source-agreements 2>$null

    $available = @()

    foreach ($line in $searchRaw) {

        if ($line -match '(Microsoft\.DotNet\.\S+)\s+([\d]+(?:\.[\d]+)+)') {

            $id  = $Matches[1].Trim()
            $ver = $Matches[2].Trim()

            if ($id -match 'Preview') {
                continue
            }

            try {

                $available += [PSCustomObject]@{
                    Id      = $id
                    Version = [Version]$ver
                }

            } catch {}
        }
    }

    if (-not $available) {
        continue
    }

    # Latest Stable Package
    $latest = $available |
        Sort-Object Version -Descending |
        Select-Object -First 1

    # ---------------------------------------
    # Application Name
    # ---------------------------------------
    $appName = switch ($family) {

        'Microsoft.DotNet.AspNetCore' {
            '.NET ASP.NET Core Runtime'
        }

        'Microsoft.DotNet.DesktopRuntime' {
            '.NET Desktop Runtime'
        }

        'Microsoft.DotNet.Runtime' {
            '.NET Runtime'
        }

        default {
            $family
        }
    }

    # Highest Installed Version
    $highestInstalled = $installed |
        Sort-Object Version -Descending |
        Select-Object -First 1

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "Application       : $appName" -ForegroundColor White
    Write-Host "Installed Version : $($highestInstalled.Version)"
    Write-Host "Latest Release    : $($latest.Version)"
    Write-Host "==================================================" -ForegroundColor Cyan

    # ---------------------------------------
    # Install Latest If Missing
    # ---------------------------------------
    $latestInstalled = $installed |
        Where-Object { $_.Id -eq $latest.Id }

    if (-not $latestInstalled) {

        Write-Host ""
        Write-Host "[UPDATE] Installing latest version..." `
            -ForegroundColor Yellow

        & $winget install `
            --id $latest.Id `
            --exact `
            --silent `
            --accept-package-agreements `
            --accept-source-agreements `
            --disable-interactivity `
			*> $null

        if ($LASTEXITCODE -eq 0) {

            Write-Host "Updated            : YES" `
                -ForegroundColor Green
        }
        else {

            Write-Host "Updated            : FAILED" `
                -ForegroundColor Red

            continue
        }
    }
    else {

        Write-Host "Updated            : NO" `
            -ForegroundColor Green
    }

    # ---------------------------------------
    # Remove Lower Versions
    # ---------------------------------------
    $removeList = $installed |
        Where-Object { $_.Id -ne $latest.Id }

    if ($removeList) {

        Write-Host ""
        Write-Host "Removing old versions..." `
            -ForegroundColor DarkYellow

        foreach ($pkg in $removeList) {

            Write-Host "  -> $($pkg.Id)  $($pkg.Version)`n"

            & $winget uninstall `
                --id $pkg.Id `
                --version $pkg.Version.ToString() `
                --exact `
                --silent `
                --accept-source-agreements `
                --disable-interactivity `
                *> $null
        }
    }

    Write-Host ""
    Write-Host "Status             : COMPLETED" `
        -ForegroundColor Green
}

Write-Host ""
Write-Host "All .NET runtime cleanup completed successfully." `
    -ForegroundColor Green