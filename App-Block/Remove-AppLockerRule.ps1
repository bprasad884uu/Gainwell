<#
.SYNOPSIS
  Interactive AppLocker rule lister + removal or toggle (supports Index or partial Name match).
  No backups; applies changes immediately.
.NOTES
  Run as Administrator.
#>

# --- Admin check ---
if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "Please run this script from an elevated (Administrator) PowerShell session."
    exit 1
}

# --------------------------
# Helper: Build indexed rule list
# --------------------------
function Get-AppLockerRuleIndexList {
    try {
        $xmlText = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
    } catch {
        throw "Failed to read effective AppLocker policy. $_"
    }

    [xml]$policy = $xmlText

    $rules = @()
    $globalIndex = 0
    foreach ($rc in $policy.AppLockerPolicy.RuleCollection) {
        foreach ($child in $rc.ChildNodes) {
            $globalIndex++
            $cond = $child.SelectSingleNode("Conditions/*")
            # safe condition summary (not all condition types have 'Path' attribute)
            $condSummary = ""
            if ($cond -ne $null) {
                try { $condSummary = $cond.GetAttribute("Path") } catch { $condSummary = $cond.OuterXml }
            }

            $rules += [PSCustomObject]@{
                Index         = $globalIndex
                CollectionType= $rc.Type
                ElementType   = $child.LocalName
                Name          = $child.GetAttribute("Name")
                Id            = $child.GetAttribute("Id")
                Action        = $child.GetAttribute("Action")
                Description   = $child.GetAttribute("Description")
                Condition     = $condSummary
                XmlNode       = $child
                ParentNode    = $rc
            }
        }
    }

    return [PSCustomObject]@{
        PolicyXml = $policy
        Rules     = $rules
    }
}

# --------------------------
# Interactive removal/toggle (supports partial name matching)
# --------------------------
function Invoke-InteractiveAppLockerRemoval {
    $data   = Get-AppLockerRuleIndexList
    $policy = $data.PolicyXml
    $rules  = $data.Rules

    if ($rules.Count -eq 0) {
        Write-Host "No AppLocker rules found." -ForegroundColor Yellow
        return
    }

    Write-Host "`nCurrent AppLocker rules:" -ForegroundColor Cyan
    $rules | Select-Object Index, CollectionType, Action, Name, Condition | Format-Table -AutoSize

    $userChoice = Read-Host "`nEnter rule Index(es) (e.g. 3,7 or 2-5) and/or Name tokens (comma-separated). Type 'q' to quit"
    if ($userChoice.Trim().ToLower() -eq 'q' -or [string]::IsNullOrWhiteSpace($userChoice)) {
        Write-Host "Aborted by user. No changes made." -ForegroundColor Yellow
        return
    }

    # Parse numeric indexes (supports ranges like 2-5)
    function Parse-Indexes([string]$s) {
        $out = @()
        foreach ($p in ($s -split '[,;]+')) {
            $t = $p.Trim()
            if ($t -match '^\d+-\d+$') {
                $bounds = $t -split '-'
                $start = [int]$bounds[0]; $end = [int]$bounds[1]
                if ($end -ge $start) { $out += ($start..$end) }
            } elseif ($t -match '^\d+$') {
                $out += [int]$t
            }
        }
        return $out | Sort-Object -Unique
    }

    $indexes = Parse-Indexes $userChoice

    # Extract name tokens (anything not a pure index/range)
    $nameTokens = @()
    foreach ($part in ($userChoice -split '[,;]+')) {
        $t = $part.Trim()
        if ($t -eq '') { continue }
        if ($t -match '^\d+(-\d+)?$') { continue }    # skip numeric parts
        $nameTokens += $t
    }

    # Build list of rules to act on
    $toAct = @()

    if ($indexes) {
        $toAct += $rules | Where-Object { $indexes -contains $_.Index }
    }

    if ($nameTokens) {
        foreach ($token in $nameTokens) {
            $lc = $token.ToLower()
            # partial, case-insensitive match against rule Name
            $matches = $rules | Where-Object { $_.Name -and ($_.Name.ToLower().Contains($lc)) }
            if ($matches) { $toAct += $matches }
        }
    }

    # Deduplicate by Id
    $toAct = $toAct | Sort-Object -Property Id -Unique

    if (-not $toAct) {
        Write-Host "No matching rules found." -ForegroundColor Yellow
        return
    }

    Write-Host "`nRules matched:" -ForegroundColor Magenta
    $toAct | Select-Object Index, CollectionType, Action, Name, Condition | Format-Table -AutoSize

    # Ask user which operation to perform
    Write-Host ""
    Write-Host "Choose operation:" -ForegroundColor Cyan
    Write-Host "  1) DELETE  - remove the selected rule(s) completely" -ForegroundColor Gray
    Write-Host "  2) TOGGLE  - flip Action between Allow and Deny for each selected rule" -ForegroundColor Gray
    Write-Host "  Q) Cancel" -ForegroundColor Gray
    $op = Read-Host "Enter 1 or 2 (DELETE/TOGGLE) or Q to cancel"
    if ($op.Trim().ToLower() -eq 'q' -or [string]::IsNullOrWhiteSpace($op)) {
        Write-Host "Cancelled by user." -ForegroundColor Yellow
        return
    }

    if ($op.Trim() -eq '1') {
        $operation = 'DELETE'
    } elseif ($op.Trim() -eq '2') {
        $operation = 'TOGGLE'
    } else {
        Write-Host "Invalid choice. Exiting." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    $confirm = Read-Host "Type YES to confirm operation '$operation' on the above rule(s)"
    if ($confirm -ne "YES") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    # Perform operation
    foreach ($r in $toAct) {
        try {
            if ($operation -eq 'DELETE') {
                $r.ParentNode.RemoveChild($r.XmlNode) | Out-Null
                Write-Host "Deleted: $($r.Name) (Index $($r.Index))" -ForegroundColor Green
            } else {
                # Toggle Allow <-> Deny
                $current = $r.XmlNode.GetAttribute("Action")
                if ($current -eq "Allow") {
                    $r.XmlNode.SetAttribute("Action","Deny")
                    Write-Host "Toggled to Deny: $($r.Name) (Index $($r.Index))" -ForegroundColor Yellow
                } elseif ($current -eq "Deny") {
                    $r.XmlNode.SetAttribute("Action","Allow")
                    Write-Host "Toggled to Allow: $($r.Name) (Index $($r.Index))" -ForegroundColor Green
                } else {
                    Write-Warning "Rule $($r.Name) (Index $($r.Index)) has unexpected Action '$current' and was skipped."
                }
            }
        } catch {
            Write-Warning "Failed to apply operation to $($r.Name): $_"
        }
    }

    # Apply modified policy
    $tmpFile = [IO.Path]::GetTempFileName()
    $policy.OuterXml | Out-File $tmpFile -Encoding UTF8
    try {
        Set-AppLockerPolicy -XmlPolicy $tmpFile -ErrorAction Stop
        Write-Host "Patched AppLocker policy applied." -ForegroundColor Green
    } catch {
        Write-Error "Failed to apply policy: $_"
    } finally {
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }

    # Refresh GP and restart AppIDSvc
    gpupdate /force | Out-Null
    sc.exe config appidsvc start= auto | Out-Null
    try {
        Restart-Service -Name AppIDSvc -Force -ErrorAction Stop
        Write-Host "AppIDSvc restarted." -ForegroundColor Green
    } catch {
        Write-Warning "Could not restart AppIDSvc; a reboot may be required."
    }
}

# --------------------------
# Non-interactive helper (unchanged)
# --------------------------
function Remove-AppLockerRule {
    [CmdletBinding()]
    param(
        [int[]]$Index,
        [string[]]$Name,
        [string[]]$Id,
        [switch]$Force
    )

    $data   = Get-AppLockerRuleIndexList
    $policy = $data.PolicyXml
    $rules  = $data.Rules

    $matches = @()
    if ($Index) { $matches += $rules | Where-Object { $Index -contains $_.Index } }
    if ($Name)  { foreach ($n in $Name) { $matches += $rules | Where-Object { $_.Name -and ($_.Name.ToLower().Contains($n.ToLower())) } } }
    if ($Id)    { $matches += $rules | Where-Object { $Id -contains $_.Id } }
    $matches = $matches | Sort-Object -Property Id -Unique

    if (-not $matches) {
        Write-Host "No matching rules found." -ForegroundColor Yellow
        return
    }

    if (-not $Force) {
        Write-Host "Rules to remove:" -ForegroundColor Yellow
        $matches | Select-Object Index, CollectionType, Action, Name, Condition | Format-Table -AutoSize
        $confirm = Read-Host "Type YES to proceed"
        if ($confirm -ne "YES") { return }
    }

    foreach ($r in $matches) {
        $r.ParentNode.RemoveChild($r.XmlNode) | Out-Null
        Write-Host "Removed: $($r.Name)" -ForegroundColor Green
    }

    $tmpFile = [IO.Path]::GetTempFileName()
    $policy.OuterXml | Out-File $tmpFile -Encoding UTF8
    try {
        Set-AppLockerPolicy -XmlPolicy $tmpFile -ErrorAction Stop
        Write-Host "Patched AppLocker policy applied." -ForegroundColor Green
    } catch {
        Write-Error "Failed to apply policy: $_"
    } finally {
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }

    gpupdate /force | Out-Null
    sc.exe config appidsvc start= auto | Out-Null
    try { Restart-Service -Name AppIDSvc -Force -ErrorAction Stop } catch {}
}

# --- Run interactive removal/toggle ---
Invoke-InteractiveAppLockerRemoval
