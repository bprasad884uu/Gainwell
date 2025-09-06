<#
.SYNOPSIS
  Non-interactive deletion of AppLocker rule(s) by Index or Name (partial, case-insensitive).
.USAGE
  # by index (single)
  $ruleToRemove = 5

  # by index (multiple)
  $ruleToRemove = 3,7,12

  # by name (partial match)
  $ruleToRemove = "Notepad"

  # by multiple name tokens
  $ruleToRemove = "Notepad","Chrome"

  Then run the script in an elevated session (ManageEngine job).
.NOTES
  Run as Administrator.
  No prompts; proceed carefully.
#>

# -------------------------
# CONFIGURE: set $ruleToRemove before running (ManageEngine job should set it)
# Example (uncomment one):
# $ruleToRemove = 5
# $ruleToRemove = 3,7
# $ruleToRemove = "Notepad"
# $ruleToRemove = "Notepad","Chrome"
# -------------------------
if (-not (Get-Variable -Name ruleToRemove -Scope Script -ErrorAction SilentlyContinue)) {
    Write-Error "Set the variable `$ruleToRemove before running this script. (Index or Name token(s))."
    exit 1
}

# Admin check
if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "Run this script in an elevated (Administrator) PowerShell session."
    exit 1
}

# Read effective policy
try {
    $xmlText = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
} catch {
    Write-Error "Failed to read AppLocker policy: $_"
    exit 1
}
[xml]$policy = $xmlText

# Build indexed rule list
$rules = @()
$globalIndex = 0
foreach ($rc in $policy.AppLockerPolicy.RuleCollection) {
    foreach ($node in $rc.ChildNodes) {
        $globalIndex++
        $cond = $node.SelectSingleNode("Conditions/*")
        $condSummary = ""
        if ($cond -ne $null) {
            try { $condSummary = $cond.GetAttribute("Path") } catch { $condSummary = $cond.OuterXml }
        }

        $rules += [PSCustomObject]@{
            Index         = $globalIndex
            CollectionType= $rc.Type
            ElementType   = $node.LocalName
            Name          = $node.GetAttribute("Name")
            Id            = $node.GetAttribute("Id")
            Action        = $node.GetAttribute("Action")
            Condition     = $condSummary
            XmlNode       = $node
            ParentNode    = $rc
        }
    }
}

if ($rules.Count -eq 0) {
    Write-Host "No AppLocker rules present." -ForegroundColor Yellow
    exit 0
}

# Decide whether input is numeric index(es) or name token(s)
# Normalize $ruleToRemove into arrays
$inputValues = @( $ruleToRemove )

# Collect matches
$toRemove = @()

foreach ($item in $inputValues) {
    if ($item -is [int] -or ($item -as [int] -ne $null)) {
        # numeric index
        $idx = [int]$item
        $match = $rules | Where-Object { $_.Index -eq $idx }
        if ($match) { $toRemove += $match } else { Write-Warning "No rule at Index $idx" }
    } else {
        # treat as string token -> partial (case-insensitive) match against rule Name
        $token = [string]$item
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        $lc = $token.ToLower()
        $matches = $rules | Where-Object { $_.Name -and $_.Name.ToLower().Contains($lc) }
        if ($matches) {
            $toRemove += $matches
        } else {
            Write-Warning "No rule Name matches token '$token'"
        }
    }
}

# Deduplicate by Id
$toRemove = $toRemove | Sort-Object -Property Id -Unique

if (-not $toRemove -or $toRemove.Count -eq 0) {
    Write-Host "No matching rules found to remove." -ForegroundColor Yellow
    exit 0
}

# Log what will be removed (console output)
Write-Host "Removing the following AppLocker rule(s):" -ForegroundColor Cyan
$toRemove | Select-Object Index, CollectionType, Action, Name, Id, Condition | Format-Table -AutoSize

# Perform removal
foreach ($r in $toRemove) {
    try {
        $r.ParentNode.RemoveChild($r.XmlNode) | Out-Null
        Write-Host "Removed: $($r.Name) (Index $($r.Index))" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to remove $($r.Name): $_"
    }
}

# Apply modified policy immediately
$tmpFile = [IO.Path]::GetTempFileName()
try {
    $policy.OuterXml | Out-File -FilePath $tmpFile -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy $tmpFile -ErrorAction Stop
    Write-Host "Patched AppLocker policy applied." -ForegroundColor Green
} catch {
    Write-Error "Failed to apply patched policy: $_"
} finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}

# Refresh group policy and ensure AppIDSvc configured and restarted
gpupdate /force | Out-Null
sc.exe config appidsvc start= auto | Out-Null
try {
    Restart-Service -Name AppIDSvc -Force -ErrorAction Stop
    Write-Host "AppIDSvc restarted." -ForegroundColor Green
} catch {
    Write-Warning "Could not restart AppIDSvc; a reboot may be required."
}
