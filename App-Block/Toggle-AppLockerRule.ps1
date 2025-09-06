<#
.SYNOPSIS
  Toggle an AppLocker rule's Action between Allow and Deny and update the rule Name to match.
.DESCRIPTION
  Accepts a rule by Index or Name (partial match, case-insensitive).
  Flips Action=Allow to Deny, or Deny to Allow, updates the Name accordingly, then applies immediately.
.USAGE
  # Example 1: by index
  $ruleToToggle = 5

  # Example 2: by name (partial)
  $ruleToToggle = "Notepad"

  # Example 3: multiple rules
  $ruleToToggle = 3,"Chrome"
.NOTES
  Run as Administrator.
  No interactive prompts; use carefully.
#>

# -------------------------
# CONFIGURE: set $ruleToToggle before running
# Example:
# $ruleToToggle = 25
# $ruleToToggle = "Notepad"
# $ruleToToggle = 3,"Chrome"
# -------------------------

if (-not (Get-Variable -Name ruleToToggle -Scope Script -ErrorAction SilentlyContinue)) {
    Write-Error "Set `$ruleToToggle before running this script. (Index or Name token(s))."
    exit 1
}

# Admin check
if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "Run this script in an elevated (Administrator) PowerShell session."
    exit 1
}

# Read current effective policy
try {
    $xmlText = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
} catch {
    Write-Error "Failed to read AppLocker policy: $_"
    exit 1
}
[xml]$policy = $xmlText

# Build indexed rule list
$rules = @()
$index = 0
foreach ($rc in $policy.AppLockerPolicy.RuleCollection) {
    foreach ($node in $rc.ChildNodes) {
        $index++
        $cond = $node.SelectSingleNode("Conditions/*")
        $condSummary = ""
        if ($cond -ne $null) {
            try { $condSummary = $cond.GetAttribute("Path") } catch { $condSummary = $cond.OuterXml }
        }

        $rules += [PSCustomObject]@{
            Index      = $index
            Name       = $node.GetAttribute("Name")
            Id         = $node.GetAttribute("Id")
            Action     = $node.GetAttribute("Action")
            Condition  = $condSummary
            XmlNode    = $node
        }
    }
}

if ($rules.Count -eq 0) {
    Write-Host "No AppLocker rules found." -ForegroundColor Yellow
    exit 0
}

# Normalize input (allow single or array)
$targets = @($ruleToToggle)
$matches = @()

foreach ($item in $targets) {
    if ($item -is [int] -or ($item -as [int] -ne $null)) {
        $idx = [int]$item
        $m = $rules | Where-Object { $_.Index -eq $idx }
        if ($m) { $matches += $m } else { Write-Warning "No rule found at Index $idx" }
    } else {
        $token = [string]$item
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        $lc = $token.ToLower()
        $m = $rules | Where-Object { $_.Name -and $_.Name.ToLower().Contains($lc) }
        if ($m) { $matches += $m } else { Write-Warning "No rule Name matches token '$token'" }
    }
}

# Deduplicate matches by Id
$matches = $matches | Sort-Object -Property Id -Unique

if (-not $matches) {
    Write-Host "No matching rules to toggle." -ForegroundColor Yellow
    exit 0
}

# Toggle Action and update Name
foreach ($r in $matches) {
    $current = $r.XmlNode.GetAttribute("Action")
    $curName = $r.XmlNode.GetAttribute("Name")
    try {
        if ($current -eq "Allow") {
            # set to Deny
            $r.XmlNode.SetAttribute("Action","Deny")

            # update name: if starts with Allow/Deny, replace the first token; else prepend
            if ($curName -match '^\s*(Allow|Deny)\b(.*)$') {
                $rest = $Matches[2].Trim()
                if ($rest -ne "") { $newName = "Deny $rest" } else { $newName = "Deny" }
            } else {
                $newName = "Deny - $curName"
            }
            $r.XmlNode.SetAttribute("Name",$newName)
            Write-Host "Toggled: $($r.Name) (Index $($r.Index)) > Deny; renamed to '$newName'" -ForegroundColor Yellow

        } elseif ($current -eq "Deny") {
            # set to Allow
            $r.XmlNode.SetAttribute("Action","Allow")

            if ($curName -match '^\s*(Allow|Deny)\b(.*)$') {
                $rest = $Matches[2].Trim()
                if ($rest -ne "") { $newName = "Allow $rest" } else { $newName = "Allow" }
            } else {
                $newName = "Allow - $curName"
            }
            $r.XmlNode.SetAttribute("Name",$newName)
            Write-Host "Toggled: $($r.Name) (Index $($r.Index)) > Allow; renamed to '$newName'" -ForegroundColor Green

        } else {
            Write-Warning "Rule $($r.Name) (Index $($r.Index)) has unexpected Action '$current' and was skipped."
        }
    } catch {
        Write-Warning "Failed toggling rule $($r.Name): $_"
    }
}

# Apply modified policy
$tmpFile = [IO.Path]::GetTempFileName()
try {
    $policy.OuterXml | Out-File -FilePath $tmpFile -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy $tmpFile -ErrorAction Stop
    Write-Host "Patched AppLocker policy applied." -ForegroundColor Cyan
} catch {
    Write-Error "Failed to apply patched policy: $_"
} finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}

# Refresh policy + restart AppIDSvc
gpupdate /force | Out-Null
sc.exe config appidsvc start= auto | Out-Null
try {
    Restart-Service -Name AppIDSvc -Force -ErrorAction Stop
    Write-Host "AppIDSvc restarted." -ForegroundColor Green
} catch {
    Write-Warning "Could not restart AppIDSvc; a reboot may be required."
}
