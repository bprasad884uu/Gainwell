<#
.SYNOPSIS
  List AppLocker rules (Index, CollectionType, ElementType, Action, Name, Id, Condition)
.NOTES
  Run as Administrator.
#>

# Admin check
if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "Run this script in an elevated (Administrator) PowerShell session."
    exit 1
}

try {
    $xmlText = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
} catch {
    Write-Error "Failed to read AppLocker policy: $_"
    exit 1
}

[xml]$policy = $xmlText

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
            Index         = $index
            CollectionType= $rc.Type
            ElementType   = $node.LocalName
            Action        = $node.GetAttribute("Action")
            Name          = $node.GetAttribute("Name")
            Id            = $node.GetAttribute("Id")
            Condition     = $condSummary
        }
    }
}

# Output as a table (easy for ManageEngine parsing or logging)
$rules | Select-Object Index, CollectionType, ElementType, Action, Name, Id, Condition | Format-Table -AutoSize
