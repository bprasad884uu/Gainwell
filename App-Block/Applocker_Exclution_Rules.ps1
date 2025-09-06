# ================================
# AppLocker Rule Add Template
# ================================

# --- CHANGE THESE VARIABLES ---
$ruleType       = "Exe"   # Options: Exe, Dll, Script, Msi, Appx
$action         = "Allow" # Options: Allow, Deny
$ruleName       = "Allow Notepad++"
$description    = "Allow Notepad++ EXE"
$targetPath     = "%PROGRAMFILES%\Notepad++\notepad++.exe"  # Path or wildcard
$userOrGroupSid = "S-1-1-0"  # Default = Everyone (S-1-1-0)
$outFile        = "$env:Temp\AppLocker-Patched.xml"

# --- DO NOT CHANGE BELOW UNLESS NEEDED ---

# 1. Export current AppLocker policy (as XML string)
$xml = Get-AppLockerPolicy -Effective -Xml

# 2. Load XML into an editable object
$policy = [xml]$xml

# 3. Create a new <FilePathRule> element
$newRule = $policy.CreateElement("FilePathRule")
$newRule.SetAttribute("Id", ([guid]::NewGuid().ToString()))  # Unique GUID for the rule
$newRule.SetAttribute("Name", $ruleName)                     # Friendly name
$newRule.SetAttribute("Description", $description)           # Optional description
$newRule.SetAttribute("UserOrGroupSid", $userOrGroupSid)     # Target user/group
$newRule.SetAttribute("Action", $action)                     # "Allow" or "Deny"

# 4. Build the <Conditions> container
$conditions = $policy.CreateElement("Conditions")

# 5. Add the actual condition (FilePathCondition for path-based rule)
$condition  = $policy.CreateElement("FilePathCondition")
$condition.SetAttribute("Path", $targetPath)  # Path or wildcard (e.g., %PROGRAMFILES%\App\*)
$conditions.AppendChild($condition) | Out-Null

# 6. Attach <Conditions> to the new rule
$newRule.AppendChild($conditions) | Out-Null

# 7. Find the correct RuleCollection (Exe, Dll, Script, Msi, Appx)
$targetCollection = $policy.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $ruleType }

# 8. Insert the new rule into that collection
$targetCollection.AppendChild($newRule) | Out-Null

# 9. Save the updated policy to a file
$policy.OuterXml | Out-File $outFile -Encoding UTF8
Write-Host "Saved patched policy to $outFile"

# 10. Apply the policy immediately
Set-AppLockerPolicy -XmlPolicy $outFile
Write-Host "Applied new AppLocker rule: $ruleName ($action $ruleType)"

# 11. Apply policy
try {
    Write-Host "`nApplying AppLocker policy (Enforce) ..."
    Set-AppLockerPolicy -XmlPolicy $outFile
    gpupdate /force | Out-Null

    # ensure AppIDSvc is configured & restarted
    sc.exe config appidsvc start= auto | Out-Null
    try { Restart-Service -Name AppIDSvc -Force -ErrorAction Stop; Write-Host "`nAppIDSvc restarted." } catch { Write-Warning "`nCould not restart AppIDSvc; reboot may be required." }

    Write-Host "`nAppLocker policy applied in ENFORCE mode. Check Event Viewer > Microsoft > Windows > AppLocker for events."
} catch {
    Write-Error "`nFailed to apply AppLocker policy: $_"
    exit 1
}
