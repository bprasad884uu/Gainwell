# ==========================
# AppLocker Allow Rules
# ==========================

# --- Allow an EXE ---
# $rule = New-AppLockerFileRule -RuleType Path -Path "C:\Path\To\MyApp.exe" -User "Everyone" -Action Allow -RuleCollectionType Exe
# $policy = Get-AppLockerPolicy -Local
# $policy.RuleCollections[0].FilePathRules.Add($rule)
# Set-AppLockerPolicy -PolicyObject $policy -Merge
# gpupdate /force | Out-Null
# Write-Host "✅ Exe ALLOWED: C:\Path\To\MyApp.exe"

# --- Allow a DLL ---
# $rule = New-AppLockerFileRule -RuleType Path -Path "C:\Path\To\MyLib.dll" -User "Everyone" -Action Allow -RuleCollectionType Dll
# $policy = Get-AppLockerPolicy -Local
# $policy.RuleCollections[2].FilePathRules.Add($rule)
# Set-AppLockerPolicy -PolicyObject $policy -Merge
# gpupdate /force | Out-Null
# Write-Host "✅ DLL ALLOWED: C:\Path\To\MyLib.dll"

# --- Allow a Script (.ps1 / .vbs / .js) ---
# $rule = New-AppLockerFileRule -RuleType Path -Path "C:\Path\To\MyScript.ps1" -User "Everyone" -Action Allow -RuleCollectionType Script
# $policy = Get-AppLockerPolicy -Local
# $policy.RuleCollections[1].FilePathRules.Add($rule)
# Set-AppLockerPolicy -PolicyObject $policy -Merge
# gpupdate /force | Out-Null
# Write-Host "✅ Script ALLOWED: C:\Path\To\MyScript.ps1"

# --- Allow an MSI installer ---
# $rule = New-AppLockerFileRule -RuleType Path -Path "C:\Path\To\Setup.msi" -User "Everyone" -Action Allow -RuleCollectionType Msi
# $policy = Get-AppLockerPolicy -Local
# $policy.RuleCollections[3].FilePathRules.Add($rule)
# Set-AppLockerPolicy -PolicyObject $policy -Merge
# gpupdate /force | Out-Null
# Write-Host "✅ MSI ALLOWED: C:\Path\To\Setup.msi"


# ==========================
# AppLocker Block Rules
# ==========================

# --- Block an EXE ---
# $rule = New-AppLockerFileRule -RuleType Path -Path "C:\Path\To\BadApp.exe" -User "Everyone" -Action Deny -RuleCollectionType Exe
# $policy = Get-AppLockerPolicy -Local
# $policy.RuleCollections[0].FilePathRules.Add($rule)
# Set-AppLockerPolicy -PolicyObject $policy -Merge
# gpupdate /force | Out-Null
# Write-Host "❌ Exe BLOCKED: C:\Path\To\BadApp.exe"

# --- Block a DLL ---
# $rule = New-AppLockerFileRule -RuleType Path -Path "C:\Path\To\BadLib.dll" -User "Everyone" -Action Deny -RuleCollectionType Dll
# $policy = Get-AppLockerPolicy -Local
# $policy.RuleCollections[2].FilePathRules.Add($rule)
# Set-AppLockerPolicy -PolicyObject $policy -Merge
# gpupdate /force | Out-Null
# Write-Host "❌ DLL BLOCKED: C:\Path\To\BadLib.dll"

# --- Block a Script (.ps1 / .vbs / .js) ---
# $rule = New-AppLockerFileRule -RuleType Path -Path "C:\Path\To\Malicious.ps1" -User "Everyone" -Action Deny -RuleCollectionType Script
# $policy = Get-AppLockerPolicy -Local
# $policy.RuleCollections[1].FilePathRules.Add($rule)
# Set-AppLockerPolicy -PolicyObject $policy -Merge
# gpupdate /force | Out-Null
# Write-Host "❌ Script BLOCKED: C:\Path\To\Malicious.ps1"

# --- Block an MSI installer ---
# $rule = New-AppLockerFileRule -RuleType Path -Path "C:\Path\To\BadSetup.msi" -User "Everyone" -Action Deny -RuleCollectionType Msi
# $policy = Get-AppLockerPolicy -Local
# $policy.RuleCollections[3].FilePathRules.Add($rule)
# Set-AppLockerPolicy -PolicyObject $policy -Merge
# gpupdate /force | Out-Null
# Write-Host "❌ MSI BLOCKED: C:\Path\To\BadSetup.msi"
