# Define the path to the XML file
$xmlFilePath = "C:\Program Files (x86)\ManageEngine\UEMS_Agent\data\ds-server-info.xml"

# Load the XML file into a PowerShell XML object
[xml]$xmlContent = Get-Content -Path $xmlFilePath

# Find the specific AgentParams element by its param_name (in this case, "BRANCHOFFICENAME")
$paramValue = $xmlContent.SelectNodes("//AgentParams[@param_name='BRANCHOFFICENAME']").param_value

# Output the param_value (branch office name)
Write-Host "The Branch Office Name (DS Name) is: $paramValue"
