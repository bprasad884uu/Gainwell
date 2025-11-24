# Detect the real logged-in use
$userFull  = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
$userName  = $userFull.Split('\')[-1]          # Domain\Username se sirf username

# Build the SAP Common folder path for that user
$targetFolder = "C:\Users\$userName\AppData\Roaming\SAP\Common"

########################
# 1. saplogon.ini
########################
$saplogonContent = @'
[Configuration]
SessManNewKey=43

[EntryKey]
Item1=
Item2=
Item3=
Item4=

[Router]
Item1=
Item2=
Item3=
Item4=

[Router2]
Item1=
Item2=
Item3=
Item4=

[RouterChoice]
Item1=0
Item2=0
Item3=0
Item4=0

[Server]
Item1=
Item2=
Item3=10.131.51.229
Item4=10.131.51.241

[Database]
Item1=00
Item2=00
Item3=00
Item4=010

[System]
Item1=3
Item2=3
Item3=3
Item4=3

[Description]
Item1=
Item2=
Item3=CRMQUA
Item4=ECCQUA

[Address]
Item1=
Item2=
Item3=
Item4=

[MSSysName]
Item1=
Item2=
Item3=QCA
Item4=QE1

[MSSrvName]
Item1=
Item2=
Item3=
Item4=

[MSSrvPort]
Item1=
Item2=
Item3=sapmsQCA
Item4=sapmsQE1

[SessManKey]
Item1=-1
Item2=-1
Item3=-1
Item4=-1

[SncName]
Item1=
Item2=
Item3=
Item4=

[SncChoice]
Item1=-1
Item2=-1
Item3=-1
Item4=-1

[SncNoSSO]
Item1=0
Item2=0
Item3=0
Item4=0

[Codepage]
Item1=1100
Item2=1100
Item3=1100
Item4=1100

[CodepageIndex]
Item1=-1
Item2=-1
Item3=-1
Item4=-1

[Origin]
Item1=USEREDIT
Item2=USEREDIT
Item3=USEREDIT
Item4=USEREDIT

[LowSpeedConnection]
Item1=0
Item2=0
Item3=0
Item4=0

[Utf8Off]
Item1=0
Item2=0
Item3=0
Item4=0

[EncodingID]
Item1=
Item2=
Item3=DEFAULT_NON_UC
Item4=DEFAULT_NON_UC

[ShortcutType]
Item1=1
Item2=1
Item3=0
Item4=0

[ShortcutString]
Item1=
Item2=
Item3=
Item4=

[ShortcutTo]
Item1=
Item2=
Item3=
Item4=

[ShortcutBy]
Item1=
Item2=
Item3=
Item4=

[MSLast]
MSLast=PE1
'@

Set-Content -Path "$targetFolder\saplogon.ini" -Value $saplogonContent -Encoding ASCII


########################
# 2. SapLogonTree.xml
########################
Set-Content -Path "$targetFolder\SapLogonTree.xml" -Value '<?xml version="1.0" encoding="utf-8"?>' -Encoding UTF8


########################
# 3. saprules.xml
########################
$saprulesContent = '<?xml version="1.0" encoding="UTF-8"?><SAP><type>SAP object rules</type><version>1.1</version><timestamp>2019-12-17 10:41:59</timestamp><rules/></SAP>'
Set-Content -Path "$targetFolder\saprules.xml" -Value $saprulesContent -Encoding UTF8


########################
# 4. sapshortcut.ini (blank)
########################
Set-Content -Path "$targetFolder\sapshortcut.ini" -Value '' -Encoding ASCII


########################
# 5. SAPUILandscape.xml
########################
$SAPUILandscapeContent = @'
<?xml version="1.0" encoding="UTF-8"?>
<Landscape updated="2023-02-12T13:36:17Z" version="1" generator="SAP GUI for Windows v7500.2.4.128"><Workspaces><Workspace uuid="3fad49ff-8253-4aca-ac70-eeb8784c3a7c" name="Local"><Item uuid="ee5fdd92-7c76-4820-bbdf-7c7678665a15" serviceid="05815dc4-4bc6-49d5-b0eb-1dddd53f89a6"/><Item uuid="dabd331b-b3e5-423c-8219-67bf2952e1f7" serviceid="f4c83427-ff25-4078-84f7-5c69fb7d35a1"/><Item uuid="99b7d013-6134-4da1-a5bf-6967ff2d90c2" serviceid="247505d9-aade-4e51-83b0-7d02217daefe"/><Item uuid="98bfc933-7924-4559-a4a9-609f70d2b00c" serviceid="96d73a4c-a5cc-4f95-964c-95e07cfed521"/><Item uuid="66add887-7ce6-41d3-a389-85a83c32770e" serviceid="c7bd28b6-0e2e-4117-b0d1-b870bdd01b70"/></Workspace></Workspaces><Messageservers><Messageserver uuid="88662e09-27da-464f-9c1d-1336f1e5bb68" name="PE1" host="10.131.51.203"/><Messageserver uuid="219e8184-9bb4-41c5-abe7-fc2ad2e1d89e" name="PC1" host="192.100.1.74"/></Messageservers><Services><Service type="SAPGUI" shortcut="1" reuse="1" uuid="05815dc4-4bc6-49d5-b0eb-1dddd53f89a6" name="CRM Quality" systemid="QCA" client="300" user="Admin" language="EN" guiparam="192.100.1.26" work_dir="C:\Users\roopsik\Documents\SAP\SAP GUI"/><Service type="SAPGUI" shortcut="1" reuse="1" uuid="f4c83427-ff25-4078-84f7-5c69fb7d35a1" name="ECC Quality" systemid="QE1" client="300" user="Admin" language="EN" guiparam="192.100.1.28" work_dir="C:\Users\roopsik\Documents\SAP\SAP GUI"/><Service type="SAPGUI" uuid="247505d9-aade-4e51-83b0-7d02217daefe" name="ECC Production - AWS" systemid="PE1" msid="88662e09-27da-464f-9c1d-1336f1e5bb68" server="SAPERP" sncop="-1" sapcpg="1100" dcpg="2"/><Service type="SAPGUI" uuid="96d73a4c-a5cc-4f95-964c-95e07cfed521" name="ECC Quality - AWS" systemid="QE1" mode="1" server="10.131.51.241:3200" sncop="-1" sapcpg="1100" dcpg="2"/><Service type="SAPGUI" uuid="c7bd28b6-0e2e-4117-b0d1-b870bdd01b70" name="CRM Quality - AWS" systemid="QCA" mode="1" server="10.131.51.229:3200" sncop="-1" sapcpg="1100" dcpg="2"/></Services><Routers><Router uuid="ba7f2838-a7a4-4aea-827f-132e678b0144" name="/H/219.65.73.134/S/3299" description="/H/219.65.73.134/S/3299" router="/H/219.65.73.134/S/3299"/></Routers></Landscape>
'@

Set-Content -Path "$targetFolder\SAPUILandscape.xml" -Value $SAPUILandscapeContent -Encoding UTF8


########################
# 6. SAPUILandscapeGlobal.xml
########################
$SAPUILandscapeGlobalContent = '<?xml version="1.0" encoding="UTF-8"?><Landscape><Messageservers/></Landscape>'
Set-Content -Path "$targetFolder\SAPUILandscapeGlobal.xml" -Value $SAPUILandscapeGlobalContent -Encoding UTF8

Write-Host "Files created in: $targetFolder"
