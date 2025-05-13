Option Explicit

Dim objShell, objFSO, chromePath, chromeVersion, latestVersion, downloadURL, tempFolder, chromeInstaller

' Initialize objects
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Path to Chrome executable
chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"

' Check if Chrome is installed
If objFSO.FileExists(chromePath) Then
    ' Get the installed version of Chrome
    chromeVersion = GetFileVersion(chromePath)

    ' Fetch the latest version number available
    latestVersion = GetLatestChromeVersion()

    ' Compare versions
    If CompareVersions(chromeVersion, latestVersion) < 0 Then
        WScript.Echo "Updating Chrome from version " & chromeVersion & " to " & latestVersion & "..."

        ' Download and install the latest version
        downloadURL = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
        tempFolder = objShell.ExpandEnvironmentStrings("%TEMP%")
        chromeInstaller = tempFolder & "\chrome_installer.exe"

        ' Download the Chrome installer
        DownloadFile downloadURL, chromeInstaller

        ' Run the installer silently
        objShell.Run chr(34) & chromeInstaller & chr(34) & " /silent /install", 0, True

        ' Clean up
        If objFSO.FileExists(chromeInstaller) Then
            objFSO.DeleteFile chromeInstaller
        End If

        WScript.Echo "Chrome has been updated successfully."
    Else
        WScript.Echo "Chrome is already up to date."
    End If
Else
    WScript.Echo "Google Chrome is not installed."
End If

' Function to get the file version of a program
Function GetFileVersion(filePath)
    Dim objFileVersion
    Set objFileVersion = objFSO.GetFileVersion(filePath)
    GetFileVersion = objFileVersion
End Function

' Function to download a file from the internet
Function DownloadFile(URL, LocalPath)
    Dim xmlHttp, bStrm
    Set xmlHttp = CreateObject("MSXML2.XMLHTTP")
    xmlHttp.Open "GET", URL, False
    xmlHttp.Send
    If xmlHttp.Status = 200 Then
        Set bStrm = CreateObject("ADODB.Stream")
        bStrm.Type = 1
        bStrm.Open
        bStrm.Write xmlHttp.responseBody
        bStrm.SaveToFile LocalPath, 2
        bStrm.Close
    End If
End Function

' Function to get the latest Chrome version
Function GetLatestChromeVersion()
    Dim xmlHttp, jsonResponse, versionData, versionStart, versionEnd
    Set xmlHttp = CreateObject("MSXML2.XMLHTTP")
    xmlHttp.Open "GET", "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1", False
    xmlHttp.Send
    If xmlHttp.Status = 200 Then
        jsonResponse = xmlHttp.responseText
        ' Find the start and end of the version string in the JSON response
        versionStart = InStr(jsonResponse, """version"":""") + 11
        versionEnd = InStr(versionStart, jsonResponse, """")
        GetLatestChromeVersion = Mid(jsonResponse, versionStart, versionEnd - versionStart)
    Else
        GetLatestChromeVersion = "0.0.0.0" ' If unable to fetch, return a very low version to avoid updating
    End If
End Function

' Function to compare two version strings (returns -1 if version1 < version2, 0 if equal, 1 if version1 > version2)
Function CompareVersions(version1, version2)
    Dim v1Parts, v2Parts, i
    v1Parts = Split(version1, ".")
    v2Parts = Split(version2, ".")
    For i = 0 To UBound(v1Parts)
        If CInt(v1Parts(i)) < CInt(v2Parts(i)) Then
            CompareVersions = -1
            Exit Function
        ElseIf CInt(v1Parts(i)) > CInt(v2Parts(i)) Then
            CompareVersions = 1
            Exit Function
        End If
    Next
    CompareVersions = 0
End Function
