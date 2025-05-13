Option Explicit

Dim objFSO, objFolder, objFile, objShell, objWMIService, colFiles, objReg, strKeyPath, strValueName
Dim strComputer, strDirectory, strUpdateName, strCommand

' Set the computer name and directory where updates are stored
strComputer = "."
strDirectory = "C:\Updates"

' Create objects
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\CIMV2")
Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")

' Check if the directory exists
If objFSO.FolderExists(strDirectory) Then
    Set objFolder = objFSO.GetFolder(strDirectory)
    Set colFiles = objFolder.Files

    ' Loop through each file in the directory
    For Each objFile In colFiles
        If objFSO.GetExtensionName(objFile.Name) = "msp" Then
            strUpdateName = objFSO.GetBaseName(objFile.Name)
            WScript.Echo "Installed update: " & strUpdateName
            ' Add more actions if needed, such as copying the update to another location or extracting information from it
        End If
    Next
Else
    WScript.Echo "Directory not found: " & strDirectory
End If

' Clean up
Set objFSO = Nothing
Set objFolder = Nothing
Set objFile = Nothing
Set objShell = Nothing
Set objWMIService = Nothing
Set colFiles = Nothing
Set objReg = Nothing
