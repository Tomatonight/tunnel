Option Explicit

Dim fileSystem, shell, root, guiExe, commandLine, argument
Set fileSystem = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

root = fileSystem.GetParentFolderName(WScript.ScriptFullName)
guiExe = fileSystem.BuildPath(root, "build\gui\TunnelUI\TunnelUI.exe")

If Not fileSystem.FileExists(guiExe) Then
    MsgBox "GUI package not found:" & vbCrLf & _
           guiExe & vbCrLf & vbCrLf & _
           "Run build.bat --gui first.", vbExclamation, "Tunnel GUI"
    WScript.Quit 1
End If

commandLine = Quote(guiExe)
For Each argument In WScript.Arguments
    commandLine = commandLine & " " & Quote(CStr(argument))
Next

' Start without creating a cmd.exe window.
shell.Run commandLine, 0, False

Function Quote(value)
    Quote = Chr(34) & Replace(value, Chr(34), Chr(34) & Chr(34)) & Chr(34)
End Function
