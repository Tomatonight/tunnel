Option Explicit

' Hidden Windows entry point for the same project-scoped cleanup used by
' stop-gui.bat and by the GUI launchers.
Dim fs, shell, root, script, commandLine
Set fs = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
root = fs.GetParentFolderName(WScript.ScriptFullName)
script = fs.BuildPath(root, "stop-gui.bat")
If Not fs.FileExists(script) Then
    MsgBox "Tunnel cleanup script not found: " & script, vbExclamation, "Tunnel"
    WScript.Quit 1
End If

commandLine = Quote(script)
On Error Resume Next
shell.Run commandLine, 0, True
If Err.Number <> 0 Then
    Dim description
    description = Err.Description
    Err.Clear
    On Error GoTo 0
    MsgBox "Unable to stop Tunnel: " & description, vbCritical, "Tunnel"
    WScript.Quit 1
End If
On Error GoTo 0
WScript.Quit 0

Function Quote(value)
    Quote = Chr(34) & Replace(value, Chr(34), Chr(34) & Chr(34)) & Chr(34)
End Function
