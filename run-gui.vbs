Option Explicit

' Keep the visible entry point tiny; all package lookup, argument quoting and
' elevation live in the shared Python launcher.
Dim fs, shell, root, launcher, commandLine, argument
Set fs = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
root = fs.GetParentFolderName(WScript.ScriptFullName)
launcher = fs.BuildPath(root, "run-gui.bat")
If Not fs.FileExists(launcher) Then
    MsgBox "GUI launcher wrapper not found: " & launcher, vbExclamation, "Tunnel"
    WScript.Quit 1
End If

commandLine = Quote(launcher)
For Each argument In WScript.Arguments
    commandLine = commandLine & " " & Quote(CStr(argument))
Next
On Error Resume Next
shell.Run commandLine, 0, False
If Err.Number <> 0 Then
    Dim description
    description = Err.Description
    Err.Clear
    On Error GoTo 0
    MsgBox "Unable to start Tunnel GUI: " & description, vbCritical, "Tunnel"
    WScript.Quit 1
End If
On Error GoTo 0
WScript.Quit 0

Function Quote(value)
    Quote = Chr(34) & Replace(value, Chr(34), Chr(34) & Chr(34)) & Chr(34)
End Function
