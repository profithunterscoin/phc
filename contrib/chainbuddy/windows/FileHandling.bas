Attribute VB_Name = "FileHandling"
'************************
'*  FILE VB6 FUNCTIONS  *
'*     VERSION 1.0      *
'*   Biznaturally.ca    *
'*   © June 26, 2016    *
'************************

Public Function LoadListFromFile(Listbox As Listbox, Filename) As String
'LoadListFromFile (VB6) © 2013 Biznatch Enterprises - Biznaturally.ca

On Error GoTo hand

    Open Filename For Input As #1

        Do
        DoEvents
            tmpstr = ""
            If Not EOF(1) Then Line Input #1, tmpstr
            If tmpstr <> "" Then Listbox.AddItem tmpstr
      Loop While Not EOF(1)
    
    Close #1

LoadListFromFile = "Success"

hand:
Close #1
LoadListFromFile = Error

End Function

Public Function SaveListToFile(Listbox As Listbox, Filename As String, AppendFile As Boolean) As String
'SaveListToFile (VB6) © 2013 Biznatch Enterprises - Biznaturally.ca

On Error GoTo hand

    Select Case AppendFile
        Case 0
            Open Filename For Output As #1
        Case 1
            Open Filename For Append As #1
    End Select

    For i = 0 To Listbox.ListCount - 1
        DoEvents
        Print #1, Listbox.List(i)
    Next

    Close #1

    SaveListToFile = "Success"
    Exit Function
    
hand:
Close #1
SaveListToFile = Error
End Function

Public Function LoadFileContents(Filename As String)
Dim tmpstr As String
Dim tmpline As String

On Error GoTo hand

    Open Filename For Input As #1

        Do
        DoEvents
            tmpstr = ""
            If Not EOF(1) Then Line Input #1, tmpline
            If tmpline <> "" Then tmpstr = tmpstr & tmpstr
      Loop While Not EOF(1)
    
    Close #1

LoadFileContents = tmpstr

Exit Function

hand:
Close #1
LoadFileContents = Error

End Function

Public Function SaveFileContents(Filename As String, Contents As String) As String
On Error GoTo hand

Open Filename For Output As #1

Write #1, Contents

Close #1

SaveFileContents = "Success"

Exit Function

hand:
Close #1
SaveFileContents = Error

End Function



