VERSION 5.00
Object = "{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}#1.1#0"; "ieframe.dll"
Object = "{5E9E78A0-531B-11CF-91F6-C2863C385E30}#1.0#0"; "MSFLXGRD.OCX"
Begin VB.Form Main 
   BorderStyle     =   1  'Fixed Single
   Caption         =   "Chain Buddy 1.0 (Win32) - Profit Hunters Coin © 2018"
   ClientHeight    =   4335
   ClientLeft      =   7500
   ClientTop       =   3330
   ClientWidth     =   6255
   Icon            =   "Main.frx":0000
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   ScaleHeight     =   4335
   ScaleWidth      =   6255
   Begin VB.CommandButton SaveSite_BTN 
      Caption         =   "Save"
      Height          =   375
      Left            =   3600
      TabIndex        =   18
      ToolTipText     =   "Save Sites List"
      Top             =   3840
      Width           =   615
   End
   Begin VB.CommandButton LoadSites_BTN 
      Caption         =   "Load"
      Height          =   375
      Left            =   3000
      TabIndex        =   17
      ToolTipText     =   "Load Sites List"
      Top             =   3840
      Width           =   615
   End
   Begin VB.CommandButton ClrChains_BTN 
      Caption         =   "Clear ^"
      Height          =   375
      Left            =   5160
      TabIndex        =   16
      ToolTipText     =   "Clear the Chains List Above"
      Top             =   2400
      Width           =   975
   End
   Begin VB.TextBox Chain_Type 
      Height          =   375
      Left            =   4440
      TabIndex        =   15
      Top             =   4440
      Width           =   1695
   End
   Begin VB.TextBox Interval 
      Enabled         =   0   'False
      Height          =   285
      Left            =   4440
      TabIndex        =   13
      Text            =   "60"
      Top             =   2880
      Width           =   495
   End
   Begin MSFlexGridLib.MSFlexGrid Monitoring 
      Height          =   1815
      Left            =   120
      TabIndex        =   12
      Top             =   2400
      Width           =   2775
      _ExtentX        =   4895
      _ExtentY        =   3201
      _Version        =   393216
      Rows            =   1
      FixedCols       =   0
      SelectionMode   =   1
   End
   Begin VB.CommandButton Settings_BTN 
      Caption         =   "Settings"
      Enabled         =   0   'False
      Height          =   375
      Left            =   5160
      TabIndex        =   11
      ToolTipText     =   "Modify Settings"
      Top             =   3840
      Width           =   975
   End
   Begin VB.CommandButton EditSite_BTN 
      Caption         =   "Edit"
      Height          =   375
      Left            =   3000
      TabIndex        =   9
      ToolTipText     =   "Edit Site From List"
      Top             =   3360
      Width           =   1215
   End
   Begin VB.CommandButton RemoveSite_BTN 
      Caption         =   "Remove"
      Height          =   375
      Left            =   3000
      TabIndex        =   8
      ToolTipText     =   "Remove Site From List"
      Top             =   2880
      Width           =   1215
   End
   Begin VB.CommandButton AddSite_BTN 
      Caption         =   "Add"
      Height          =   375
      Left            =   3000
      TabIndex        =   7
      ToolTipText     =   "Add Site To List"
      Top             =   2400
      Width           =   1215
   End
   Begin VB.TextBox Cycle 
      Enabled         =   0   'False
      Height          =   285
      Left            =   4440
      TabIndex        =   6
      Text            =   "0"
      Top             =   3840
      Width           =   495
   End
   Begin VB.CommandButton CheckAllChains_BTN 
      Caption         =   "Check ALL"
      Height          =   375
      Left            =   5160
      TabIndex        =   5
      ToolTipText     =   "Check All Sites"
      Top             =   3360
      Width           =   975
   End
   Begin SHDocVwCtl.WebBrowser Web_Browser 
      Height          =   2175
      Left            =   120
      TabIndex        =   4
      Top             =   6720
      Width           =   6015
      ExtentX         =   10610
      ExtentY         =   3836
      ViewMode        =   0
      Offline         =   0
      Silent          =   0
      RegisterAsBrowser=   0
      RegisterAsDropTarget=   1
      AutoArrange     =   0   'False
      NoClientEdge    =   0   'False
      AlignLeft       =   0   'False
      NoWebView       =   0   'False
      HideFileNames   =   0   'False
      SingleClick     =   0   'False
      SingleSelection =   0   'False
      NoFolders       =   0   'False
      Transparent     =   0   'False
      ViewID          =   "{0057D0E0-3573-11CF-AE69-08002B2E1262}"
      Location        =   "http:///"
   End
   Begin VB.TextBox Web_URL 
      Height          =   375
      Left            =   120
      TabIndex        =   3
      Top             =   4440
      Width           =   4215
   End
   Begin VB.CommandButton CheckChain_BTN 
      Caption         =   "Check"
      Height          =   375
      Left            =   5160
      TabIndex        =   2
      ToolTipText     =   "Check selected Site"
      Top             =   2880
      Width           =   975
   End
   Begin VB.TextBox Web_Source 
      Height          =   1695
      Left            =   120
      TabIndex        =   1
      Top             =   4920
      Width           =   6015
   End
   Begin MSFlexGridLib.MSFlexGrid Chains 
      Height          =   2055
      Left            =   120
      TabIndex        =   0
      Top             =   120
      Width           =   6015
      _ExtentX        =   10610
      _ExtentY        =   3625
      _Version        =   393216
      Rows            =   1
      Cols            =   5
      AllowUserResizing=   1
   End
   Begin VB.Timer Timer1 
      Interval        =   60000
      Left            =   4560
      Top             =   1680
   End
   Begin VB.Label Cycle_Label 
      Alignment       =   2  'Center
      Caption         =   "Cycle"
      Height          =   255
      Left            =   4320
      TabIndex        =   14
      Top             =   3480
      Width           =   735
   End
   Begin VB.Label Interval_Label 
      Alignment       =   2  'Center
      Caption         =   "Interval:"
      Height          =   255
      Left            =   4320
      TabIndex        =   10
      Top             =   2520
      Width           =   735
   End
End
Attribute VB_Name = "Main"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
'###############################################################
'### Chain Buddy 1.0 (Win32) - Profit Hunters Coin © 2018    ###
'### Automatically monitor node/peer blockchain health       ###
'### Official Website: www.ProfitHuntersCoin.com             ###
'### Official Github: www.github.com/BiznatchEnterprises/phc ###
'###############################################################

' Main.frm

Private Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
Private Declare Function GetTickCount Lib "kernel32" () As Long

Sub CheckForForks()

    Dim Blocks_Highest As Long
    Dim Blocks_Tolerance As Long
    Dim Blocks_Min As Long
    Dim Blocks_Max As Long
    Dim Blocks_Temp As Long
    
    Blocks_Tolerance = 10
    Blocks_Temp = 0
    
    For i = 1 To Chains.Rows - 1
    
        Blocks_Temp = Chains.TextMatrix(i, 1)
           
        If Blocks_Temp > Blocks_Highest Then
            
            Blocks_Highest = Blocks_Temp
        
        End If
    
    Next
    
    Blocks_Min = Blocks_Highest - Blocks_Tolerance
    Blocks_Max = Blocks_Highest + Blocks_Tolerance
    
    For i = 1 To Chains.Rows - 1
    
        Chains.Row = i
        Chains.Col = 1
        Chains.CellBackColor = &HC0C0FF
    
        If Chains.TextMatrix(i, 1) > Blocks_Min Then
        
            If Chains.TextMatrix(i, 1) < Blocks_Max Then
        
            Chains.Row = i
            Chains.Col = 1
            Chains.CellBackColor = &HC0FFFF
            
            End If
        
        End If
        
        If Chains.TextMatrix(i, 1) = Blocks_Highest Then
        
            Chains.CellBackColor = &HC0FFC0
        
        End If
    
    Next

End Sub

Private Sub Wait(ByVal DurationMS As Long)

On Error GoTo ErrorHandler

    Dim EndTime As Long
    
    EndTime = GetTickCount + DurationMS
    
    Do While EndTime > GetTickCount
    
        DoEvents
        Sleep 1
        
    Loop


EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "Wait: " & Error
    
    GoTo AbortSub

AbortSub:

    Exit Sub
    
    
End Sub


Function ClearGrid(GridName As MSFlexGrid)

On Error GoTo ErrorHandler

    For i = 1 To GridName.Rows - 1

        GridName.TextMatrix(i, 0) = ""
        GridName.TextMatrix(i, 1) = ""

    Next

    GridName.Rows = 1

EndFunction:

    GoTo AbortFunction
    
ErrorHandler:

    MsgBox "ClearGrid: " & Error
    GoTo AbortFunction

AbortFunction:

    Exit Function
    

End Function


Function CleanURL(urlstr)

On Error GoTo ErrorHandler

    Dim tmpstr As String

    tmpstr = Replace(urlstr, "/api/getblockcount", "")
    tmpstr = Replace(tmpstr, "http://", "")
    tmpstr = Replace(tmpstr, "https://", "")
    tmpstr = Replace(tmpstr, "/explorer", "")
   
EndFunction:

    CleanURL = tmpstr
    GoTo AbortFunction
    
ErrorHandler:

    MsgBox "CleanURL: " & Error
    GoTo AbortFunction

AbortFunction:

    Exit Function
    
    
End Function


Function AddToChainGrid(GridName As MSFlexGrid, nStatus, nBlockCount, nType, nAddress, nVersion)

On Error GoTo ErrorHandler
    
    If nStatus <> "" Then
        If CleanURL(nAddress) <> "" Then
            GridName.Rows = GridName.Rows + 1
            GridName.TextMatrix(GridName.Rows - 1, 0) = nStatus
            GridName.TextMatrix(GridName.Rows - 1, 1) = nBlockCount
            GridName.TextMatrix(GridName.Rows - 1, 2) = nType
            GridName.TextMatrix(GridName.Rows - 1, 3) = CleanURL(nAddress)
            GridName.TextMatrix(GridName.Rows - 1, 4) = nVersion
        End If
    End If

EndFunction:

    GoTo AbortFunction
    
ErrorHandler:

    MsgBox "AddToChainGrid: " & Error
    GoTo AbortFunction

AbortFunction:

    Exit Function


End Function


Function AddToMonitoringGrid(GridName As MSFlexGrid, nType, nAddress)

On Error GoTo ErrorHandler
    
    If nType <> "" Then
        If nAddress <> "" Then
            GridName.Rows = GridName.Rows + 1
            GridName.TextMatrix(GridName.Rows - 1, 0) = nType
            GridName.TextMatrix(GridName.Rows - 1, 1) = nAddress
        End If
    End If

EndFunction:

    GoTo AbortFunction
    
ErrorHandler:

    MsgBox "AddToMonitoringGrid: " & Error
    GoTo AbortFunction

AbortFunction:

    Exit Function


End Function



Sub CheckChain()

On Error GoTo ErrorHandler

    CheckChain_BTN.Enabled = False
    
    Chain_Type.Text = Monitoring.TextMatrix(Monitoring.RowSel, 0)
    Web_URL.Text = Monitoring.TextMatrix(Monitoring.RowSel, 1)
    
    Web_Source.Text = ""
    
        CheckSelectedChain
    
    Do
        DoEvents
        
        If Web_Browser.Busy = False Then
        
            Web_Source.Text = Web_Browser.Document.body.innerhtml
        
        End If
        
    Loop Until Web_Source.Text <> ""

    Select Case Chain_Type.Text
    
        Case "YIIMP"
            Output = Parsers.ParseYiimpExplorer(Web_Source.Text)
        Case "BlockExplorer"
            Output = Parsers.ParseBlockExplorer(Web_Source.Text)
        Case "BlockAPI"
            Output = Parsers.ParseBlockExplorerAPI(Web_Source.Text)
        Web_Source.Text = ""
    End Select
    
    AddToChainGrid Chains, Output(0), Output(1), Output(2), Web_URL.Text, Output(4)
    
    Output(0) = ""
    Output(1) = ""
    Output(2) = ""
    Output(3) = ""
    Output(4) = ""
    
    Web_Source.Text = ""
    Web_URL.Text = ""
    Chain_Type.Text = ""
    
    Web_Browser.Navigate "about:blank"
    
    CheckChain_BTN.Enabled = True

EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "CheckChain: " & Error
    
    GoTo AbortSub

AbortSub:

    Exit Sub


End Sub


Sub CheckAllChains()

'On Error GoTo ErrorHandler

    CheckAllChains_BTN.Enabled = False

    Chains.Rows = 1
    
    For i = 1 To Monitoring.Rows - 1
    
        Monitoring.RowSel = i
        Monitoring.Row = i
        
        CheckChain
        
        Do
            DoEvents
        Loop Until CheckChain_BTN.Enabled = True
        
        Wait 3000

    Next
    
    CheckAllChains_BTN.Enabled = True
    
    CheckForForks

EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "CheckAllChains: " & Error
    
    GoTo AbortSub

AbortSub:

    Exit Sub


End Sub


Function CheckSelectedChain()

On Error GoTo ErrorHandler
    
    Web_Source.Text = ""
    
    Web_Browser.Navigate Web_URL.Text
    
EndFunction:

    GoTo AbortFunction
    
ErrorHandler:

    MsgBox "CheckSelectedChain: " & Error
    
    GoTo AbortFunction

AbortFunction:

    Exit Function


End Function


Private Sub AddSite_BTN_Click()
    
    AddSite.Visible = True
    
End Sub


Private Sub CheckAllChains_BTN_Click()

    CheckAllChains
    
End Sub


Private Sub CheckChain_BTN_Click()

    CheckChain
    
End Sub


Private Sub ClrChains_BTN_Click()

    ClearGrid Chains

End Sub

Private Sub EditSite_BTN_Click()

On Error GoTo ErrorHandler

    If Monitoring.RowSel > 0 Then
    
        EditSite.Visible = True
        EditSite.SetFocus
        EditSite.Row_LABEL.Caption = Monitoring.RowSel
        EditSite.Type_LIST.Text = Monitoring.TextMatrix(Monitoring.RowSel, 0)
        EditSite.Address_TEXT.Text = Monitoring.TextMatrix(Monitoring.RowSel, 1)
        
    End If
    
EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "EditSite_BTN: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    
    
End Sub


Private Sub Form_Load()

On Error GoTo ErrorHandler

    Chains.TextMatrix(0, 0) = "Status"
    Chains.TextMatrix(0, 1) = "Blocks"
    Chains.TextMatrix(0, 2) = "Type"
    Chains.TextMatrix(0, 3) = "Address"
    Chains.TextMatrix(0, 4) = "Version"

    Chains.ColWidth(3) = 1600
    Chains.ColWidth(4) = 1300
    
    Monitoring.ColWidth(1) = 1900
    Monitoring.TextMatrix(0, 0) = "Type"
    Monitoring.TextMatrix(0, 1) = "Address"
    
    LoadMonitoringSites
    
EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "Form_Load: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    
    
End Sub


Sub LoadMonitoringSites()

On Error GoTo ErrorHandler

    Dim TmpLine As String
    Dim TmpType As String
    Dim TmpAddress As String
    Dim Divider_POS As Integer
    Dim Divider_STR As String
    Divider_STR = "%==%"
    
    If Dir(App.Path & "\chainbuddy_monitoring.conf") <> "" Then
    
        ClearGrid Monitoring
    
        Open App.Path & "\chainbuddy_monitoring.conf" For Input As #1
    
            Do
            DoEvents
                TmpLine = ""
                If Not EOF(1) Then Line Input #1, TmpLine
                
                If TmpLine <> "" Then
                    
                    Divider_POS = InStr(1, TmpLine, Divider_STR)
                    
                        If Divider_POS > 0 Then
                            
                            TmpType = Mid(TmpLine, 1, Divider_POS - 1)
                            TmpAddress = Mid(TmpLine, Divider_POS + Len(Divider_STR), Len(TmpLine))
                            AddToMonitoringGrid Monitoring, TmpType, TmpAddress
                            
                        End If
                    
                End If
                
            Loop While Not EOF(1)
        
        Close #1
       
    End If
    
EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "LoadMonitoringSites: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    


End Sub


Sub SaveMonitoringSites()

On Error GoTo ErrorHandler

    Dim Divider_STR As String
    Divider_STR = "%==%"
   
    Open App.Path & "\chainbuddy_monitoring.conf" For Output As #1
        
        For i = 1 To Monitoring.Rows - 1
            
            Print #1, Monitoring.TextMatrix(i, 0) & Divider_STR & Monitoring.TextMatrix(i, 1)
            
        Next
        
    Close #1
        
EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "SaveMonitoringSites: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    
End Sub

Private Sub Form_Terminate()

    SaveMonitoringSites

    End

End Sub


Private Sub Form_Unload(Cancel As Integer)

On Error GoTo ErrorHandler

SaveMonitoringSites

    End
    
EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "Form_Unload: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    
    
End Sub


Private Sub LoadSites_BTN_Click()

    LoadMonitoringSites

End Sub



Private Sub RemoveSite_BTN_Click()

On Error GoTo ErrorHandler

    If Monitoring.RowSel > 0 Then
    
        RemoveSite.Visible = True
        RemoveSite.SetFocus
        RemoveSite.Row_LABEL.Caption = Monitoring.RowSel
        RemoveSite.Type_Label.Caption = Monitoring.TextMatrix(Monitoring.RowSel, 0)
        RemoveSite.Address_Label.Caption = Monitoring.TextMatrix(Monitoring.RowSel, 1)
        
    End If
    
EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "RemoveSite_BTN: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    
    
End Sub

Private Sub SaveSite_BTN_Click()
    
    SaveMonitoringSites
    
End Sub

Private Sub Settings_BTN_Click()
    
    Settings.Visible = True
    
End Sub


Private Sub Interval_Change()

On Error GoTo ErrorHandler

    If Interval.Text < 60 Then

        Interval.Text = 60
    
    End If

EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "Timer1_Timer: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    

End Sub


Private Sub Timer1_Timer()

On Error GoTo ErrorHandler

    If Cycle.Text = Interval.Text Then
        Cycle.Text = 0
        CheckAllChains
    End If
    
    Cycle.Text = Cycle.Text + 1
    
EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "Timer1_Timer: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    
    
End Sub


Private Sub Web_Browser_DocumentComplete(ByVal pDisp As Object, URL As Variant)

On Error GoTo ErrorHandler

    Web_Source.Text = Web_Browser.Document.body.innerhtml
    
EndSub:

    GoTo AbortSub
    
ErrorHandler:

    'MsgBox "Web_Browser_DocumentComplete: " & Error
    GoTo AbortSub

AbortSub:

    Exit Sub
    
    
End Sub

