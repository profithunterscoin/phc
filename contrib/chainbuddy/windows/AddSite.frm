VERSION 5.00
Begin VB.Form AddSite 
   BorderStyle     =   3  'Fixed Dialog
   Caption         =   "Chain Buddy - Add Site"
   ClientHeight    =   1110
   ClientLeft      =   8325
   ClientTop       =   4500
   ClientWidth     =   4530
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   1110
   ScaleWidth      =   4530
   ShowInTaskbar   =   0   'False
   Begin VB.CommandButton Cancel_BTN 
      Caption         =   "Cancel"
      Height          =   375
      Left            =   2520
      TabIndex        =   3
      Top             =   600
      Width           =   1095
   End
   Begin VB.CommandButton AddSite_BTN 
      Caption         =   "Add Site"
      Height          =   375
      Left            =   840
      TabIndex        =   2
      Top             =   600
      Width           =   1335
   End
   Begin VB.TextBox Address_TEXT 
      Height          =   285
      Left            =   1440
      TabIndex        =   1
      Text            =   "http://"
      Top             =   120
      Width           =   3015
   End
   Begin VB.ComboBox Type_LIST 
      Height          =   315
      ItemData        =   "AddSite.frx":0000
      Left            =   120
      List            =   "AddSite.frx":000D
      TabIndex        =   0
      Text            =   "BlockAPI"
      Top             =   120
      Width           =   1215
   End
End
Attribute VB_Name = "AddSite"
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

' AddSite.frm

Private Sub AddSite_BTN_Click()

On Error GoTo ErrorHandler

    Dim Type_TMP As String
    Dim Address_TMP As String
  
    If Type_LIST.ListIndex > 0 Then
    
        Type_TMP = Type_LIST.List(Type_LIST.ListIndex)
        
    Else
    
        Type_TMP = Type_LIST.Text
        
    End If
    
    Main.Monitoring.Rows = Main.Monitoring.Rows + 1
       
    Main.Monitoring.TextMatrix(Main.Monitoring.Rows - 1, 0) = Type_TMP
    Main.Monitoring.TextMatrix(Main.Monitoring.Rows - 1, 1) = Address_TEXT.Text
    Main.Monitoring.TopRow = Main.Monitoring.Rows - 1
    
    AddSite.Visible = False

EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "AddSite: " & Error
    
    GoTo AbortSub

AbortSub:

    Exit Sub


End Sub

Private Sub Cancel_BTN_Click()

    Me.Visible = False
    
End Sub

Private Sub Form_Load()

    Me.Icon = Main.Icon

End Sub
