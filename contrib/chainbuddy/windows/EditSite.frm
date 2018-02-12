VERSION 5.00
Begin VB.Form EditSite 
   BorderStyle     =   3  'Fixed Dialog
   Caption         =   "Chain Buddy - Edit Site"
   ClientHeight    =   1080
   ClientLeft      =   8490
   ClientTop       =   4170
   ClientWidth     =   4560
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   1080
   ScaleWidth      =   4560
   ShowInTaskbar   =   0   'False
   Begin VB.CommandButton Cancel_BTN 
      Caption         =   "Cancel"
      Height          =   375
      Left            =   2520
      TabIndex        =   3
      Top             =   600
      Width           =   1215
   End
   Begin VB.CommandButton EditSite_BTN 
      Caption         =   "Edit Site"
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
      ItemData        =   "EditSite.frx":0000
      Left            =   120
      List            =   "EditSite.frx":000D
      TabIndex        =   0
      Text            =   "BlockAPI"
      Top             =   120
      Width           =   1215
   End
   Begin VB.Label Row_LABEL 
      Height          =   255
      Left            =   120
      TabIndex        =   4
      Top             =   240
      Width           =   375
   End
End
Attribute VB_Name = "EditSite"
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

' EditSite.frm

Private Sub Cancel_BTN_Click()

    Me.Visible = False
    
End Sub

Private Sub EditSite_BTN_Click()

On Error GoTo ErrorHandler

    Dim Type_TMP As String
    Dim Address_TMP As String
  
    If Type_LIST.ListIndex > 0 Then
    
        Type_TMP = Type_LIST.List(Type_LIST.ListIndex)
        
    Else
    
        Type_TMP = Type_LIST.Text
        
    End If
    
    Main.Monitoring.TextMatrix(Row_LABEL.Caption, 0) = Type_TMP
    Main.Monitoring.TextMatrix(Row_LABEL.Caption, 1) = Address_TEXT.Text
 
    EditSite.Visible = False

EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "RemoveSite: " & Error
    
    GoTo AbortSub

AbortSub:

    Exit Sub


End Sub

Private Sub Form_Load()

    Me.Icon = Main.Icon

End Sub

