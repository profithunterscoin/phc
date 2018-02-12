VERSION 5.00
Begin VB.Form RemoveSite 
   BorderStyle     =   1  'Fixed Single
   Caption         =   "Chain Buddy - Remove Site"
   ClientHeight    =   1080
   ClientLeft      =   8325
   ClientTop       =   4005
   ClientWidth     =   4275
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   1080
   ScaleWidth      =   4275
   Begin VB.CommandButton Cancel_BTN 
      Caption         =   "Cancel"
      Height          =   375
      Left            =   2520
      TabIndex        =   3
      Top             =   600
      Width           =   1215
   End
   Begin VB.CommandButton RemoveSite_BTN 
      Caption         =   "Remove Site"
      Height          =   375
      Left            =   480
      TabIndex        =   2
      Top             =   600
      Width           =   1335
   End
   Begin VB.Label Type_Label 
      Height          =   255
      Left            =   120
      TabIndex        =   0
      Top             =   240
      Width           =   855
   End
   Begin VB.Label Address_Label 
      Height          =   255
      Left            =   1200
      TabIndex        =   1
      Top             =   240
      Width           =   2895
   End
   Begin VB.Label Row_LABEL 
      Height          =   255
      Left            =   120
      TabIndex        =   4
      Top             =   240
      Width           =   375
   End
End
Attribute VB_Name = "RemoveSite"
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

' RemoveSite.frm

Private Sub Cancel_BTN_Click()

    Me.Visible = False
    
End Sub

Private Sub Form_Load()

    Me.Icon = Main.Icon

End Sub

Private Sub RemoveSite_BTN_Click()

On Error GoTo ErrorHandler

    Main.Monitoring.RemoveItem Row_LABEL.Caption
    RemoveSite.Visible = False

EndSub:

    GoTo AbortSub
    
ErrorHandler:

    MsgBox "RemoveSite: " & Error
    
    GoTo AbortSub

AbortSub:

    Exit Sub



End Sub

