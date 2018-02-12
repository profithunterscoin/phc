Attribute VB_Name = "Parsers"
'###############################################################
'### Chain Buddy 1.0 (Win32) - Profit Hunters Coin © 2018    ###
'### Automatically monitor node/peer blockchain health       ###
'### Official Website: www.ProfitHuntersCoin.com             ###
'### Official Github: www.github.com/BiznatchEnterprises/phc ###
'###############################################################

' Parsers.bas

Public Function ParseYiimpExplorer(SourceCode As String) As String()

On Error GoTo ErrorHandler

    Dim Output(4) As String

    Output(0) = "OFF"
    Output(1) = 0
    Output(2) = "Yiimp"

    SourceCode = LCase(SourceCode)

    If SourceCode <> "" Then

        Position_STR = "<b>phc</b>"
        Version_StartSTR = "scrypt</td><td>"
        Version_EndSTR = "</td><td>"
        Blocks_EndSTR = "</td>"
    
        Current_POS = InStr(1, SourceCode, Position_STR)
    
        If Current_POS > 0 Then
    
            Version_StartPOS = InStr(Current_POS, SourceCode, Version_StartSTR)
            Version_StartPOS = Version_StartPOS + Len(Version_StartSTR)
            
            If Version_StartPOS > 0 Then
            
                Version_EndPOS = InStr(Version_StartPOS, SourceCode, Version_EndSTR)
            
                    If Version_EndPOS > 0 Then
                    
                        Output(0) = "ON"
                        Output(4) = Mid(SourceCode, Version_StartPOS, Version_EndPOS - Version_StartPOS)
                    
                            Blocks_StartPOS = Version_EndPOS + Len(Version_EndSTR)
                            Blocks_EndPOS = InStr(Blocks_StartPOS, SourceCode, Blocks_EndSTR)
                            
                            If Blocks_EndPOS > 0 Then
                            
                                Output(1) = Mid(SourceCode, Blocks_StartPOS, Blocks_EndPOS - Blocks_StartPOS)
                            
                            End If
                    
                    End If
            
            End If
            
        End If

    End If


EndFunction:

    ParseYiimpExplorer = Output
    GoTo AbortFunction
    
ErrorHandler:

    MsgBox Error
    GoTo AbortFunction

AbortFunction:

    Exit Function

End Function

Public Function ParseBlockExplorer(SourceCode As String) As String()
    
On Error GoTo ErrorHandler

    Dim Output(4) As String

    Output(0) = "OFF"
    Output(1) = 0
    Output(2) = "Explorer"

    If SourceCode <> "" Then

        Position_STR = "Block Count:</SPAN><BR>"
        Blocks_EndSTR = " </DIV>"
        Position_StartPOS = InStr(1, SourceCode, Position_STR)
    
        If Position_StartPOS > 0 Then
    
            Position_EndPOS = InStr(Position_StartPOS, SourceCode, Blocks_EndSTR)
        
            If Position_EndPOS > 0 Then
        
                Output(0) = "ON"
                Output(1) = Mid(SourceCode, Position_StartPOS + Len(Position_STR), Position_EndPOS - Position_StartPOS - Len(Position_STR))
                Output(2) = "Explorer"
            
            End If
    
        End If

    End If
    

EndFunction:

    ParseBlockExplorer = Output
    GoTo AbortFunction
    
ErrorHandler:

    MsgBox Error
    GoTo AbortFunction

AbortFunction:

    Exit Function


End Function

Public Function ParseBlockExplorerAPI(SourceCode As String) As String()

On Error GoTo ErrorHandler
    
    Dim Output(4) As String

    Output(2) = "BlockAPI"

    If SourceCode = "There was an error. Check your console." Then
    
        Output(0) = "OFF"
        Output(1) = 0
        GoTo EndFunction
        
    End If

    If SourceCode <> "" Then
    
        Output(0) = "ON"
        Output(1) = SourceCode
        
    Else
    
        Output(0) = "OFF"
        Output(1) = 0
        
    End If

EndFunction:

    ParseBlockExplorerAPI = Output
    
    GoTo AbortFunction
    
ErrorHandler:

    MsgBox Error
    
    GoTo AbortFunction

AbortFunction:

    Exit Function


End Function


