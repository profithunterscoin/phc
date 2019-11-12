// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2019 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#include "qvalidatedtextedit.h"

#include "guiconstants.h"

#include <QMessageBox>


QValidatedTextEdit::QValidatedTextEdit(QWidget *parent) : QPlainTextEdit(parent), valid(true)
{}


void QValidatedTextEdit::setValid(bool valid)
{
    setStyleSheet(valid ? "" : STYLE_INVALID);

    if(valid)
    {
        if(toPlainText() == this->errorText)
        {
            setPlainText("");
        }
    }
    else if(toPlainText() == "")
    {
        setPlainText(this->errorText);
    }

}


void QValidatedTextEdit::setErrorText(QString errorText)
{
    this->errorText = errorText;
}


void QValidatedTextEdit::focusInEvent(QFocusEvent *evt)
{
    // Clear invalid flag on focus
    setValid(true);
    
    QPlainTextEdit::focusInEvent(evt);
}


void QValidatedTextEdit::markValid()
{
    setValid(true);
}


void QValidatedTextEdit::clear()
{
    setValid(true);

    QPlainTextEdit::clear();
}
