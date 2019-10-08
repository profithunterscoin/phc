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


#ifndef QVALIDATEDTEXTEDIT_H
#define QVALIDATEDTEXTEDIT_H

#include <QPlainTextEdit>

/** Text edit that can be marked as "invalid" to show input validation feedback. When marked as invalid,
   it will get a red background until it is focused.
 */
class QValidatedTextEdit : public QPlainTextEdit
{
    Q_OBJECT

    public:

        explicit QValidatedTextEdit(QWidget *parent = 0);
        
        void clear();

    protected:

        void focusInEvent(QFocusEvent *evt);

    private:

        bool valid;

        QString errorText;

    public slots:

        void setValid(bool valid);

        void setErrorText(QString errorText);

    private slots:

        void markValid();
};

#endif // QVALIDATEDTEXTEDIT_H
