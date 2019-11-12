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


#ifndef TRANSACTIONDESCDIALOG_H
#define TRANSACTIONDESCDIALOG_H

#include <QDialog>


namespace Ui
{
    class TransactionDescDialog;
}


QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE


/** Dialog showing transaction details. */
class TransactionDescDialog : public QDialog
{
    Q_OBJECT

    public:

        explicit TransactionDescDialog(const QModelIndex &idx, QWidget *parent = 0);
        
        ~TransactionDescDialog();

    private:
    
        Ui::TransactionDescDialog *ui;
};

#endif // TRANSACTIONDESCDIALOG_H
