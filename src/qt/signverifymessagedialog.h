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


#ifndef SIGNVERIFYMESSAGEDIALOG_H
#define SIGNVERIFYMESSAGEDIALOG_H

#include <QDialog>

namespace Ui
{
    class SignVerifyMessageDialog;
}

class WalletModel;

class SignVerifyMessageDialog : public QDialog
{
    Q_OBJECT

    public:

        explicit SignVerifyMessageDialog(QWidget *parent = 0);
        
        ~SignVerifyMessageDialog();

        void setModel(WalletModel *model);
        
        void setAddress_SM(QString address);
        void setAddress_VM(QString address);

        void showTab_SM(bool fShow);
        void showTab_VM(bool fShow);

    protected:

        bool eventFilter(QObject *object, QEvent *event);

    private:

        Ui::SignVerifyMessageDialog *ui;
        WalletModel *model;

    private slots:

        /* sign message */
        void on_addressBookButton_SM_clicked();
        void on_pasteButton_SM_clicked();
        void on_signMessageButton_SM_clicked();
        void on_copySignatureButton_SM_clicked();
        void on_clearButton_SM_clicked();
        
        /* verify message */
        void on_addressBookButton_VM_clicked();
        void on_verifyMessageButton_VM_clicked();
        void on_clearButton_VM_clicked();
};

#endif // SIGNVERIFYMESSAGEDIALOG_H
