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


#ifndef ASKPASSPHRASEDIALOG_H
#define ASKPASSPHRASEDIALOG_H

#include <QDialog>


namespace Ui
{
    class AskPassphraseDialog;
}


class WalletModel;


/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class AskPassphraseDialog : public QDialog
{
    Q_OBJECT

    public:

        enum Mode
        {
            Encrypt,       /**< Ask passphrase twice and encrypt */
            UnlockStaking, /**< Ask passphrase and unlock */
            Unlock,        /**< Ask passphrase and unlock */
            ChangePass,    /**< Ask old passphrase + new passphrase twice */
            Decrypt        /**< Ask passphrase and decrypt wallet */
        };

        explicit AskPassphraseDialog(Mode mode, QWidget *parent = 0);

        ~AskPassphraseDialog();

        void accept();

        void setModel(WalletModel *model);

    private:

        Ui::AskPassphraseDialog *ui;
        
        Mode mode;
        
        WalletModel *model;
       
        bool fCapsLock;

    private slots:

        void textChanged();

    protected:

        bool event(QEvent *event);
        bool eventFilter(QObject *, QEvent *event);
        
        void secureClearPassFields();
};

#endif // ASKPASSPHRASEDIALOG_H
