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


#ifndef DARKSENDCONFIG_H
#define DARKSENDCONFIG_H

#include <QDialog>

namespace Ui
{
    class DarksendConfig;
}

class WalletModel;

/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class DarksendConfig : public QDialog
{
    Q_OBJECT

    public:

        DarksendConfig(QWidget *parent = 0);
        ~DarksendConfig();

        void setModel(WalletModel *model);


    private:

        Ui::DarksendConfig *ui;
        
        WalletModel *model;

        void configure(bool enabled, int coins, int rounds);

    private slots:

        void clickBasic();
        void clickHigh();
        void clickMax();
};

#endif // DARKSENDCONFIG_H
