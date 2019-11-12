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


#ifndef BITCOIN_QT_WALLETMODELTRANSACTION_H
#define BITCOIN_QT_WALLETMODELTRANSACTION_H

#include "walletmodel.h"
#include "util.h"

#include <QObject>


class SendCoinsRecipient;

class CReserveKey;
class CWallet;
class CWalletTx;


/** Data model for a walletmodel transaction. */
class WalletModelTransaction
{
    public:

        explicit WalletModelTransaction(const QList<SendCoinsRecipient> &recipients);

        ~WalletModelTransaction();

        QList<SendCoinsRecipient> getRecipients();

        CWalletTx *getTransaction();

        unsigned int getTransactionSize();

        void setTransactionFee(const CAmount& newFee);

        CAmount getTransactionFee();

        CAmount getTotalTransactionAmount();

        void newPossibleKeyChange(CWallet *wallet);

        CReserveKey *getPossibleKeyChange();

    private:

        const QList<SendCoinsRecipient> recipients;

        CWalletTx *walletTransaction;

        CReserveKey *keyChange;
        
        CAmount fee;
};

#endif // BITCOIN_QT_WALLETMODELTRANSACTION_H
