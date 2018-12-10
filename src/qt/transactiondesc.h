// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018 Profit Hunters Coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef TRANSACTIONDESC_H
#define TRANSACTIONDESC_H

#include <QString>
#include <QObject>

class TransactionRecord;
class CWallet;
class CWalletTx;

/** Provide a human-readable extended HTML description of a transaction.
 */
class TransactionDesc: public QObject
{
    Q_OBJECT

    public:

        static QString toHTML(CWallet *wallet, CWalletTx &wtx, TransactionRecord *rec, int unit);

    private:
    
        TransactionDesc() {}

        static QString FormatTxStatus(const CWalletTx& wtx);
};

#endif // TRANSACTIONDESC_H
