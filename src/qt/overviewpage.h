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


#ifndef OVERVIEWPAGE_H
#define OVERVIEWPAGE_H

#include "util.h"

#include <QTimer>
#include <QWidget>


class ClientModel;
class WalletModel;
class TxViewDelegate;
class TransactionFilterProxy;


namespace Ui
{
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE


/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

    public:
    
        explicit OverviewPage(QWidget *parent = 0);
        
        ~OverviewPage();

        void setClientModel(ClientModel *clientModel);

        void setWalletModel(WalletModel *walletModel);

        void showOutOfSyncWarning(bool fShow);

        void updateDarksendProgress();

    public slots:

        void darkSendStatus();

        void setBalance(const CAmount& balance, const CAmount& stake, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, const CAmount& anonymizedBalance, const CAmount& watchOnlyBalance, const CAmount& watchOnlyStake, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);

    signals:

        void transactionClicked(const QModelIndex &index);

    private:

        QTimer *timer;

        Ui::OverviewPage *ui;

        ClientModel *clientModel;

        WalletModel *walletModel;

        CAmount currentBalance;
        CAmount currentStake;
        CAmount currentUnconfirmedBalance;
        CAmount currentImmatureBalance;
        CAmount currentAnonymizedBalance;
        CAmount currentWatchOnlyBalance;
        CAmount currentWatchOnlyStake;
        CAmount currentWatchUnconfBalance;
        CAmount currentWatchImmatureBalance;

        int nDisplayUnit;

        TxViewDelegate *txdelegate;
        TransactionFilterProxy *filter;

    private slots:

        void toggleDarksend();

        void darksendAuto();

        void darksendReset();

        void updateDisplayUnit();

        void handleTransactionClicked(const QModelIndex &index);

        void updateAlerts(const QString &warnings);

        void updateWatchOnlyLabels(bool showWatchOnly);
};

#endif // OVERVIEWPAGE_H