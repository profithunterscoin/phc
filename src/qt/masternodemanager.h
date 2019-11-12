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


#ifndef MASTERNODEMANAGER_H
#define MASTERNODEMANAGER_H

#include "util.h"
#include "sync.h"
#include "guiutil.h"

#include <QMenu>
#include <QWidget>
#include <QTimer>
#include <QItemSelectionModel>

namespace Ui
{
    class MasternodeManager;
}

class ClientModel;
class WalletModel;
class QAbstractItemView;
class QItemSelectionModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Masternode Manager page widget */
class MasternodeManager : public QWidget
{
    Q_OBJECT

    public:
        explicit MasternodeManager(QWidget *parent = 0);
        
        ~MasternodeManager();

        void setClientModel(ClientModel *clientModel);
        void setWalletModel(WalletModel *walletModel);

    private:

        QMenu* contextMenu;
        
    public slots:

        void updateNodeList();

        void updateAdrenalineNode(QString alias, QString addr, QString privkey, QString txHash, QString txIndex, QString rewardAddress, QString rewardPercentage, QString status);
       
        void on_UpdateButton_clicked();
        
        void copyAddress();
        
        void copyPubkey();
        
        /** open the masternode.conf from the current datadir */
        void on_openMNConfigfileButton_clicked();

    signals:

    private:

        QTimer *timer;
        
        Ui::MasternodeManager *ui;
        
        ClientModel *clientModel;
        WalletModel *walletModel;
        
        CCriticalSection cs_adrenaline;

    private slots:

        void showContextMenu(const QPoint&);
        
        void on_createButton_clicked();
        
        void on_startButton_clicked();
        
        void on_startAllButton_clicked();
        
        void on_tableWidget_2_itemSelectionChanged();
        
        void on_tabWidget_currentChanged(int index);
};
#endif // MASTERNODEMANAGER_H
