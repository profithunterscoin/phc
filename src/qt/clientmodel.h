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


#ifndef CLIENTMODEL_H
#define CLIENTMODEL_H

#include <QObject>

class OptionsModel;
class AddressTableModel;
class BanTableModel;
class PeerTableModel;
class TransactionTableModel;
class CWallet;

QT_BEGIN_NAMESPACE
class QDateTime;
class QTimer;
QT_END_NAMESPACE


/** Model for Bitcoin network client. */
class ClientModel : public QObject
{
    Q_OBJECT

    public:
    
        explicit ClientModel(OptionsModel *optionsModel, QObject *parent = 0);
        ~ClientModel();

        OptionsModel *getOptionsModel();
        PeerTableModel *getPeerTableModel();
        BanTableModel *getBanTableModel();

        int getNumConnections() const;
        
        QString getMasternodeCountString() const;
        
        int getNumBlocks() const;
        int getNumBlocksAtStartup();

        quint64 getTotalBytesRecv() const;
        quint64 getTotalBytesSent() const;

        QDateTime getLastBlockDate() const;

        //! Return true if client connected to testnet
        bool isTestNet() const;
        
        //! Return true if core is doing initial block download
        bool inInitialBlockDownload() const;
        
        //! Return true if core is importing blocks
        bool isImporting() const;
        
        //! Return warnings to be displayed in status bar
        QString getStatusBarWarnings() const;

        QString formatFullVersion() const;
        QString formatBuildDate() const;
        bool isReleaseVersion() const;
        QString clientName() const;
        QString formatClientStartupTime() const;

    private:

        OptionsModel *optionsModel;
        PeerTableModel *peerTableModel;
        BanTableModel *banTableModel;

        int cachedNumBlocks;

        int numBlocksAtStartup;

        QString cachedMasternodeCountString;

        QTimer *pollTimer;
        QTimer *pollMnTimer;

        void subscribeToCoreSignals();

        void unsubscribeFromCoreSignals();

    signals:

        void numConnectionsChanged(int count);

        void numBlocksChanged(int count);

        void strMasternodesChanged(const QString &strMasternodes);

        void alertsChanged(const QString &warnings);

        void bytesChanged(quint64 totalBytesIn, quint64 totalBytesOut);

        //! Asynchronous message notification
        void message(const QString &title, const QString &message, bool modal, unsigned int style);

        // Show progress dialog e.g. for verifychain
        void showProgress(const QString &title, int nProgress);

    public slots:

        void updateTimer();

        void updateMnTimer();

        void updateNumConnections(int numConnections);

        void updateAlert(const QString &hash, int status);

        void updateBanlist();
};

#endif // CLIENTMODEL_H
