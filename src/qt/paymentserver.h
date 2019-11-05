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


#ifndef PAYMENTSERVER_H
#define PAYMENTSERVER_H

//
// This class handles payment requests from clicking on
// bitcoin: URIs
//
// This is somewhat tricky, because we have to deal with
// the situation where the user clicks on a link during
// startup/initialization, when the splash-screen is up
// but the main window (and the Send Coins tab) is not.
//
// So, the strategy is:
//
// Create the server, and register the event handler,
// when the application is created. Save any URIs
// received at or during startup in a list.
//
// When startup is finished and the main window is
// shown, a signal is sent to slot uiReady(), which
// emits a receivedURL() signal for any payment
// requests that happened during startup.
//
// After startup, receivedURL() happens as usual.
//
// This class has one more feature: a static
// method that finds URIs passed in the command line
// and, if a server is running in another process,
// sends them to the server.
//
#include <QObject>
#include <QString>

class OptionsModel;

class QApplication;
class QLocalServer;

class PaymentServer : public QObject
{
    Q_OBJECT

    private:

        bool saveURIs;
        
        QLocalServer* uriServer;

    public:

        // Returns true if there were URIs on the command line
        // which were successfully sent to an already-running
        // process.
        static bool ipcSendCommandLine();

        PaymentServer(QApplication* parent);

        bool eventFilter(QObject *object, QEvent *event);

        // OptionsModel is used for getting proxy settings and display unit
        void setOptionsModel(OptionsModel *optionsModel);

    signals:

        void receivedURI(QString);

    public slots:

        // Signal this when the main window's UI is ready
        // to display payment requests to the user
        void uiReady();

    private slots:

        void handleURIConnection();

    private:

        OptionsModel *optionsModel;
};

#endif // PAYMENTSERVER_H
