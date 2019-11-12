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


#ifndef SENDMESSAGESENTRY_H
#define SENDMESSAGESENTRY_H

#include <QFrame>


namespace Ui
{
    class SendMessagesEntry;
}

class MessageModel;
class SendMessagesRecipient;


/** A single entry in the dialog for sending messages. */
class SendMessagesEntry : public QFrame
{
    Q_OBJECT

    public:

        explicit SendMessagesEntry(QWidget *parent = 0);
        
        ~SendMessagesEntry();

        void setModel(MessageModel *model);

        void loadRow(int row);

        bool validate();

        SendMessagesRecipient getValue();

        /** Return whether the entry is still empty and unedited */
        bool isClear();

        void setValue(const SendMessagesRecipient &value);

        /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
        */
        QWidget *setupTabChain(QWidget *prev);

        void setFocus();

    public slots:

        void setRemoveEnabled(bool enabled);

        void clear();
        
    signals:

        void removeEntry(SendMessagesEntry *entry);

    private slots:

        void on_deleteButton_clicked();

        void on_addressBookButton_clicked();

        void on_pasteButton_clicked();

        void on_PubkeyPasteButton_clicked();

        void on_sendTo_textChanged(const QString &address);

    private:

        Ui::SendMessagesEntry *ui;
        
        MessageModel *model;
};

#endif // SENDMESSAGESENTRY_H
