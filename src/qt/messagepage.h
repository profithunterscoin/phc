// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2014-2015 The ShadowCoin developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2019 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#ifndef MESSAGEPAGE_H
#define MESSAGEPAGE_H

#include <QWidget>

namespace Ui
{
    class MessagePage;
}

class MessageModel;
//class OptionsModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
class MessageViewDelegate;
class MRichTextEdit;
QT_END_NAMESPACE


/** Widget that shows a list of sending or receiving addresses.
  */
class MessagePage : public QWidget
{
    Q_OBJECT

    public:

        explicit MessagePage(QWidget *parent = 0);
        
        ~MessagePage();

        void setModel(MessageModel *model);

    private:

        void setupTextActions();

    public slots:

        void exportClicked();

    private:

        Ui::MessagePage *ui;
        MessageModel *model;
        
        QMenu *contextMenu;
        
        QAction *replyAction;
        QAction *copyFromAddressAction;
        QAction *copyToAddressAction;
        QAction *deleteAction;
        QString replyFromAddress;
        QString replyToAddress;
        
        MessageViewDelegate *msgdelegate;
        
        MRichTextEdit *messageTextEdit;

    private slots:

        void on_sendButton_clicked();
        
        void on_newButton_clicked();

        void on_copyFromAddressButton_clicked();

        void on_copyToAddressButton_clicked();

        void on_deleteButton_clicked();

        void on_backButton_clicked();

        void messageTextChanged();

        void selectionChanged();

        void itemSelectionChanged();

        void incomingMessage();

        /** Spawn contextual menu (right mouse menu) for address book entry */
        void contextualMenu(const QPoint &point);

    signals:
};

#endif // MESSAGEPAGE_H
