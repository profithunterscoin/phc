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


#ifndef COINCONTROLDIALOG_H
#define COINCONTROLDIALOG_H

#include <QAbstractButton>
#include <QAction>
#include <QDialog>
#include <QList>
#include <QMenu>
#include <QPoint>
#include <QString>
#include <QTreeWidgetItem>

class WalletModel;
class CCoinControl;

namespace Ui
{
    class CoinControlDialog;
}

class CoinControlDialog : public QDialog
{
    Q_OBJECT

    public:

        explicit CoinControlDialog(QWidget *parent = 0);

        ~CoinControlDialog();

        void setModel(WalletModel *model);

        // static because also called from sendcoinsdialog
        static void updateLabels(WalletModel*, QDialog*);

        static QString getPriorityLabel(double);

        static QList<qint64> payAmounts;

        static CCoinControl *coinControl;

    private:

        Ui::CoinControlDialog *ui;

        WalletModel *model;

        int sortColumn;

        Qt::SortOrder sortOrder;

        QMenu *contextMenu;

        QTreeWidgetItem *contextMenuItem;

        QAction *copyTransactionHashAction;
        QAction *lockAction;
        QAction *unlockAction;

        QString strPad(QString, int, QString);

        void sortView(int, Qt::SortOrder);

        void updateView();

        enum
        {
            COLUMN_CHECKBOX,
            COLUMN_AMOUNT,
            COLUMN_LABEL,
            COLUMN_ADDRESS,
            COLUMN_DARKSEND_ROUNDS,
            COLUMN_DATE,
            COLUMN_CONFIRMATIONS,
            COLUMN_PRIORITY,
            COLUMN_TXHASH,
            COLUMN_VOUT_INDEX,
            COLUMN_AMOUNT_INT64,
            COLUMN_PRIORITY_INT64,
            COLUMN_DATE_INT64
        };

        // some columns have a hidden column containing the value used for sorting
        int getMappedColumn(int column, bool fVisibleColumn = true)
        {
            if (fVisibleColumn)
            {
                switch (column)
                {
                    case COLUMN_AMOUNT_INT64:
                    {
                        return COLUMN_AMOUNT;
                    }
                    break;

                    case COLUMN_PRIORITY_INT64:
                    {
                        return COLUMN_PRIORITY;
                    }
                    break;

                    case COLUMN_DATE_INT64:
                    {
                        return COLUMN_DATE;
                    }
                    break;
                }
            }
            else
            {
                switch (column)
                {
                    case COLUMN_AMOUNT:
                    {
                        return COLUMN_AMOUNT_INT64;
                    }
                    break;

                    case COLUMN_PRIORITY:
                    {
                        return COLUMN_PRIORITY_INT64;
                    }
                    break;

                    case COLUMN_DATE:
                    {
                        return COLUMN_DATE_INT64;
                    }
                    break;
                }
            }

            return column;
        }

    private slots:

        void showMenu(const QPoint &);

        void copyAmount();

        void copyLabel();

        void copyAddress();

        void copyTransactionHash();

        void lockCoin();

        void unlockCoin();

        void clipboardQuantity();
        void clipboardAmount();
        void clipboardFee();
        void clipboardAfterFee();
        void clipboardBytes();
        void clipboardPriority();
        void clipboardLowOutput();
        void clipboardChange();

        void radioTreeMode(bool);
        void radioListMode(bool);

        void viewItemChanged(QTreeWidgetItem*, int);
        
        void headerSectionClicked(int);

        void buttonBoxClicked(QAbstractButton*);
        void buttonSelectAllClicked();
        void buttonToggleLockClicked();

        void updateLabelLocked();
};

#endif // COINCONTROLDIALOG_H
