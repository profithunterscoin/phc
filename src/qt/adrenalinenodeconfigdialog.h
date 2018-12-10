// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018 Profit Hunters Coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef ADRENALINENODECONFIGDIALOG_H
#define ADRENALINENODECONFIGDIALOG_H

#include <QDialog>

namespace Ui
{
    class AdrenalineNodeConfigDialog;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Dialog showing transaction details. */
class AdrenalineNodeConfigDialog : public QDialog
{
    Q_OBJECT

    public:

        explicit AdrenalineNodeConfigDialog(QWidget *parent = 0, QString nodeAddress = "123.456.789.123:20060", QString privkey="MASTERNODEPRIVKEY");
        ~AdrenalineNodeConfigDialog();

    private:

        Ui::AdrenalineNodeConfigDialog *ui;
};

#endif // ADRENALINENODECONFIGDIALOG_H
