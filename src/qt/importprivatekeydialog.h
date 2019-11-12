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

#ifndef IMPORTPRIVATEKEYDIALOG_H
#define IMPORTPRIVATEKEYDIALOG_H

#include <QDialog>

namespace Ui
{
    class ImportPrivateKeyDialog;
}

class AddressTableModel;

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for importing a private key
 */
class ImportPrivateKeyDialog : public QDialog
{
    Q_OBJECT

    public:

        explicit ImportPrivateKeyDialog(QWidget *parent = 0);
        
        ~ImportPrivateKeyDialog();

        void setModel(AddressTableModel *model);

    private slots:

        void on_ImportPrivateKeyPasteButton_clicked();

    public slots:

        void accept();

    private:

        bool save();

        Ui::ImportPrivateKeyDialog *ui;
        QDataWidgetMapper *mapper;
        AddressTableModel *model;
};

#endif // IMPORTPRIVATEKEYDIALOG_H