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


#ifndef EDITADDRESSDIALOG_H
#define EDITADDRESSDIALOG_H

#include <QDialog>

namespace Ui
{
    class EditAddressDialog;
}

class AddressTableModel;

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditAddressDialog : public QDialog
{
    Q_OBJECT

    public:
    
        enum Mode
        {
            NewReceivingAddress,
            NewSendingAddress,
            EditReceivingAddress,
            EditSendingAddress
        };

        explicit EditAddressDialog(Mode mode, QWidget *parent = 0);
        
        ~EditAddressDialog();

        void setModel(AddressTableModel *model);
        void loadRow(int row);

        QString getAddress() const;
        void setAddress(const QString &address);

    private slots:

        void on_EditAddressPasteButton_clicked();

    public slots:

        void accept();

    private:

        bool saveCurrentRow();

        Ui::EditAddressDialog *ui;
        QDataWidgetMapper *mapper;
        Mode mode;
        AddressTableModel *model;

        QString address;
};

#endif // EDITADDRESSDIALOG_H
