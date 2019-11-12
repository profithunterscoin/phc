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


#include "importprivatekeydialog.h"
#include "ui_importprivatekeydialog.h"

#include "addresstablemodel.h"
#include "base58.h"
#include "init.h"

#include <QDataWidgetMapper>
#include <QMessageBox>
#include <QClipboard>


ImportPrivateKeyDialog::ImportPrivateKeyDialog(QWidget *parent) : QDialog(parent), ui(new Ui::ImportPrivateKeyDialog), mapper(0), model(0)
{
    ui->setupUi(this);

    ui->rescanCB->setChecked(true);

    mapper = new QDataWidgetMapper(this);

    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}


ImportPrivateKeyDialog::~ImportPrivateKeyDialog()
{
    delete ui;
}


void ImportPrivateKeyDialog::setModel(AddressTableModel *model)
{
    this->model = model;

    if(!model)
    {
        return;
    }

    mapper->setModel(model);
    
    mapper->addMapping(ui->labelEdit, AddressTableModel::Label);
}


void ImportPrivateKeyDialog::accept()
{
    if(!model)
    {
        return;
    }

    QString strKey = ui->keyEdit->text();

    if (!strKey.isEmpty())
    {
        CPHCcoinSecret vchSecret;

        bool fGood = vchSecret.SetString(strKey.toUtf8().constData());

        if (fGood)
        {
            QString strLabel = ui->labelEdit->text();
            bool fRescan = ui->rescanCB->isChecked();

            if (pwalletMain->ImportPrivateKey(vchSecret, strLabel.toUtf8().constData(), fRescan))
            {
                QMessageBox::information(this, tr("Success"), tr("Private key successfully imported!"));
                
                // Refresh the "receive" tab
                model->refresh();
            }
            else
            {
                QMessageBox::warning(this, tr("Error"), tr("Error adding key to wallet"));

                return;
            }
        }
        else
        {
            QMessageBox::warning(this, tr("Error"), tr("Invalid private key"));

            return;
        }
    }
    else
    {
        return;
    }

    QDialog::accept();
}


void ImportPrivateKeyDialog::on_ImportPrivateKeyPasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->keyEdit->setText(QApplication::clipboard()->text());
} 