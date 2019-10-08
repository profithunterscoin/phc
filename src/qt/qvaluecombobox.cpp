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


#include "qvaluecombobox.h"

#include <QStyledItemDelegate>


QValueComboBox::QValueComboBox(QWidget *parent) : QComboBox(parent), role(Qt::UserRole)
{
    setItemDelegate(new QStyledItemDelegate());

    connect(this, SIGNAL(currentIndexChanged(int)), this, SLOT(handleSelectionChanged(int)));
}


QVariant QValueComboBox::value() const
{
    return itemData(currentIndex(), role);
}


void QValueComboBox::setValue(const QVariant &value)
{
    setCurrentIndex(findData(value, role));
}


void QValueComboBox::setRole(int role)
{
    this->role = role;
}


void QValueComboBox::handleSelectionChanged(int idx)
{
    emit valueChanged();
}
