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


#ifndef COINCONTROLTREEWIDGET_H
#define COINCONTROLTREEWIDGET_H

#include <QKeyEvent>
#include <QTreeWidget>


class CoinControlTreeWidget : public QTreeWidget
{
    Q_OBJECT

  public:

    explicit CoinControlTreeWidget(QWidget *parent = 0);
      
  protected:

    virtual void  keyPressEvent(QKeyEvent *event);
};

#endif // COINCONTROLTREEWIDGET_H