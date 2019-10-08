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


#ifndef MONITOREDDATAMAPPER_H
#define MONITOREDDATAMAPPER_H

#include <QDataWidgetMapper>

QT_BEGIN_NAMESPACE
class QWidget;
QT_END_NAMESPACE


/** Data to Widget mapper that watches for edits and notifies listeners when a field is edited.
   This can be used, for example, to enable a commit/apply button in a configuration dialog.
 */
class MonitoredDataMapper : public QDataWidgetMapper
{
    Q_OBJECT

    public:

        explicit MonitoredDataMapper(QObject *parent=0);

        void addMapping(QWidget *widget, int section);
        void addMapping(QWidget *widget, int section, const QByteArray &propertyName);

    private:

        void addChangeMonitor(QWidget *widget);

    signals:

        void viewModified();
};

#endif // MONITOREDDATAMAPPER_H
