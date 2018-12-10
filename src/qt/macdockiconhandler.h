// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018 Profit Hunters Coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef MACDOCKICONHANDLER_H
#define MACDOCKICONHANDLER_H

#include <QMainWindow>
#include <QObject>

QT_BEGIN_NAMESPACE
class QIcon;
class QMenu;
class QWidget;
QT_END_NAMESPACE

#ifdef __OBJC__
@class DockIconClickEventHandler;
#else
class DockIconClickEventHandler;
#endif

/** Macintosh-specific dock icon handler.
 */
class MacDockIconHandler : public QObject
{
    Q_OBJECT

    public:

        ~MacDockIconHandler();

        QMenu *dockMenu();

        void setIcon(const QIcon &icon);
        
        void setMainWindow(QMainWindow *window);

        static MacDockIconHandler *instance();

        void handleDockIconClickEvent();

    signals:

        void dockIconClicked();

    private:

        MacDockIconHandler();

        DockIconClickEventHandler *m_dockIconClickEventHandler;

        QWidget *m_dummyWidget;

        QMenu *m_dockMenu;

        QMainWindow *mainWindow;
};

#endif // MACDOCKICONCLICKHANDLER_H
