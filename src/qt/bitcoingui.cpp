// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2012 W.J. van der Laan
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php

/*
* Qt4 & Qt 5 bitcoin GUI.
*/


#include <QApplication>

#include "bitcoingui.h"

#include "transactiontablemodel.h"
#include "addressbookpage.h"
#include "sendcoinsdialog.h"
#include "signverifymessagedialog.h"
#include "optionsdialog.h"
#include "aboutdialog.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "editaddressdialog.h"
#include "optionsmodel.h"
#include "transactiondescdialog.h"
#include "addresstablemodel.h"
#include "transactionview.h"
#include "overviewpage.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "askpassphrasedialog.h"
#include "notificator.h"
#include "guiutil.h"
#include "rpcconsole.h"
#include "wallet.h"
#include "main.h"
#include "init.h"
#include "ui_interface.h"
#include "masternodemanager.h"
#include "messagemodel.h"
#include "messagepage.h"
#include "blockbrowser.h"
#include "importprivatekeydialog.h"
//#include "tradingdialog.h"

#ifdef Q_OS_MAC
#include "macdockiconhandler.h"
#endif

#include <QMenuBar>
#include <QMenu>
#include <QIcon>
#include <QVBoxLayout>
#include <QToolBar>
#include <QStatusBar>
#include <QLabel>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QProgressDialog>
#include <QStackedWidget>
#include <QDateTime>
#include <QMovie>
#include <QFileDialog>
#include <QDesktopServices>
#include <QTimer>
#include <QDragEnterEvent>
#include <QUrl>
#include <QMimeData>
#include <QStyle>
#include <QToolButton>
#include <QScrollArea>
#include <QScroller>
#include <QTextDocument>
#include <QInputDialog>

extern bool fOnlyTor;

extern CWallet* pwalletMain;

extern int64_t nLastCoinStakeSearchInterval;

double GetPoSKernelPS();


BitcoinGUI::BitcoinGUI(QWidget *parent) :
	QMainWindow(parent),
	clientModel(0),
	walletModel(0),
	toolbar(0),
	progressBarLabel(0),
	progressBar(0),
	progressDialog(0),
	encryptWalletAction(0),
	changePassphraseAction(0),
	unlockWalletAction(0),
	lockWalletAction(0),
	aboutQtAction(0),
	trayIcon(0),
	notificator(0),
	rpcConsole(0),
	prevBlocks(0),
	nWeight(0)
{
	resize(1250, 520);
	setWindowTitle(tr("PHC") + " - " + tr("Wallet"));

	QWidget *frameBlocks = new QWidget();

	if (!fUseBlackTheme)
	{
		// NORMAL THEME

		frameBlocks->setStyleSheet("QWidget"
							"{"
							"	background-color: rgb(196, 226, 91);"
							"	margin-bottom: 5px;"
							"}"
							);

		qApp->setStyleSheet("QMainWindow"
							"{"
							"	background-image:url(:images/bkg);"
							"	border:none;"
							"	font-family:'Open Sans,sans-serif';"
							"}"

							"QMenuBar"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QMenuBar::item"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QMenuBar::item::selected"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QMenu"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QMenu::item:selected"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton"
							"{"
							"	color:#ecf0f1;"
							"	border-radius:5px;"
							"	border:solid 1px #E5D738;"
							"	background:#757575;"
							"	padding:3px 30px;"
							"}"

							"QPushButton:hover"
							"{"
							"	background-color: rgb(102, 102, 102);"
							"}"

							"QPushButton:focus"
							"{"
							"	border:none;"
							"	outline:none;"
							"}"

							"QPushButton:pressed"
							"{"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QFrame#frameCoinControl"
							"{"
							"	background-color: rgb(196, 226, 91);"
							"}"

							"QDialog"
							"{"
							"	background-color: rgb(196, 226, 91);"
							"}"

							"QGridLayout"
							"{"
							"	color: #000000;"
							"	background-color: rgb(196, 226, 91);"
							"}"

							"QHBoxLayout"
							"{"
							"	color: #000000;"
							"	background-color: rgb(196, 226, 91);"
							"}"
					
							);

		// Override style sheet for progress bar for styles that have a segmented progress bar,
		// as they make the text unreadable (workaround for issue #1071)
		// See https://qt-project.org/doc/qt-4.8/gallery.html
		QString curStyle = qApp->style()->metaObject()->className();

		if (curStyle == "QWindowsStyle" || curStyle == "QWindowsXPStyle")
		{
			progressBar->setStyleSheet("QProgressBar"
										"{"
										"	color: #ffffff;"
										"	background-color: #e8e8e8;"
										"	border: 1px solid grey;"
										"	border-radius: 7px;"
										"	padding: 1px;"
										"	text-align: center;"
										"}"

										"QProgressBar::chunk"
										"{"
										"	background: QLinearGradient(x1: 0, y1: 0, x2: 1, y2: 0, stop: 0 #FF8000, stop: 1 yellow);"
										"	border-radius: 7px;"
										"	margin: 0px;"
										"}"
										);
		}

		statusBar()->setStyleSheet("#statusBar"
									"{"
									"	color: #000000;"
									"	background-color: qradialgradient(cx: -0.8, cy: 0, fx: -0.8, fy: 0, radius: 0.6, stop: 0 #101010, stop: 1 #A4D300);"
									"}"
									);

	}
	else
	{
		// DARK THEME
		frameBlocks->setStyleSheet("QWidget"
									"{"
									"	background: none;"
									"	margin-bottom: 5px;"
									"	color: #A4D300;"
									"}"
								);

		qApp->setStyleSheet("QMainWindow"
							"{"
							"	background-image:url(:images/bkg-dark);"
							"	border:none;"
							"	font-family:'Open Sans,sans-serif';"
							"	color: #E5D738;"
							"}"

							"QPushButton"
							"{"
							"	color: #000000;"
							"	border-radius: 5px;"
							"	border: solid 1px #E5D738;"
							"	background-color: #A4D300;"
							"	padding: 3px 30px;"
							"}"

							"QPushButton:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#runAutoDenom"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#runAutoDenom:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#runAutoDenom:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#darksendAuto"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#darksendAuto:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#darksendAuto:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#toggleDarksend"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#toggleDarksend:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#toggleDarksend:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#darksendReset"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#darksendReset:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#darksendReset:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#openDebugLogfileButton"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#openDebugLogfileButton:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#openDebugLogfileButton:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#openDebugLogfileButton"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#openDebugLogfileButton:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#openDebugLogfileButton:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#openConfigfileButton"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#openConfigfileButton:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#openConfigfileButton:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#openMNConfigfileButton"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#openMNConfigfileButton:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#openMNConfigfileButton:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#showCLOptionsButton"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#showCLOptionsButton:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#showCLOptionsButton:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QPushButton#btnClearTrafficGraph"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QPushButton#btnClearTrafficGraph:hover"
							"{"
							"	color: #000000;"
							"	background-color: #FFF700;"
							"}"

							"QPushButton#btnClearTrafficGraph:pressed"
							"{"
							"	color: #000000;"
							"	background-color: rgb(80, 80, 80);"
							"}"

							"QMenuBar"
							"{"
							"	color: #000000;"
							"	border: 2px solid;"
							"	border-color: #A4D300;"
							"	background-color: #A4D300;"
							"}"

							"QMenuBar::item"
							"{"
							"	border: 2px solid;"
							"	padding: 2px;"
							"	border-color: #A4D300;"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QMenuBar::item::selected"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QMenu"
							"{"
							"	border: 2px solid;"
							"	border-color: #A4D300;"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QMenu::item:selected"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QFrame#SendCoinsEntry"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QTableView"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QTextEdit#messagesWidget"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QTabWidget::tab::selected"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QTabWidget"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QWidget::tab::selected"
							"{"
							"	color: #000000;"
							"	background-color: #A4D300;"
							"}"

							"QWidget"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QWidget#RPCConsole"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QWidget#tab_info"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QWidget#tab_console"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QWidget#tab_nettraffic"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QWidget#tab_peers"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QWidget#scrollAreaWidgetContents"
							"{"
							"	background-color: #000000;"
							"}"

							"QWidget#MasternodeManager"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QDialog"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QGridLayout"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QTableWidget"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"	alternate-background-color: #000000;"
							"}"

							"QTableWidget:section"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QTabWidget"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"}"

							"QList"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"	alternate-background-color: #000000;"
							"}"

							"QLabel"
							"{"
							"	color: #A4D300;"
							"}"

							"QCheckBox"
							"{"
							"	border: none;"
							"	color: #A4D300;"
							"}"

							"QCheckBox:unchecked"
							"{"
							"	border: none;"
							"	color: #A4D300;"
							"}"

							"QCheckBox:checked"
							"{"
							"	border: none;"
							"	color: #A4D300;"
							"}"

							"QHeaderView::section"
							"{"
							"	color: #000000;"
							"}"

							"QRadioButton"
							"{"
							"	border: none;"
							"	color: #A4D300;"
							"}"

							"QFrame#frameCoinControl"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"}"
			
							"QGridLayout"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"}"

							"QHBoxLayout"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"}"

							"QWidget#tab"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"}"

							"QWidget#tab_2"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"}"

							"QFormLayout#formLayoutCoinControl2"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"}"

							"CoinControlTreeWidget"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QTableView"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QDialog#OptionsDialog"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QTabWidget"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QWidget#tabMain"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QWidget#tabNetwork"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QWidget#tabWindow"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QWidget#tabDisplay"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QWidget#tabSignMessage"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

							"QWidget#tabVerifyMessage"
							"{"
							"	color: #A4D300;"
							"	background-color: rgb(0, 0, 0);"
							"	alternate-background-color: rgb(0, 0, 0);"
							"}"

						);



		// Override style sheet for progress bar for styles that have a segmented progress bar,
		// as they make the text unreadable (workaround for issue #1071)
		// See https://qt-project.org/doc/qt-4.8/gallery.html
		QString curStyle = qApp->style()->metaObject()->className();

		if (curStyle == "QWindowsStyle" || curStyle == "QWindowsXPStyle")
		{
			progressBar->setStyleSheet("QProgressBar"
										"{"
										"	color: #A4D300;"
										"	background-color: #000000;"
										"	border: 1px solid #A4D300;"
										"	border-radius: 7px; padding: 1px;"
										"	text-align: center;"
										"}"
										"QProgressBar::chunk"
										"{"
										"	background: QLinearGradient(x1: 0, y1: 0, x2: 1, y2: 0, stop: 0 #FF8000, stop: 1 yellow);"
										"	border-radius: 7px; margin: 0px;"
										"}"
									);
		}

		statusBar()->setStyleSheet("#statusBar"
									"{"
									"	color: #A4D300;"
									"	background-color: qradialgradient(cx: -0.8, cy: 0, fx: -0.8, fy: 0, radius: 0.6, stop: 0 #A4D300, stop: 1 #000000);"
									"}"
								);

	}


#ifndef Q_OS_MAC
			qApp->setWindowIcon(QIcon(":icons/bitcoin"));
			setWindowIcon(QIcon(":icons/bitcoin"));
#else
			MacDockIconHandler::instance()->setIcon(QIcon(":icons/bitcoin"));
#endif

	setObjectName("PHC");

	setStyleSheet("#PHC"
					"{"
					"	background-color: qradialgradient(cx: -0.8, cy: 0, fx: -0.8, fy: 0, radius: 1.4, stop: 0 #dedede, stop: 1 #efefef);"
					"}"
				);
	
	// Accept D&D of URIs
	setAcceptDrops(true);

	// Create actions for the toolbar, menu bar and tray/dock icon
	createActions();

	// Create application menu bar
	createMenuBar();

	// Create the toolbars
	createToolBars();

	// Create the tray icon (or setup the dock icon)
	createTrayIcon();

	// Create tabs
	overviewPage = new OverviewPage();

	transactionsPage = new QWidget(this);
	QVBoxLayout *vbox = new QVBoxLayout();
	transactionView = new TransactionView(this);
	vbox->addWidget(transactionView);
	transactionsPage->setLayout(vbox);

	blockBrowser = new BlockBrowser(this);

	addressBookPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::SendingTab);

	receiveCoinsPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::ReceivingTab);

	sendCoinsPage = new SendCoinsDialog(this);

	//tradingDialogPage = new tradingDialog(this);
	//tradingDialogPage->setObjectName("tradingDialog");

	signVerifyMessageDialog = new SignVerifyMessageDialog(this);

	masternodeManagerPage = new MasternodeManager(this);
	messagePage = new MessagePage(this);

	centralStackedWidget = new QStackedWidget(this);
	centralStackedWidget->setContentsMargins(0, 0, 0, 0);
	centralStackedWidget->addWidget(overviewPage);
	centralStackedWidget->addWidget(transactionsPage);
	centralStackedWidget->addWidget(addressBookPage);
	centralStackedWidget->addWidget(receiveCoinsPage);
	centralStackedWidget->addWidget(sendCoinsPage);
	centralStackedWidget->addWidget(masternodeManagerPage);
	centralStackedWidget->addWidget(messagePage);
	centralStackedWidget->addWidget(blockBrowser);
	//centralStackedWidget->addWidget(tradingDialogPage);

	QWidget *centralWidget = new QWidget();
	QVBoxLayout *centralLayout = new QVBoxLayout(centralWidget);
	centralLayout->setContentsMargins(0, 0, 0, 0);
	centralWidget->setContentsMargins(0, 0, 0, 0);
	centralLayout->addWidget(centralStackedWidget);

	setCentralWidget(centralWidget);

	// Create status bar
	statusBar();

	// Disable size grip because it looks ugly and nobody needs it
	statusBar()->setSizeGripEnabled(false);

	// Status bar notification icons

	frameBlocks->setContentsMargins(0, 0, 0, 0);
	frameBlocks->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
	
	QHBoxLayout *frameBlocksLayout = new QHBoxLayout(frameBlocks);
	
	frameBlocksLayout->setContentsMargins(3, 0, 3, 0);
	frameBlocksLayout->setSpacing(3);
	frameBlocksLayout->setAlignment(Qt::AlignHCenter);
	
	labelEncryptionIcon = new QLabel();
	labelStakingIcon = new QLabel();
	labelConnectionsIcon = new QLabel();
	labelBlocksIcon = new QLabel();
	frameBlocksLayout->addWidget(netLabel);
	//frameBlocksLayout->addStretch();
	frameBlocksLayout->addWidget(labelEncryptionIcon);
	//frameBlocksLayout->addStretch();
	frameBlocksLayout->addWidget(labelStakingIcon);
	//frameBlocksLayout->addStretch();
	frameBlocksLayout->addWidget(labelConnectionsIcon);
	//frameBlocksLayout->addStretch();
	frameBlocksLayout->addWidget(labelBlocksIcon);
	//frameBlocksLayout->addStretch();
	frameBlocksLayout->addWidget(netLabel);
	//frameBlocksLayout->addStretch();


	if (GetBoolArg("-staking", true))
	{
		QTimer *timerStakingIcon = new QTimer(labelStakingIcon);
		connect(timerStakingIcon, SIGNAL(timeout()), this, SLOT(updateStakingIcon()));
		timerStakingIcon->start(20 * 1000);
		updateStakingIcon();
	}

	// Progress bar and label for blocks download
	progressBarLabel = new QLabel();
	progressBarLabel->setVisible(false);
	progressBar = new QProgressBar();
	progressBar->setAlignment(Qt::AlignCenter);
	progressBar->setVisible(false);

	if (!fUseBlackTheme)
	{
		progressBarLabel->setStyleSheet("QLabel"
										"{"
										"	color: #000000;"
										"}"
									);
	}
	else
	{
		progressBarLabel->setStyleSheet("QLabel"
										"{"
										"	color: #A4D300;"
										"}"
									);
	}

	statusBar()->addWidget(progressBarLabel);
	statusBar()->addWidget(progressBar);
	statusBar()->addPermanentWidget(frameBlocks);
	statusBar()->setObjectName("statusBar");

	syncIconMovie = new QMovie(fUseBlackTheme ? ":/movies/update_spinner_black" : ":/movies/update_spinner", "mng", this);

	// Clicking on a transaction on the overview page simply sends you to transaction history page
	connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), this, SLOT(gotoHistoryPage()));
	connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), transactionView, SLOT(focusTransaction(QModelIndex)));

	//connect(TradingAction, SIGNAL(triggered()), tradingDialogPage, SLOT(InitTrading()));

	// Double-clicking on a transaction on the transaction history page shows details
	connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

	rpcConsole = new RPCConsole(0);
	connect(openRPCConsoleAction, SIGNAL(triggered()), rpcConsole, SLOT(showConsole()));
	connect(openInformationAction, SIGNAL(triggered()), rpcConsole, SLOT(showInfo()));
	connect(openNetTrafficAction, SIGNAL(triggered()), rpcConsole, SLOT(showNetTraffic()));
	connect(openPeersAction, SIGNAL(triggered()), rpcConsole, SLOT(showPeers()));
	connect(openConfigFileAction, SIGNAL(triggered()), rpcConsole, SLOT(on_openPHCConfigfileButton_clicked()));
	connect(openMasternodeConfigFileAction, SIGNAL(triggered()), rpcConsole, SLOT(on_openMNConfigfileButton_clicked()));
	connect(openDebugFileAction, SIGNAL(triggered()), rpcConsole, SLOT(on_openDebugLogfileButton_clicked()));
	
	connect(setgenerateTRUEAction, SIGNAL(triggered()), rpcConsole, SLOT(setgenerateTRUE()));
	connect(setgenerateFALSEAction, SIGNAL(triggered()), rpcConsole, SLOT(setgenerateFALSE()));
	connect(setstakingTRUEAction, SIGNAL(triggered()), rpcConsole, SLOT(setstakingTRUE()));
	connect(setstakingFALSEAction, SIGNAL(triggered()), rpcConsole, SLOT(setstakingFALSE()));

	// clicking on automatic backups shows details
	connect(showBackupsAction, SIGNAL(triggered()), rpcConsole, SLOT(showBackups()));

	// prevents an oben debug window from becoming stuck/unusable on client shutdown
	connect(quitAction, SIGNAL(triggered()), rpcConsole, SLOT(hide()));

	// Clicking on "Verify Message" in the address book sends you to the verify message tab
	connect(addressBookPage, SIGNAL(verifyMessage(QString)), this, SLOT(gotoVerifyMessageTab(QString)));
	// Clicking on "Sign Message" in the receive coins page sends you to the sign message tab
	connect(receiveCoinsPage, SIGNAL(signMessage(QString)), this, SLOT(gotoSignMessageTab(QString)));

	gotoOverviewPage();
}


BitcoinGUI::~BitcoinGUI()
{
	if (trayIcon)
	{
	 // Hide tray icon, as deleting will let it linger until quit (on Ubuntu)
		trayIcon->hide();
	}

#ifdef Q_OS_MAC
	delete appMenuBar;
#endif

	delete rpcConsole;
}


void BitcoinGUI::createActions()
{
	QActionGroup *tabGroup = new QActionGroup(this);

	overviewAction = new QAction(QIcon(":/icons/overview"), tr("&Dashboard"), this);
	overviewAction->setToolTip(tr("Show general overview of wallet"));
	overviewAction->setCheckable(true);
	overviewAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_1));
	tabGroup->addAction(overviewAction);

	receiveCoinsAction = new QAction(QIcon(":/icons/receiving_addresses"), tr("&Receive"), this);
	receiveCoinsAction->setToolTip(tr("Show the list of addresses for receiving payments"));
	receiveCoinsAction->setCheckable(true);
	receiveCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_2));
	tabGroup->addAction(receiveCoinsAction);

	sendCoinsAction = new QAction(QIcon(":/icons/send"), tr("&Send"), this);
	sendCoinsAction->setToolTip(tr("Send coins to a PHC address"));
	sendCoinsAction->setCheckable(true);
	sendCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_3));
	tabGroup->addAction(sendCoinsAction);

	historyAction = new QAction(QIcon(":/icons/history"), tr("&Transactions"), this);
	historyAction->setToolTip(tr("Browse transaction history"));
	historyAction->setCheckable(true);
	historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_4));
	tabGroup->addAction(historyAction);

	addressBookAction = new QAction(QIcon(":/icons/address-book"), tr("&Addresses"), this);
	addressBookAction->setToolTip(tr("Edit the list of stored addresses and labels"));
	addressBookAction->setCheckable(true);
	addressBookAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_5));
	tabGroup->addAction(addressBookAction);

	masternodeManagerAction = new QAction(QIcon(":/icons/masternodes"), tr("&Masternodes"), this);
	masternodeManagerAction->setToolTip(tr("Show Master Nodes status and configure your nodes."));
	masternodeManagerAction->setCheckable(true);
	tabGroup->addAction(masternodeManagerAction);

	messageAction = new QAction(QIcon(":/icons/edit"), tr("&Messages"), this);
	messageAction->setToolTip(tr("View and Send Encrypted messages"));
	messageAction->setCheckable(true);
	tabGroup->addAction(messageAction);

	blockAction = new QAction(QIcon(":/icons/block"), tr("&Block Explorer"), this);
	blockAction->setToolTip(tr("Explore the BlockChain"));
	blockAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_6));
	blockAction->setCheckable(true);
	tabGroup->addAction(blockAction);

	//TradingAction = new QAction(QIcon(":/icons/trade"), tr("&Bittrex"), this);
	//TradingAction->setToolTip(tr("Start Trading"));
	//TradingAction->setCheckable(true);
	//TradingAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_8));
	//TradingAction->setProperty("objectName", "TradingAction");
	//tabGroup->addAction(TradingAction);

	showBackupsAction = new QAction(QIcon(":/icons/browse"), tr("Show Auto&Backups"), this);
	showBackupsAction->setStatusTip(tr("S"));

	//connect(TradingAction, SIGNAL(triggered()), this, SLOT(gotoTradingPage()));
	connect(blockAction, SIGNAL(triggered()), this, SLOT(gotoBlockBrowser()));
	connect(overviewAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
	connect(overviewAction, SIGNAL(triggered()), this, SLOT(gotoOverviewPage()));
	connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
	connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
	connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
	connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
	connect(historyAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
	connect(historyAction, SIGNAL(triggered()), this, SLOT(gotoHistoryPage()));
	connect(addressBookAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
	connect(addressBookAction, SIGNAL(triggered()), this, SLOT(gotoAddressBookPage()));
	connect(masternodeManagerAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
	connect(masternodeManagerAction, SIGNAL(triggered()), this, SLOT(gotoMasternodeManagerPage()));
	connect(messageAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
	connect(messageAction, SIGNAL(triggered()), this, SLOT(gotoMessagePage()));

	quitAction = new QAction(QIcon(":/icons/quit"), tr("E&xit"), this);
	quitAction->setToolTip(tr("Quit application"));
	quitAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
	quitAction->setMenuRole(QAction::QuitRole);

	aboutAction = new QAction(QIcon(":/icons/bitcoin1"), tr("&About PHC"), this);
	aboutAction->setToolTip(tr("Show information about PHC"));
	aboutAction->setMenuRole(QAction::AboutRole);
	
	aboutQtAction = new QAction(QIcon(":/qt-project.org/qmessagebox/images/qtlogo-64.png"), tr("About &Qt"), this);
	aboutQtAction->setToolTip(tr("Show information about Qt"));
	aboutQtAction->setMenuRole(QAction::AboutQtRole);

	linkWebsiteAction = new QAction(QIcon(":/icons/website"), tr("&PHC Website"), this);
	linkWebsiteAction->setToolTip(tr("Visit the Official PHC website"));

    linkBitcointalkAction = new QAction(QIcon(":/icons/bitcointalk"), tr("&Bitcointalk Discussion"), this);
	linkBitcointalkAction->setToolTip(tr("Visit our Bitcointalk discussion thread"));

	linkTwitterAction = new QAction(QIcon(":/icons/twitter"), tr("&PHC Twitter"), this);
    linkTwitterAction->setToolTip(tr("Join PHC Twitter"));

	linkFacebookAction = new QAction(QIcon(":/icons/facebook"), tr("&PHC Facebook"), this);
    linkFacebookAction->setToolTip(tr("Join PHC Facebook"));

    linkDiscordAction = new QAction(QIcon(":/icons/discord"), tr("&PHC Discord"), this);
    linkDiscordAction->setToolTip(tr("Join PHC Discord"));

	linkTelegramAction = new QAction(QIcon(":/icons/telegram"), tr("&PHC Telegram"), this);
    linkTelegramAction->setToolTip(tr("Join PHC Telegram"));

	linkSlackAction = new QAction(QIcon(":/icons/slack"), tr("&PHC Slack"), this);
    linkSlackAction->setToolTip(tr("Join PHC Slack Group"));

    linkExplorer1Action = new QAction(QIcon(":/icons/explorer"), tr("&PHC Explorer #1"), this);
	linkExplorer1Action->setToolTip(tr("PHC Explorer #1"));	
	
	linkExplorer2Action = new QAction(QIcon(":/icons/explorer"), tr("&PHC Explorer #2"), this);
	linkExplorer2Action->setToolTip(tr("PHC Explorer #2"));	
	
	optionsAction = new QAction(QIcon(":/icons/options"), tr("&Options..."), this);
	optionsAction->setToolTip(tr("Modify configuration options for PHC"));
	optionsAction->setMenuRole(QAction::PreferencesRole);
	
	toggleHideAction = new QAction(QIcon(":/icons/bitcoin"), tr("&Show / Hide"), this);
	
	encryptWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Encrypt Wallet..."), this);
	encryptWalletAction->setToolTip(tr("Encrypt or decrypt wallet"));
	
	backupWalletAction = new QAction(QIcon(":/icons/filesave"), tr("&Backup Wallet..."), this);
	backupWalletAction->setToolTip(tr("Backup wallet to another location"));
	
	importPrivateKeyAction = new QAction(QIcon(":/icons/key"), tr("&Import private key..."), this);
    importPrivateKeyAction->setToolTip(tr("Import a private key"));	

	changePassphraseAction = new QAction(QIcon(":/icons/key"), tr("&Change Passphrase..."), this);
	changePassphraseAction->setToolTip(tr("Change the passphrase used for wallet encryption"));
	
	unlockWalletAction = new QAction(QIcon(":/icons/lock_open"), tr("&Unlock Wallet..."), this);
	unlockWalletAction->setToolTip(tr("Unlock wallet"));
	
	lockWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Lock Wallet"), this);
	lockWalletAction->setToolTip(tr("Lock wallet"));
	
	signMessageAction = new QAction(QIcon(":/icons/edit"), tr("Sign &message..."), this);
	
	verifyMessageAction = new QAction(QIcon(":/icons/transaction_0"), tr("&Verify message..."), this);

	exportAction = new QAction(QIcon(":/icons/export"), tr("&Export..."), this);
	exportAction->setToolTip(tr("Export the data in the current tab to a file"));
	
	openRPCConsoleAction = new QAction(QIcon(":/icons/debugwindow"), tr("&RPC Console"), this);
	openRPCConsoleAction->setToolTip(tr("Open debugging and diagnostic console"));

	openInformationAction = new QAction(QIcon(":/icons/synced"), tr("&Information"), this);
	openInformationAction->setToolTip(tr("Open client information"));

	openNetTrafficAction = new QAction(QIcon(":/icons/connect_4"), tr("&Network Traffic"), this);
	openNetTrafficAction->setToolTip(tr("Open network traffic information"));

	openPeersAction = new QAction(QIcon(":/icons/eye"), tr("&Peers"), this);
	openPeersAction->setToolTip(tr("Open peers information"));

	openConfigFileAction = new QAction(QIcon(":/icons/edit"), tr("&Open Config File"), this);
	openConfigFileAction->setToolTip(tr("Open configuration file"));

	openMasternodeConfigFileAction = new QAction(QIcon(":/icons/edit"), tr("&Open Masternode Config File"), this);
	openMasternodeConfigFileAction->setToolTip(tr("Open masternode configuration file"));

	openDebugFileAction = new QAction(QIcon(":/icons/edit"), tr("&Open Debug File"), this);
	openDebugFileAction->setToolTip(tr("Open debug file"));

	setgenerateTRUEAction = new QAction(QIcon(":/icons/tx_mined"), tr("&Start"), this);
	setgenerateTRUEAction->setToolTip(tr("Start Internal CPU Miner"));

	setgenerateFALSEAction = new QAction(QIcon(":/icons/quit"), tr("&Stop"), this);
	setgenerateFALSEAction->setToolTip(tr("Stop Internal CPU Miner"));

	setstakingTRUEAction = new QAction(QIcon(":/icons/tx_staked"), tr("&Start"), this);
	setstakingTRUEAction->setToolTip(tr("Start Staking Thread"));

	setstakingFALSEAction = new QAction(QIcon(":/icons/quit"), tr("&Stop"), this);
	setstakingFALSEAction->setToolTip(tr("Stop Staking Thread"));

	connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
	connect(aboutAction, SIGNAL(triggered()), this, SLOT(aboutClicked()));
	connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
	connect(optionsAction, SIGNAL(triggered()), this, SLOT(optionsClicked()));
	connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHidden()));
	connect(encryptWalletAction, SIGNAL(triggered()), this, SLOT(encryptWallet()));
	connect(backupWalletAction, SIGNAL(triggered()), this, SLOT(backupWallet()));
	connect(importPrivateKeyAction, SIGNAL(triggered()), this, SLOT(importPrivateKey()));
	connect(changePassphraseAction, SIGNAL(triggered()), this, SLOT(changePassphrase()));
	connect(unlockWalletAction, SIGNAL(triggered()), this, SLOT(unlockWallet()));
	connect(lockWalletAction, SIGNAL(triggered()), this, SLOT(lockWallet()));
	connect(signMessageAction, SIGNAL(triggered()), this, SLOT(gotoSignMessageTab()));
	connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(gotoVerifyMessageTab()));

	connect(linkWebsiteAction, SIGNAL(triggered()), this, SLOT(linkWebsiteClicked()));
	connect(linkBitcointalkAction, SIGNAL(triggered()), this, SLOT(linkBitcointalkClicked()));
	connect(linkTwitterAction, SIGNAL(triggered()), this, SLOT(linkTwitterClicked()));
	connect(linkFacebookAction, SIGNAL(triggered()), this, SLOT(linkFacebookClicked()));
	connect(linkDiscordAction, SIGNAL(triggered()), this, SLOT(linkDiscordClicked()));
	connect(linkTelegramAction, SIGNAL(triggered()), this, SLOT(linkTelegramClicked()));
	connect(linkSlackAction, SIGNAL(triggered()), this, SLOT(linkSlackClicked()));
	connect(linkExplorer1Action, SIGNAL(triggered()), this, SLOT(linkExplorer1Clicked()));
	connect(linkExplorer2Action, SIGNAL(triggered()), this, SLOT(linkExplorer2Clicked()));
}


void BitcoinGUI::createMenuBar()
{
#ifdef Q_OS_MAC
	appMenuBar = new QMenuBar();
#else
	appMenuBar = menuBar();
#endif

	// Configure the menus
	QMenu *main = appMenuBar->addMenu(tr("&Main"));
	main->addAction(masternodeManagerAction);

	if (!fLiteMode)
	{
		main->addAction(messageAction);
	}

	main->addAction(blockAction);

	main->addSeparator();
	main->addAction(quitAction);

	QMenu *wallet = appMenuBar->addMenu(tr("&Wallet"));
	wallet->addAction(overviewAction);
	wallet->addAction(addressBookAction);
	wallet->addAction(receiveCoinsAction);
	wallet->addAction(sendCoinsAction);
	wallet->addAction(historyAction);
	wallet->addSeparator();
	wallet->addAction(signMessageAction);
	wallet->addAction(verifyMessageAction);
	wallet->addSeparator();
	wallet->addAction(encryptWalletAction);
	wallet->addAction(changePassphraseAction);
	wallet->addAction(unlockWalletAction);
	wallet->addAction(lockWalletAction);
	wallet->addSeparator();
	wallet->addAction(backupWalletAction);
	wallet->addAction(importPrivateKeyAction);
	wallet->addAction(exportAction);

	QMenu *staking = appMenuBar->addMenu(tr("&Staking"));
	staking->addAction(setstakingTRUEAction);
	staking->addAction(setstakingFALSEAction);

	QMenu *mining = appMenuBar->addMenu(tr("&Mining"));
	mining->addAction(setgenerateTRUEAction);
	mining->addAction(setgenerateFALSEAction);
	//mining->addAction(setgenproclimitAction);

	QMenu *tools = appMenuBar->addMenu(tr("&Tools"));
	tools->addAction(optionsAction);
	tools->addSeparator();
	tools->addAction(openInformationAction);
	tools->addAction(openRPCConsoleAction);
	tools->addAction(openNetTrafficAction);
	tools->addAction(openPeersAction);
	tools->addAction(showBackupsAction);
	tools->addSeparator();
	tools->addAction(openConfigFileAction);
	tools->addAction(openMasternodeConfigFileAction);
	tools->addAction(openDebugFileAction);

	QMenu *help = appMenuBar->addMenu(tr("&Help"));
	help->addAction(aboutAction);
	help->addAction(aboutQtAction);
	help->addSeparator();
	help->addAction(linkWebsiteAction);
    help->addAction(linkBitcointalkAction);
	help->addAction(linkTwitterAction);
	help->addAction(linkFacebookAction);
	help->addAction(linkDiscordAction);
	help->addAction(linkTelegramAction);
	help->addAction(linkSlackAction);
	help->addAction(linkExplorer1Action);
	help->addAction(linkExplorer2Action);
}


static QWidget* makeToolBarSpacer()
{
	QWidget* spacer = new QWidget();
	spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	spacer->setStyleSheet("QWidget { background: none; }");
	
	return spacer;
}


void BitcoinGUI::createToolBars()
{
	fLiteMode = GetBoolArg("-litemode", false);

	toolbar = new QToolBar(tr("Tabs toolbar"));
	
	toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
	
	toolbar->setContextMenuPolicy(Qt::PreventContextMenu);
	
	toolbar->setObjectName("tabs");
	
	toolbar->setStyleSheet("QToolButton"
							"{"
							"	background-color: #A4D300;"
							"	color: #000000;"
							"	font-size: 13px;"
							"	font-weight: 400;"
							"	padding:5px; font-family: 'Verdana';"
							"	border: none;"
							"}"

							"QToolButton:hover"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"	border: none;"
							"	padding-top: 5px;"
							"	padding-bottom: 5px;"
							"}"

							"QToolButton:checked"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"	border: none;"
							"	padding-top: 5px;"
							"	padding-bottom: 5px;"
							"}"
							
							"QToolButton:pressed"
							"{"
							"	color: #A4D300;"
							"	background-color: #000000;"
							"	border: none;"
							"	padding-top: 5px;"
							"	padding-bottom: 5px;"
							"}"
							
							"#tabs"
							"{"
							"	background-color: #A4D300;"
							"	color: #000000;"
							"	border: none;"
							"	padding-top: 0px;"
							"	padding-bottom: 0px;"
							"}"
						);

	//	QLabel* header = new QLabel();
	//	header->setMinimumSize(152, 152);
	//	header->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	//	header->setPixmap(QPixmap(":/images/header"));
	//	header->setScaledContents(false);
	//	header->setObjectName("header");
	//	header->setStyleSheet("#header { border: none; }");
	//	toolbar->addWidget(header);

	//QMenu *toolbarMenu = new QMenu();
	
	toolbar->addAction(overviewAction);
	toolbar->addAction(receiveCoinsAction);
	toolbar->addAction(sendCoinsAction);
	toolbar->addAction(historyAction);
	toolbar->addAction(addressBookAction);
	toolbar->addAction(masternodeManagerAction);

	if (!fLiteMode)
	{
		toolbar->addAction(messageAction);
	}

	toolbar->addAction(blockAction);
	
	//toolbar->addAction(TradingAction);
	
	netLabel = new QLabel();

	QWidget *spacer = makeToolBarSpacer();
	
	netLabel->setObjectName("netLabel");
	
	if (!fUseBlackTheme)
	{
		netLabel->setStyleSheet("#netLabel"
								"{"
								"	color: #000000;"
								"}"
							);
	}
	else
	{
		netLabel->setStyleSheet("#netLabel"
								"{"
								"	color: #A4D300;"
								"}"
							);
	}

	toolbar->addWidget(spacer);
	toolbar->setOrientation(Qt::Vertical);
	toolbar->setMovable(false);

	addToolBar(Qt::TopToolBarArea, toolbar);

	foreach(QAction *action, toolbar->actions())
	{
		toolbar->widgetForAction(action)->setFixedWidth(152);
	}
}


void BitcoinGUI::setClientModel(ClientModel *clientModel)
{
	if (!fOnlyTor)
	{
		netLabel->setText("CLEARNET");
	}
	else
	{
		if (!IsLimited(NET_TOR))
		{
			netLabel->setText("TOR");
		}
	}

	this->clientModel = clientModel;
	if (clientModel)
	{
		// Replace some strings and icons, when using the testnet
		if (clientModel->isTestNet())
		{
			setWindowTitle(windowTitle() + QString(" ") + tr("[testnet]"));
#ifndef Q_OS_MAC
			qApp->setWindowIcon(QIcon(":icons/bitcoin_testnet"));
			setWindowIcon(QIcon(":icons/bitcoin_testnet"));
#else
			MacDockIconHandler::instance()->setIcon(QIcon(":icons/bitcoin_testnet"));
#endif
			if (trayIcon)
			{
				trayIcon->setToolTip(tr("PHC client") + QString(" ") + tr("[testnet]"));
				trayIcon->setIcon(QIcon(":/icons/toolbar_testnet"));
				toggleHideAction->setIcon(QIcon(":/icons/toolbar_testnet"));
			}
		}

		// Keep up to date with client
		setNumConnections(clientModel->getNumConnections());
		connect(clientModel, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));

		setNumBlocks(clientModel->getNumBlocks());
		connect(clientModel, SIGNAL(numBlocksChanged(int)), this, SLOT(setNumBlocks(int)));

		// Receive and report messages from network/worker thread
		connect(clientModel, SIGNAL(message(QString, QString, bool, unsigned int)), this, SLOT(message(QString, QString, bool, unsigned int)));

		// Show progress dialog
		connect(clientModel, SIGNAL(showProgress(QString, int)), this, SLOT(showProgress(QString, int)));
		connect(walletModel, SIGNAL(showProgress(QString, int)), this, SLOT(showProgress(QString, int)));

		overviewPage->setClientModel(clientModel);
		rpcConsole->setClientModel(clientModel);
		addressBookPage->setOptionsModel(clientModel->getOptionsModel());
		receiveCoinsPage->setOptionsModel(clientModel->getOptionsModel());
	}
}


void BitcoinGUI::setWalletModel(WalletModel *walletModel)
{
	this->walletModel = walletModel;
	
	if (walletModel)
	{
		// Receive and report messages from wallet thread
		connect(walletModel, SIGNAL(message(QString, QString, bool, unsigned int)), this, SLOT(message(QString, QString, bool, unsigned int)));
		connect(sendCoinsPage, SIGNAL(message(QString, QString, bool, unsigned int)), this, SLOT(message(QString, QString, bool, unsigned int)));

		// Put transaction list in tabs
		transactionView->setModel(walletModel);
		overviewPage->setWalletModel(walletModel);
		addressBookPage->setModel(walletModel->getAddressTableModel());
		receiveCoinsPage->setModel(walletModel->getAddressTableModel());
		sendCoinsPage->setModel(walletModel);
		signVerifyMessageDialog->setModel(walletModel);
		blockBrowser->setModel(walletModel);
		//tradingDialogPage->setModel(walletModel);

		setEncryptionStatus(walletModel->getEncryptionStatus());
		connect(walletModel, SIGNAL(encryptionStatusChanged(int)), this, SLOT(setEncryptionStatus(int)));

		// Balloon pop-up for new transaction
		connect(walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex, int, int)), this, SLOT(incomingTransaction(QModelIndex, int, int)));

		// Ask for passphrase if needed
		connect(walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));
	}
}


void BitcoinGUI::setMessageModel(MessageModel *messageModel)
{
	this->messageModel = messageModel;

	if (messageModel)
	{
		// Report errors from message thread
		connect(messageModel, SIGNAL(error(QString, QString, bool)), this, SLOT(error(QString, QString, bool)));

		// Put transaction list in tabs
		messagePage->setModel(messageModel);

		// Balloon pop-up for new message
		connect(messageModel, SIGNAL(rowsInserted(QModelIndex, int, int)), this, SLOT(incomingMessage(QModelIndex, int, int)));
	}
}


void BitcoinGUI::createTrayIcon()
{
	QMenu *trayIconMenu;
#ifndef Q_OS_MAC
	trayIcon = new QSystemTrayIcon(this);
	trayIconMenu = new QMenu(this);
	trayIcon->setContextMenu(trayIconMenu);
	trayIcon->setToolTip(tr("PHC client"));
	trayIcon->setIcon(QIcon(":/icons/toolbar"));
	connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)), this, SLOT(trayIconActivated(QSystemTrayIcon::ActivationReason)));
	trayIcon->show();
#else
	// Note: On Mac, the dock icon is used to provide the tray's functionality.
	MacDockIconHandler *dockIconHandler = MacDockIconHandler::instance();
	dockIconHandler->setMainWindow((QMainWindow *)this);
	trayIconMenu = dockIconHandler->dockMenu();
#endif

	// Configuration of the tray icon (or dock icon) icon menu
	trayIconMenu->addAction(toggleHideAction);
	trayIconMenu->addSeparator();
	trayIconMenu->addAction(receiveCoinsAction);
	trayIconMenu->addAction(sendCoinsAction);
	trayIconMenu->addSeparator();
	trayIconMenu->addAction(signMessageAction);
	trayIconMenu->addAction(verifyMessageAction);
	trayIconMenu->addSeparator();
	trayIconMenu->addAction(optionsAction);
	trayIconMenu->addAction(openRPCConsoleAction);
	trayIconMenu->addAction(showBackupsAction);
#ifndef Q_OS_MAC // This is built-in on Mac
	trayIconMenu->addSeparator();
	trayIconMenu->addAction(quitAction);
#endif

	notificator = new Notificator(qApp->applicationName(), trayIcon);
}


#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
	if (reason == QSystemTrayIcon::Trigger)
	{
		// Click on system tray icon triggers show/hide of the main window
		toggleHideAction->trigger();
	}
}
#endif


void BitcoinGUI::optionsClicked()
{
	if (!clientModel || !clientModel->getOptionsModel())
	{
		return;
	}

	OptionsDialog dlg;
	dlg.setModel(clientModel->getOptionsModel());
	dlg.exec();
}


void BitcoinGUI::aboutClicked()
{
	AboutDialog dlg;
	dlg.setModel(clientModel);
	dlg.exec();
}


void BitcoinGUI::setNumConnections(int count)
{
	QString icon;

	switch (count)
	{
		case 0:
		{
			icon = fUseBlackTheme ? ":/icons/black/connect_0" : ":/icons/connect_0";
		} 
		break;
		
		case 1: case 2: case 3:
		{
 			icon = fUseBlackTheme ? ":/icons/black/connect_1" : ":/icons/connect_1";
		}
		break;
		
		case 4: case 5: case 6: 
		{
			icon = fUseBlackTheme ? ":/icons/black/connect_2" : ":/icons/connect_2";
		}
		break;
		
		case 7: case 8: case 9:
		{
			icon = fUseBlackTheme ? ":/icons/black/connect_3" : ":/icons/connect_3";
		}
		break;
		
		default:
		{
 			icon = fUseBlackTheme ? ":/icons/black/connect_4" : ":/icons/connect_4";
		}
		break;
	}

	labelConnectionsIcon->setPixmap(QIcon(icon).pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
	labelConnectionsIcon->setToolTip(tr("%n active connection(s) to PHC network", "", count));
}


void BitcoinGUI::setNumBlocks(int count)
{
	QString tooltip;

	QDateTime lastBlockDate = clientModel->getLastBlockDate();
	QDateTime currentDate = QDateTime::currentDateTime();
	
	int totalSecs = GetTime() - Params().GenesisBlock().GetBlockTime();
	int secs = lastBlockDate.secsTo(currentDate);

	tooltip = tr("Processed %1 blocks of transaction history.").arg(count);

	// Set icon state: spinning if catching up, tick otherwise
	if (secs < 90 * 60)
	{
		tooltip = tr("Up to date") + QString(".<br>") + tooltip;
		labelBlocksIcon->setPixmap(QIcon(fUseBlackTheme ? ":/icons/black/synced" : ":/icons/synced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));

		overviewPage->showOutOfSyncWarning(false);

		progressBarLabel->setVisible(false);
		progressBar->setVisible(false);
	}
	else
	{
		// Represent time from last generated block in human readable text
		QString timeBehindText;
		
		const int HOUR_IN_SECONDS = 60 * 60;
		const int DAY_IN_SECONDS = 24 * 60 * 60;
		const int WEEK_IN_SECONDS = 7 * 24 * 60 * 60;
		const int YEAR_IN_SECONDS = 31556952; // Average length of year in Gregorian calendar
		
		if (secs < 2 * DAY_IN_SECONDS)
		{
			timeBehindText = tr("%n hour(s)", "", secs / HOUR_IN_SECONDS);
		}
		else if (secs < 2 * WEEK_IN_SECONDS)
		{
			timeBehindText = tr("%n day(s)", "", secs / DAY_IN_SECONDS);
		}
		else if (secs < YEAR_IN_SECONDS)
		{
			timeBehindText = tr("%n week(s)", "", secs / WEEK_IN_SECONDS);
		}
		else
		{
			int years = secs / YEAR_IN_SECONDS;
			int remainder = secs % YEAR_IN_SECONDS;
			
			timeBehindText = tr("%1 and %2").arg(tr("%n year(s)", "", years)).arg(tr("%n week(s)", "", remainder / WEEK_IN_SECONDS));
		}

		progressBarLabel->setText(tr(clientModel->isImporting() ? "Importing blocks..." : "Synchronizing with network..."));
		progressBarLabel->setVisible(true);

		progressBar->setFormat(tr("%1 behind").arg(timeBehindText));
		progressBar->setMaximum(totalSecs);
		progressBar->setValue(totalSecs - secs);
		progressBar->setVisible(true);

		tooltip = tr("Catching up...") + QString("<br>") + tooltip;
		labelBlocksIcon->setPixmap(QIcon(fUseBlackTheme ? ":/icons/black/notsynced" : ":/icons/notsynced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));

		/*
		labelBlocksIcon->setMovie(syncIconMovie);

		if (count != prevBlocks)
		{
			syncIconMovie->jumpToNextFrame();
		}
		
		prevBlocks = count;
		*/

		overviewPage->showOutOfSyncWarning(true);

		tooltip += QString("<br>");
		tooltip += tr("Last received block was generated %1 ago.").arg(timeBehindText);
		tooltip += QString("<br>");
		tooltip += tr("Transactions after this will not yet be visible.");
	}

	// Don't word-wrap this (fixed-width) tooltip
	tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

	labelBlocksIcon->setToolTip(tooltip);
	progressBarLabel->setToolTip(tooltip);
	progressBar->setToolTip(tooltip);

	statusBar()->setVisible(true);
}


void BitcoinGUI::message(const QString &title, const QString &message, bool modal, unsigned int style)
{
	QString strTitle = tr("PHC") + " - ";

	// Default to information icon
	int nMBoxIcon = QMessageBox::Information;
	int nNotifyIcon = Notificator::Information;

	// Check for usage of predefined title
	switch (style)
	{
		case CClientUIInterface::MSG_ERROR:
		{
			strTitle += tr("Error");
		}
		break;
		
		case CClientUIInterface::MSG_WARNING:
		{
			strTitle += tr("Warning");
		}
		break;

		case CClientUIInterface::MSG_INFORMATION:
		{
			strTitle += tr("Information");
		}
		break;

		default:
		{
			strTitle += title; // Use supplied title
		}
	}

	// Check for error/warning icon
	if (style & CClientUIInterface::ICON_ERROR)
	{
		nMBoxIcon = QMessageBox::Critical;
		nNotifyIcon = Notificator::Critical;
	}
	else if (style & CClientUIInterface::ICON_WARNING)
	{
		nMBoxIcon = QMessageBox::Warning;
		nNotifyIcon = Notificator::Warning;
	}

	// Display message
	if (modal)
	{
		// Check for buttons, use OK as default, if none was supplied
		QMessageBox::StandardButton buttons;

		if (!(buttons = (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK)))
		{
			buttons = QMessageBox::Ok;
		}

		QMessageBox mBox((QMessageBox::Icon)nMBoxIcon, strTitle, message, buttons);
		mBox.exec();
	}
	else
	{
		notificator->notify((Notificator::Class)nNotifyIcon, strTitle, message);
	}

}


void BitcoinGUI::error(const QString &title, const QString &message, bool modal)
{
	// Report errors from network/worker thread
	if (modal)
	{
		QMessageBox::critical(this, title, message, QMessageBox::Ok, QMessageBox::Ok);
	}
	else
	{
		notificator->notify(Notificator::Critical, title, message);
	}
}


void BitcoinGUI::changeEvent(QEvent *e)
{
	QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
	if (e->type() == QEvent::WindowStateChange)
	{
		if (clientModel && clientModel->getOptionsModel()->getMinimizeToTray())
		{
			QWindowStateChangeEvent *wsevt = static_cast<QWindowStateChangeEvent*>(e);
			if (!(wsevt->oldState() & Qt::WindowMinimized) && isMinimized())
			{
				QTimer::singleShot(0, this, SLOT(hide()));
				e->ignore();
			}
		}
	}
#endif
}


void BitcoinGUI::closeEvent(QCloseEvent *event)
{
	if (clientModel)
	{
#ifndef Q_OS_MAC // Ignored on Mac
		if (!clientModel->getOptionsModel()->getMinimizeToTray() && !clientModel->getOptionsModel()->getMinimizeOnClose())
		{
			// close rpcConsole in case it was open to make some space for the shutdown window
			rpcConsole->close();

			qApp->quit();
		}
#endif
	}

	QMainWindow::closeEvent(event);
}


void BitcoinGUI::askFee(qint64 nFeeRequired, bool *payFee)
{
	if (!clientModel || !clientModel->getOptionsModel())
	{
		return;

	}

	QString strMessage = tr("This transaction is over the size limit. You can still send it for a fee of %1, "
		"which goes to the nodes that process your transaction and helps to support the network. "
		"Do you want to pay the fee?").arg(BitcoinUnits::formatWithUnit(clientModel->getOptionsModel()->getDisplayUnit(), nFeeRequired));

	QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm transaction fee"), strMessage, QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Yes);
	
	*payFee = (retval == QMessageBox::Yes);
}


void BitcoinGUI::incomingTransaction(const QModelIndex & parent, int start, int end)
{
	// Prevent balloon-spam when initial block download is in progress
	if (!walletModel || !clientModel || clientModel->inInitialBlockDownload() || walletModel->processingQueuedTransactions())
	{
		return;
	}

	TransactionTableModel *ttm = walletModel->getTransactionTableModel();

	qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
	
	QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
	QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
	QString address = ttm->index(start, TransactionTableModel::ToAddress, parent).data().toString();
	QIcon icon = qvariant_cast<QIcon>(ttm->index(start, TransactionTableModel::ToAddress, parent).data(Qt::DecorationRole));

	// On new transaction, make an info balloon
	notificator->notify(Notificator::Information, (amount)<0 ? tr("Sent transaction") :	tr("Incoming transaction"), tr("Date: %1\n" "Amount: %2\n" "Type: %3\n" "Address: %4\n")
		.arg(date) .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), amount, true)) .arg(type) .arg(address), icon);
}


void BitcoinGUI::incomingMessage(const QModelIndex & parent, int start, int end)
{
	if (!messageModel)
	{
		return;
	}

	MessageModel *mm = messageModel;

	if (mm->index(start, MessageModel::TypeInt, parent).data().toInt() == MessageTableEntry::Received)
	{
		QString sent_datetime = mm->index(start, MessageModel::ReceivedDateTime, parent).data().toString();
		QString from_address = mm->index(start, MessageModel::FromAddress, parent).data().toString();
		QString to_address = mm->index(start, MessageModel::ToAddress, parent).data().toString();
		QString message = mm->index(start, MessageModel::Message, parent).data().toString();
		
		QTextDocument html;
		
		html.setHtml(message);
		
		QString messageText(html.toPlainText());
		
		notificator->notify(Notificator::Information, tr("Incoming Message"), tr("Date: %1\n"	"From Address: %2\n" "To Address: %3\n" "Message: %4\n")
			.arg(sent_datetime) .arg(from_address) .arg(to_address) .arg(messageText));
	};
}


void BitcoinGUI::clearWidgets()
{
	centralStackedWidget->setCurrentWidget(centralStackedWidget->widget(0));

	for (int i = centralStackedWidget->count(); i>0; i--)
	{
		QWidget* widget = centralStackedWidget->widget(i);
		
		centralStackedWidget->removeWidget(widget);
		widget->deleteLater();
	}
}


void BitcoinGUI::gotoMasternodeManagerPage()
{
	masternodeManagerAction->setChecked(true);
	centralStackedWidget->setCurrentWidget(masternodeManagerPage);

	exportAction->setEnabled(false);
	disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}


void BitcoinGUI::gotoBlockBrowser()
{
	blockAction->setChecked(true);
	centralStackedWidget->setCurrentWidget(blockBrowser);

	exportAction->setEnabled(false);
	disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}


void BitcoinGUI::gotoOverviewPage()
{
	overviewAction->setChecked(true);
	centralStackedWidget->setCurrentWidget(overviewPage);

	exportAction->setEnabled(false);
	disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}


void BitcoinGUI::gotoHistoryPage()
{
	historyAction->setChecked(true);
	centralStackedWidget->setCurrentWidget(transactionsPage);

	exportAction->setEnabled(true);
	disconnect(exportAction, SIGNAL(triggered()), 0, 0);
	connect(exportAction, SIGNAL(triggered()), transactionView, SLOT(exportClicked()));
}


void BitcoinGUI::gotoAddressBookPage()
{
	addressBookAction->setChecked(true);
	centralStackedWidget->setCurrentWidget(addressBookPage);

	exportAction->setEnabled(true);
	disconnect(exportAction, SIGNAL(triggered()), 0, 0);
	connect(exportAction, SIGNAL(triggered()), addressBookPage, SLOT(exportClicked()));
}


//void BitcoinGUI::gotoTradingPage()
//{

	//TradingAction->setChecked(true);
	//centralStackedWidget->setCurrentWidget(tradingDialogPage);

	//  exportAction->setEnabled(false);
	//  disconnect(exportAction, SIGNAL(triggered()), 0, 0);
//}


void BitcoinGUI::gotoReceiveCoinsPage()
{
	receiveCoinsAction->setChecked(true);
	centralStackedWidget->setCurrentWidget(receiveCoinsPage);

	exportAction->setEnabled(true);
	disconnect(exportAction, SIGNAL(triggered()), 0, 0);
	connect(exportAction, SIGNAL(triggered()), receiveCoinsPage, SLOT(exportClicked()));
}


void BitcoinGUI::gotoSendCoinsPage()
{
	sendCoinsAction->setChecked(true);
	centralStackedWidget->setCurrentWidget(sendCoinsPage);

	exportAction->setEnabled(false);
	disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}


void BitcoinGUI::gotoSignMessageTab(QString addr)
{
	// call show() in showTab_SM()
	signVerifyMessageDialog->showTab_SM(true);

	if (!addr.isEmpty())
	{
		signVerifyMessageDialog->setAddress_SM(addr);
	}
}


void BitcoinGUI::gotoVerifyMessageTab(QString addr)
{
	// call show() in showTab_VM()
	signVerifyMessageDialog->showTab_VM(true);

	if (!addr.isEmpty())
	{
		signVerifyMessageDialog->setAddress_VM(addr);
	}
}


void BitcoinGUI::gotoMessagePage()
{
	messageAction->setChecked(true);
	centralStackedWidget->setCurrentWidget(messagePage);

	exportAction->setEnabled(true);
	disconnect(exportAction, SIGNAL(triggered()), 0, 0);
	connect(exportAction, SIGNAL(triggered()), messagePage, SLOT(exportClicked()));
}


void BitcoinGUI::dragEnterEvent(QDragEnterEvent *event)
{
	// Accept only URIs
	if (event->mimeData()->hasUrls())
	{
		event->acceptProposedAction();
	}
}


void BitcoinGUI::dropEvent(QDropEvent *event)
{
	if (event->mimeData()->hasUrls())
	{
		int nValidUrisFound = 0;
		
		QList<QUrl> uris = event->mimeData()->urls();
		
		foreach(const QUrl &uri, uris)
		{
			if (sendCoinsPage->handleURI(uri.toString()))
			{
				nValidUrisFound++;
			}
		}

		// if valid URIs were found
		if (nValidUrisFound)
		{
			gotoSendCoinsPage();
		}
		else
		{
			notificator->notify(Notificator::Warning, tr("URI handling"), tr("URI can not be parsed! This can be caused by an invalid PHC address or malformed URI parameters."));
		}
	}

	event->acceptProposedAction();
}


void BitcoinGUI::handleURI(QString strURI)
{
	// URI has to be valid
	if (sendCoinsPage->handleURI(strURI))
	{
		showNormalIfMinimized();
		gotoSendCoinsPage();
	}
	else
	{
		notificator->notify(Notificator::Warning, tr("URI handling"), tr("URI can not be parsed! This can be caused by an invalid PHC address or malformed URI parameters."));
	}
}


void BitcoinGUI::setEncryptionStatus(int status)
{
	if (fWalletUnlockStakingOnly)
	{
		labelEncryptionIcon->setPixmap(QIcon(fUseBlackTheme ? ":/icons/black/lock_open" : ":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
		labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked for staking only</b>"));
		changePassphraseAction->setEnabled(false);
		unlockWalletAction->setVisible(true);
		lockWalletAction->setVisible(true);
		encryptWalletAction->setEnabled(false);

	}
	else
	{

		switch (status)
		{
			case WalletModel::Unencrypted:
			{
				labelEncryptionIcon->setPixmap(QIcon(fUseBlackTheme ? ":/icons/black/lock_open" : ":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
				labelEncryptionIcon->setToolTip(tr("Wallet is <b>not encrypted</b>"));
				changePassphraseAction->setEnabled(false);
				unlockWalletAction->setVisible(false);
				lockWalletAction->setVisible(false);
				encryptWalletAction->setEnabled(true);
			}
			break;

			case WalletModel::Unlocked:
			{
				labelEncryptionIcon->setPixmap(QIcon(fUseBlackTheme ? ":/icons/black/lock_open" : ":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
				labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked</b>"));
				changePassphraseAction->setEnabled(true);
				unlockWalletAction->setVisible(false);
				lockWalletAction->setVisible(true);
				encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
			}
			break;

			case WalletModel::Locked:
			{
				labelEncryptionIcon->setPixmap(QIcon(fUseBlackTheme ? ":/icons/black/lock_closed" : ":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
				labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>locked</b>"));
				changePassphraseAction->setEnabled(true);
				unlockWalletAction->setVisible(true);
				lockWalletAction->setVisible(false);
				encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
			}
			break;
		}

	}
}


void BitcoinGUI::encryptWallet()
{
	if (!walletModel)
	{
		return;
	}

	AskPassphraseDialog dlg(AskPassphraseDialog::Encrypt, this);
	dlg.setModel(walletModel);
	dlg.exec();

	setEncryptionStatus(walletModel->getEncryptionStatus());
}


void BitcoinGUI::backupWallet()
{
	QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
	QString filename = QFileDialog::getSaveFileName(this, tr("Backup Wallet"), saveDir, tr("Wallet Data (*.dat)"));
	
	if (!filename.isEmpty())
	{
		if (!walletModel->backupWallet(filename))
		{
			QMessageBox::warning(this, tr("Backup Failed"), tr("There was an error trying to save the wallet data to the new location."));
		}
	}
}


void BitcoinGUI::importPrivateKey()
{
    ImportPrivateKeyDialog dlg(this);
    dlg.setModel(walletModel->getAddressTableModel());
    dlg.exec();
}


void BitcoinGUI::changePassphrase()
{
	AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
	dlg.setModel(walletModel);
	dlg.exec();
}


void BitcoinGUI::unlockWallet()
{
	if (!walletModel)
	{
		return;
	}

	// Unlock wallet when requested by wallet model
	if (walletModel->getEncryptionStatus() == WalletModel::Locked)
	{
		AskPassphraseDialog::Mode mode = sender() == unlockWalletAction ? AskPassphraseDialog::UnlockStaking : AskPassphraseDialog::Unlock;
		AskPassphraseDialog dlg(mode, this);
		dlg.setModel(walletModel);
		dlg.exec();
	}
}


void BitcoinGUI::lockWallet()
{
	if (!walletModel)
	{
		return;
	}

	walletModel->setWalletLocked(true);
}


void BitcoinGUI::showNormalIfMinimized(bool fToggleHidden)
{
	// activateWindow() (sometimes) helps with keyboard focus on Windows
	if (isHidden())
	{
		show();
		activateWindow();
	}
	else if (isMinimized())
	{
		showNormal();
		activateWindow();
	}
	else if (GUIUtil::isObscured(this))
	{
		raise();
		activateWindow();
	}
	else if (fToggleHidden)
	{
		hide();
	}
}


void BitcoinGUI::toggleHidden()
{
	showNormalIfMinimized(true);
}


void BitcoinGUI::updateWeight()
{
	if (!pwalletMain)
	{
		return;
	}

	TRY_LOCK(cs_main, lockMain);
	if (!lockMain)
	{
		return;
	}

	TRY_LOCK(pwalletMain->cs_wallet, lockWallet);
	if (!lockWallet)
	{
		return;
	}

	nWeight = pwalletMain->GetStakeWeight();
}


void BitcoinGUI::updateStakingIcon()
{
	updateWeight();

	uint64_t nWeight = this->nWeight;

	if (nLastCoinStakeSearchInterval && nWeight)
	{
		uint64_t nNetworkWeight = GetPoSKernelPS();
		
		unsigned nEstimateTime = 0;
		
		nEstimateTime = TARGET_SPACING * nNetworkWeight / nWeight;

		QString text;
		
		if (nEstimateTime < 60)
		{
			text = tr("%n second(s)", "", nEstimateTime);
		}
		else if (nEstimateTime < 60 * 60)
		{
			text = tr("%n minute(s)", "", nEstimateTime / 60);
		}
		else if (nEstimateTime < 24 * 60 * 60)
		{
			text = tr("%n hour(s)", "", nEstimateTime / (60 * 60));
		}
		else
		{
			text = tr("%n day(s)", "", nEstimateTime / (60 * 60 * 24));
		}

		nWeight /= COIN;
		nNetworkWeight /= COIN;

		labelStakingIcon->setPixmap(QIcon(fUseBlackTheme ? ":/icons/black/staking_on" : ":/icons/staking_on").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
		labelStakingIcon->setToolTip(tr("Staking.<br>Your weight is %1<br>Network weight is %2<br>Expected time to earn reward is %3").arg(nWeight).arg(nNetworkWeight).arg(text));
	}
	else
	{
		labelStakingIcon->setPixmap(QIcon(fUseBlackTheme ? ":/icons/black/staking_off" : ":/icons/staking_off").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
		
		if (pwalletMain && pwalletMain->IsLocked() == true)
		{
			labelStakingIcon->setToolTip(tr("Not staking because wallet is locked"));
		}
        else if (vNodes.empty() == true)
		{
			labelStakingIcon->setToolTip(tr("Not staking because wallet is offline"));
		}
		else if (vNodes.size() < 8)
		{
			labelStakingIcon->setToolTip(tr("Not staking because you need minimum 8 peers"));
		}
		else if (IsInitialBlockDownload() == true)
		{
			labelStakingIcon->setToolTip(tr("Not staking because wallet is syncing"));
		}
		else if (pindexBest->GetBlockTime() < GetTime() - 10 * 60)
		{
			labelStakingIcon->setToolTip(tr("Not staking, waiting for full syncronization"));
		}
		else if (!nWeight)
		{
			labelStakingIcon->setToolTip(tr("Not staking because you don't have mature coins"));
		}
        else if (nLastCoinStakeSearchInterval == 0 && GetBoolArg("-staking", true) == true && pwalletMain->GetStake() > 0)
		{
			labelStakingIcon->setToolTip(tr("Not staking, waiting to unlock coins..."));
		}
        else if (GetBoolArg("-staking", true) == true && nLastCoinStakeSearchInterval == 0)
		{
			labelStakingIcon->setToolTip(tr("Not staking, waiting to sign a block."));
		}
		else if (GetBoolArg("-staking", true) == true)
		{
			labelStakingIcon->setToolTip(tr("Not staking, unknown error."));
		}
		else
		{
			labelStakingIcon->setToolTip(tr("Staking disabled."));
		}
	}
}


void BitcoinGUI::detectShutdown()
{
	if (ShutdownRequested())
	{
		QMetaObject::invokeMethod(QCoreApplication::instance(), "quit", Qt::QueuedConnection);
	}
}


void BitcoinGUI::showProgress(const QString &title, int nProgress)
{
	if (nProgress == 0)
	{
		progressDialog = new QProgressDialog(title, "", 0, 100);
		progressDialog->setWindowModality(Qt::ApplicationModal);
		progressDialog->setMinimumDuration(0);
		progressDialog->setCancelButton(0);
		progressDialog->setAutoClose(false);
		progressDialog->setValue(0);
	}
	else if (nProgress == 100)
	{
		if (progressDialog)
		{
			progressDialog->close();
			progressDialog->deleteLater();
		}
	}
	else if (progressDialog)
	{
		progressDialog->setValue(nProgress);
	}
}


void BitcoinGUI::linkWebsiteClicked()
{
	QDesktopServices::openUrl(QUrl("https://profithunterscoin.com", QUrl::TolerantMode));
}


void BitcoinGUI::linkBitcointalkClicked()
{
    QDesktopServices::openUrl(QUrl("https://bitcointalk.org/index.php?topic=2786295.0", QUrl::TolerantMode));
}


void BitcoinGUI::linkTwitterClicked()
{
    QDesktopServices::openUrl(QUrl("https://twitter.com/phcadmin", QUrl::TolerantMode));
}


void BitcoinGUI::linkFacebookClicked()
{
    QDesktopServices::openUrl(QUrl("https://www.facebook.com/ProfitHuntersCoin/", QUrl::TolerantMode));
}


void BitcoinGUI::linkDiscordClicked()
{
    QDesktopServices::openUrl(QUrl("https://discordapp.com/invite/Abwhbw2", QUrl::TolerantMode));
}


void BitcoinGUI::linkTelegramClicked()
{
    QDesktopServices::openUrl(QUrl("https://t.me/profithunterscoin", QUrl::TolerantMode));
}


void BitcoinGUI::linkSlackClicked()
{
    QDesktopServices::openUrl(QUrl("https://profithunterscoin.slack.com/join/shared_invite/enQ%20tMjk1NTU0NjI4NjMxLWE5NmM1MWYyN2Y4NTY4ZjE0ZTgxYzJiNGYyNDYwODh%20iNGQwODQ1OTFkYTY4OTZkODFjN2Y0NDA4MWEwY2FiNWU"));
}


void BitcoinGUI::linkExplorer1Clicked()
{
    QDesktopServices::openUrl(QUrl("http://explorer.profithunterscoin.com", QUrl::TolerantMode));
}


void BitcoinGUI::linkExplorer2Clicked()
{
    QDesktopServices::openUrl(QUrl("http://explorer2.profithunterscoin.com", QUrl::TolerantMode));
}
