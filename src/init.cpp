// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#include "init.h"
#include "addrman.h"
#include "main.h"
#include "chainparams.h"
#include "txdb.h"
#include "rpcserver.h"
#include "net.h"
#include "key.h"
#include "pubkey.h"
#include "util.h"
#include "ui_interface.h"
#include "checkpoints.h"
#include "darksend-relay.h"
#include "activemasternode.h"
#include "masternode-payments.h"
#include "masternode.h"
#include "masternodeman.h"
#include "masternodeconfig.h"
#include "spork.h"
#include "smessage.h"
#include "miner.h"

#ifdef ENABLE_WALLET
#include "db.h"
#include "wallet.h"
#include "walletdb.h"
#endif

#define BOOST_NO_CXX11_SCOPED_ENUMS

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/thread.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <openssl/crypto.h>

#ifndef WIN32
#include <signal.h>
#endif

using namespace std;
using namespace boost;

#ifdef ENABLE_WALLET

CWallet* pwalletMain = NULL;

int nWalletBackups = 10;

#endif

CClientUIInterface uiInterface;

bool fConfChange;

unsigned int nNodeLifespan;
unsigned int nDerivationMethodIndex;
unsigned int nMinerSleep;

bool fUseFastIndex;
bool fOnlyTor = false;

extern bool fDebug;
extern bool fDebugSmsg;
extern bool fNoSmsg;
extern bool fPrintToConsole;
extern bool fPrintToDebugLog;
extern vector<string> DebugCategories; 

// Turbosync (C) 2019 - Profit Hunters Coin
int64_t TURBOSYNC_MAX;


//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when StartShutdown() or the SIGTERM
// signal handler sets fRequestShutdown, which triggers
// the DetectShutdownThread(), which interrupts the main thread group.
// DetectShutdownThread() then exits, which causes AppInit() to
// continue (it .joins the shutdown thread).
// Shutdown() is then
// called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Note that if running -daemon the parent process returns from AppInit2
// before adding any threads to the threadGroup, so .join_all() returns
// immediately and the parent exits from main().
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// fRequestShutdown getting set, and then does the normal Qt
// shutdown thing.
//

volatile bool fRequestShutdown = false;

void StartShutdown()
{
    fRequestShutdown = true;
}
bool ShutdownRequested()
{
    return fRequestShutdown;
}

static boost::scoped_ptr<ECCVerifyHandle> globalVerifyHandle;

void Shutdown()
{
    // Needed when we shutdown the wallet
	fRequestShutdown = true;
    
    if (fDebug)
    {
        LogPrint("init", "%s : WARNING - Shutdown In progress... \n", __FUNCTION__);
    }

    static CCriticalSection cs_Shutdown;
    
    TRY_LOCK(cs_Shutdown, lockShutdown);

    if (!lockShutdown)
    {
        return;
    }

    RenameThread("PHC-shutoff");
    
    mempool.AddTransactionsUpdated(1);
    
    StopRPCThreads();
    
    SecureMsgShutdown();

#ifdef ENABLE_WALLET
    
    ShutdownRPCMining();

    if (pwalletMain)
    {
        bitdb.Flush(false);
    }

    GeneratePoWcoins(false, NULL);

#endif

    StopNode();

    UnregisterNodeSignals(GetNodeSignals());

    DumpMasternodes();
    {
        LOCK(cs_main);

#ifdef ENABLE_WALLET
        if (pwalletMain)
        {
            pwalletMain->SetBestChain(CBlockLocator(pindexBest));
        }

#endif
    }

#ifdef ENABLE_WALLET
    if (pwalletMain)
    {
        bitdb.Flush(true);
    }

#endif

    boost::filesystem::remove(GetPidFile());

    UnregisterAllWallets();

#ifdef ENABLE_WALLET
    delete pwalletMain;

    pwalletMain = NULL;
#endif

    globalVerifyHandle.reset();

    ECC_Stop();

    if (fDebug)
    {
        LogPrint("init", "%s : OK - Shutdown done \n", __FUNCTION__);
    }
}

//
// Signal handlers are very limited in what they are allowed to do, so:
//
void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}

bool static InitError(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_ERROR);

    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_WARNING);

    return true;
}

bool static Bind(const CService &addr, bool fError = true)
{
    if (IsLimited(addr))
    {
        return false;
    }

    std::string strError;

    if (!BindListenPort(addr, strError))
    {
        if (fError)
        {
            return InitError(strError);
        }

        return false;
    }

    return true;
}

// Core-specific options shared between UI and daemon
std::string HelpMessage()
{
    string strUsage = _("Options:") + "\n";
    strUsage += "  -?                     " + _("This help message") + "\n";
    strUsage += "  -conf=<file>           " + _("Specify configuration file (default: phc.conf)") + "\n";
    strUsage += "  -gen                   " + _("Generate coins (default: 0)") + "\n" +
    strUsage += "  -pid=<file>            " + _("Specify pid file (default: phcd.pid)") + "\n";
    strUsage += "  -datadir=<dir>         " + _("Specify data directory") + "\n";
    strUsage += "  -wallet=<dir>          " + _("Specify wallet file (within data directory)") + "\n";
    strUsage += "  -dbcache=<n>           " + _("Set database cache size in megabytes (default: 10)") + "\n";
    strUsage += "  -dbwalletcache=<n>     " + _("Set wallet database cache size in megabytes (default: 1)") + "\n";
    strUsage += "  -dblogsize=<n>         " + _("Set database disk log size in megabytes (default: 100)") + "\n";
    strUsage += "  -timeout=<n>           " + _("Specify connection timeout in milliseconds (default: 5000)") + "\n";
    strUsage += "  -proxy=<ip:port>       " + _("Connect through SOCKS5 proxy") + "\n";
    strUsage += "  -tor=<ip:port>         " + _("Use proxy to reach tor hidden services (default: same as -proxy)") + "\n";
    strUsage += "  -dns                   " + _("Allow DNS lookups for -addnode, -seednode and -connect") + "\n";
    strUsage += "  -port=<port>           " + _("Listen for connections on <port> (default: 30140)") + "\n";
    strUsage += "  -maxconnections=<n>    " + _("Maintain at most <n> connections to peers (default: 125)") + "\n";
    strUsage += "  -addnode=<ip>          " + _("Add a node to connect to and attempt to keep the connection open") + "\n";
    strUsage += "  -connect=<ip>          " + _("Connect only to the specified node(s)") + "\n";
    strUsage += "  -seednode=<ip>         " + _("Connect to a node to retrieve peer addresses, and disconnect") + "\n";
    strUsage += "  -externalip=<ip>       " + _("Specify your own public address") + "\n";
    strUsage += "  -onlynet=<net>         " + _("Only connect to nodes in network <net> (IPv4, IPv6 or Tor)") + "\n";
    strUsage += "  -discover              " + _("Discover own IP address (default: 1 when listening and no -externalip)") + "\n";
    strUsage += "  -listen                " + _("Accept connections from outside (default: 1 if no -proxy or -connect)") + "\n";
    strUsage += "  -bind=<addr>           " + _("Bind to given address. Use [host]:port notation for IPv6") + "\n";
    strUsage += "  -dnsseed               " + _("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect)") + "\n";
    strUsage += "  -forcednsseed          " + _("Always query for peer addresses via DNS lookup (default: 0)") + "\n";
    strUsage += "  -synctime              " + _("Sync time with other nodes. Disable if time on your system is precise e.g. syncing with NTP (default: 1)") + "\n";
    strUsage += "  -banscore=<n>          " + _("Threshold for disconnecting misbehaving peers (default: 100)") + "\n";
    strUsage += "  -bantime=<n>           " + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)") + "\n";
    strUsage += "  -maxreceivebuffer=<n>  " + _("Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)") + "\n";
    strUsage += "  -maxsendbuffer=<n>     " + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)") + "\n";
#ifdef USE_UPNP
#if USE_UPNP
    strUsage += "  -upnp                  " + _("Use UPnP to map the listening port (default: 1 when listening)") + "\n";
#else
    strUsage += "  -upnp                  " + _("Use UPnP to map the listening port (default: 0)") + "\n";
#endif
#endif
    strUsage += "  -paytxfee=<amt>        " + _("Fee per KB to add to transactions you send") + "\n";
    strUsage += "  -mininput=<amt>        " + _("When creating transactions, ignore inputs with value less than this (default: 0.01)") + "\n";

    if (fHaveGUI)
    {
        strUsage += "  -server                " + _("Accept command line and JSON-RPC commands") + "\n";
    }

#if !defined(WIN32)
    if (fHaveGUI)
    {
        strUsage += "  -daemon                " + _("Run in the background as a daemon and accept commands") + "\n";
    }

#endif
    strUsage += "  -testnet               " + _("Use the test network") + "\n";
    strUsage += "  -lowbandwidth          " + _("Use low bandwidth sync mode") + "\n";
    strUsage += "  -hypersync             " + _("Use very high bandwidth sync mode") + "\n";
    strUsage += "  -orphansync            " + _("Use orphan chain sync mode") + "\n";

    strUsage += "  -nodebug                 " + _("Turn off debugging messages, same as -debug=0") + "\n";
    strUsage += "  -logtimestamps         " + _("Prepend debug output with timestamp") + "\n";
    strUsage += "  -shrinkdebugfile       " + _("Shrink debug.log file on client startup (default: 1 when no -debug)") + "\n";
    strUsage += "  -debugrpc              " + _("Debug to console from RPC Request Data") + "\n";
    strUsage += "  -debuglog              " + _("Debug to debug.log") + "\n";
    strUsage += "  -debugconsole          " + _("Debug to console") + "\n";
    strUsage += "  -debug=<category>      " + _("Output debugging information (default: 0, supplying <category> is optional)") + "\n";
    strUsage +=                               _("If <category> is not supplied, output all debugging information.") + "\n";
    strUsage +=                               _("<category> can be: alert, core, init, db, wallet, masternode, instantx, firewall,") + "\n";
    strUsage +=                               _("stealth, protocol, net, darksend, mempool, uint, stakemodifier, kernel, util, rpc,") + "\n";
    strUsage +=                               _("addrman, daemon, sync, socks, smessage, mining, coinage, spork, leveldb, key, base58, script, wallet") + "\n";

    if (fHaveGUI)
    {
        strUsage += ", gui , qt.\n";
    }
    else
    {
        strUsage += ".\n";
    }

    strUsage += "  -regtest               " + _("Enter regression test mode, which uses a special chain in which blocks can be "
                                                "solved instantly. This is intended for regression testing tools and app development.") + "\n";
    strUsage += "  -rpcuser=<user>        " + _("Username for JSON-RPC connections") + "\n";
    strUsage += "  -rpcpassword=<pw>      " + _("Password for JSON-RPC connections") + "\n";
    strUsage += "  -rpcport=<port>        " + _("Listen for JSON-RPC connections on <port> (default: 17171)") + "\n";
    strUsage += "  -rpcallowip=<ip>       " + _("Allow JSON-RPC connections from specified IP address") + "\n";

    if (!fHaveGUI)
    {
        strUsage += "  -rpcconnect=<ip>       " + _("Send commands to node running on <ip> (default: 127.0.0.1)") + "\n";
        strUsage += "  -rpcwait               " + _("Wait for RPC server to start") + "\n";
    }

    strUsage += "  -rpcthreads=<n>        " + _("Set the number of threads to service RPC calls (default: 4)") + "\n";
    strUsage += "  -blocknotify=<cmd>     " + _("Execute command when the best block changes (%s in cmd is replaced by block hash)") + "\n";
    strUsage += "  -walletnotify=<cmd>    " + _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)") + "\n";
    strUsage += "  -confchange            " + _("Require a confirmations for change (default: 0)") + "\n";
    strUsage += "  -alertnotify=<cmd>     " + _("Execute command when a relevant alert is received (%s in cmd is replaced by message)") + "\n";
    strUsage += "  -upgradewallet         " + _("Upgrade wallet to latest format") + "\n";
    strUsage += "  -createwalletbackups=<n> " + _("Number of automatic wallet backups (default: 10)") + "\n";
    strUsage += "  -keypool=<n>           " + _("Set key pool size to <n> (default: 100) (litemode: 10)") + "\n";
    strUsage += "  -rescan                " + _("Rescan the block chain for missing wallet transactions") + "\n";
    strUsage += "  -salvagewallet         " + _("Attempt to recover private keys from a corrupt wallet.dat") + "\n";
    strUsage += "  -checkblocks=<n>       " + _("How many blocks to check at startup (default: 500, 0 = all)") + "\n";
    strUsage += "  -checklevel=<n>        " + _("How thorough the block verification is (0-6, default: 1)") + "\n";
    strUsage += "  -loadblock=<file>      " + _("Imports blocks from external blk000?.dat file") + "\n";
    strUsage += "  -reindex               " + _("Reindex addresses found in blockchain database") + "\n";
    strUsage += "  -rebuild               " + _("Rebuilds local Blockchain Database") + "\n";
    strUsage += "  -clearchainfiles       " + _("Removes local Blockchain Database files") + "\n";
    strUsage += "  -autoprune=<n>         " + _("Autoprune when orphan found X amount of blocks (default: 0") + "\n";
    strUsage += "  -rollbackchain=<n>     " + _("Rollbackchain local database X amount of blocks (default: 100") + "\n";
    strUsage += "  -backtoblock=<n>       " + _("Rollbacktoblock local database to block height (default: 100000)") + "\n";
    strUsage += "  -maxorphanblocks=<n>   " + strprintf(_("Keep at most <n> unconnectable blocks in memory (default: %u)"), DEFAULT_MAX_ORPHAN_BLOCKS) + "\n";

    strUsage += "\n" + _("Block creation options:") + "\n";
    strUsage += "  -blockminsize=<n>      "   + _("Set minimum block size in bytes (default: 0)") + "\n";
    strUsage += "  -blockmaxsize=<n>      "   + _("Set maximum block size in bytes (default: 250000)") + "\n";
    strUsage += "  -blockprioritysize=<n> "   + _("Set maximum size of high-priority/low-fee transactions in bytes (default: 27000)") + "\n";

    strUsage += "\n" + _("SSL options: (see the Bitcoin Wiki for SSL setup instructions)") + "\n";
    strUsage += "  -rpcssl                                  " + _("Use OpenSSL (https) for JSON-RPC connections") + "\n";
    strUsage += "  -rpcsslcertificatechainfile=<file.cert>  " + _("Server certificate file (default: server.cert)") + "\n";
    strUsage += "  -rpcsslprivatekeyfile=<file.pem>         " + _("Server private key (default: server.pem)") + "\n";
    strUsage += "  -rpcsslciphers=<ciphers>                 " + _("Acceptable ciphers (default: TLSv1.2+HIGH:TLSv1+HIGH:!SSLv3:!SSLv2:!aNULL:!eNULL:!3DES:@STRENGTH)") + "\n";
    strUsage += "  -litemode=<n>          " + _("Disable all Darksend and Stealth Messaging related functionality (0-1, default: 0)") + "\n";
    strUsage += "\n" + _("Masternode options:") + "\n";
    strUsage += "  -masternode=<n>            " + _("Enable the client to act as a masternode (0-1, default: 0)") + "\n";
    strUsage += "  -mnconf=<file>             " + _("Specify masternode configuration file (default: masternode.conf)") + "\n";
    strUsage += "  -mnconflock=<n>            " + _("Lock masternodes from masternode configuration file (default: 1)") + "\n";
    strUsage += "  -masternodeprivkey=<n>     " + _("Set the masternode private key") + "\n";
    strUsage += "  -masternodeaddr=<n>        " + _("Set external address:port to get to this masternode (example: address:port)") + "\n";
    strUsage += "  -masternodeminprotocol=<n> " + _("Ignore masternodes less than version (example: 61401; default : 0)") + "\n";

    strUsage += "\n" + _("Darksend options:") + "\n";
    strUsage += "  -enabledarksend=<n>          " + _("Enable use of automated darksend for funds stored in this wallet (0-1, default: 0)") + "\n";
    strUsage += "  -darksendrounds=<n>          " + _("Use N separate masternodes to anonymize funds  (2-8, default: 2)") + "\n";
    strUsage += "  -AnonymizeAmount=<n> " + _("Keep N PHC anonymized (default: 0)") + "\n";
    strUsage += "  -liquidityprovider=<n>       " + _("Provide liquidity to Darksend by infrequently mixing coins on a continual basis (0-100, default: 0, 1=very frequent, high fees, 100=very infrequent, low fees)") + "\n";

    strUsage += "\n" + _("InstantX options:") + "\n";
    strUsage += "  -enableinstantx=<n>    " + _("Enable instantx, show confirmations for locked transactions (bool, default: true)") + "\n";
    strUsage += "  -instantxdepth=<n>     " + strprintf(_("Show N confirmations for a successfully locked transaction (0-9999, default: %u)"), nInstantXDepth) + "\n"; 
    strUsage += _("Secure messaging options:") + "\n" +
        "  -nosmsg                                  " + _("Disable secure messaging.") + "\n" +
        "  -debugsmsg                               " + _("Log extra debug messages.") + "\n" +
        "  -smsgscanchain                           " + _("Scan the block chain for public key addresses on startup.") + "\n" +
    strUsage += "  -stakethreshold=<n> " + _("This will set the output size of your stakes to never be below this number (default: 100)") + "\n";

    strUsage += "\n" + _("Network Options:") + "\n";
    strUsage += "  -turbosyncmax=<n> " + _("Maximum level 0-5 (default: 5)") + "\n" +
    "           0 = disabled (10000 Max Inv) (1000 Max Addr) (500 Max Blocks) \n" +
    "           1 = enabled (20000 Max Inv) (2000 Max Addr) (1000 Max Blocks) \n" +
    "           2 = enabled (40000 Max Inv) (4000 Max Addr) (2000 Max Blocks) \n" +
    "           3 = enabled (80000 Max Inv) (8000 Max Addr) (4000 Max Blocks) \n" +
    "           4 = enabled (160000 Max Inv) (16000 Max Addr) (8000 Max Blocks) \n" +
    "           5 = enabled (320000 Max Inv) (32000 Max Addr) (16000 Max Blocks) \n";

    return strUsage;
}

/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void)
{
    if(!ECC_InitSanityCheck())
    {
        InitError("OpenSSL appears to lack support for elliptic curve cryptography. For more "
                  "information, visit https://en.bitcoin.it/wiki/OpenSSL_and_EC_Libraries");

        return false;
    }

    // TODO: remaining sanity checks, see #4081

    return true;
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInit2(boost::thread_group& threadGroup)
{
    // Turbosync (C) 2019 - Profit Hunters Coin
    // 0 = disabled (10000 Max Inv) (1000 Max Addr) (500 Max Blocks)
    // 1 = enabled (20000 Max Inv) (2000 Max Addr) (1000 Max Blocks)
    // 2 = enabled (40000 Max Inv) (4000 Max Addr) (2000 Max Blocks)
    // 3 = enabled (80000 Max Inv) (8000 Max Addr) (4000 Max Blocks)
    // 4 = enabled (160000 Max Inv) (16000 Max Addr) (8000 Max Blocks)
    // 5 = enabled (320000 Max Inv) (32000 Max Addr) (16000 Max Blocks)
    TURBOSYNC_MAX = GetArg("-turbosyncmax", 5);

    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
    // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
    // which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    
    if (setProcDEPPol != NULL)
    {
        setProcDEPPol(PROCESS_DEP_ENABLE);
    }
#endif
#ifndef WIN32
    umask(077);

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;

    sigemptyset(&sa.sa_mask);

    sa.sa_flags = 0;

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;

    sa_hup.sa_handler = HandleSIGHUP;

    sigemptyset(&sa_hup.sa_mask);

    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);
#endif

    // ********************************************************* Step 2: parameter interactions

    fLogTimestamps = GetBoolArg("-logtimestamps", true);

    fDebug = false;
    DebugCategories = mapMultiArgs["-debug"];

    // Special-case: if -debug=1/ is set, turn on debugging messages
    if (GetBoolArg("-debug", false) == true)
    {
        fDebug = true;
    }

    if(fDebug)
    {
	    fDebugSmsg = true;
    }
    else
    {
        fDebugSmsg = GetBoolArg("-debugsmsg", false);
    }

    if (fLiteMode)
    {
        fNoSmsg = true;
    }
    else
    {
        fNoSmsg = GetBoolArg("-nosmsg", false);
    }

    if (GetBoolArg("-debuglog", false) == true)
    {
        // Debug.log
        fDebug = true;
        fPrintToDebugLog = true;
        fPrintToConsole = false;

        DebugCategories = mapMultiArgs["-debuglog"];

        InitWarning(_("WARNING - Debugging to debug.log"));
    }
    
    if (GetBoolArg("-debugconsole", false) == true)
    {
        // Console
        fDebug = true;
        fPrintToDebugLog = false;
        fPrintToConsole = true;

        DebugCategories = mapMultiArgs["-debugconsole"];

        InitWarning(_("WARNING - Debugging to console"));
    }

    // Check for -debugnet (deprecated)
    if (GetBoolArg("-debugnet", false))
    {
        InitWarning(_("Warning: Deprecated argument -debugnet ignored, use -debug=net"));
    }

    nNodeLifespan = GetArg("-addrlifespan", 7);
    fUseFastIndex = GetBoolArg("-fastindex", true);
    nMinerSleep = GetArg("-minersleep", 1000);

    nDerivationMethodIndex = 0;

    if (mapArgs.count("-bind"))
    {
        // when specifying an explicit binding address, you want to listen on it
        // even when -connect or -proxy is specified
        if (SoftSetBoolArg("-listen", true))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 parameter interaction: -bind set -> setting -listen=1 \n", __FUNCTION__);
            }
        }
    }

    // Process masternode config
    masternodeConfig.read(GetMasternodeConfigFile());

    if (mapArgs.count("-connect")
        && mapMultiArgs["-connect"].size() > 0)
    {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (SoftSetBoolArg("-dnsseed", false))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -connect set -> setting -dnsseed=0 \n", __FUNCTION__);
            }
        }

        if (SoftSetBoolArg("-listen", false))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -connect set -> setting -listen=0 \n", __FUNCTION__);
            }
        }
    }

    if (mapArgs.count("-proxy"))
    {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (SoftSetBoolArg("-listen", false))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -proxy set -> setting -listen=0 \n", __FUNCTION__);
            }
        }

        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (SoftSetBoolArg("-upnp", false))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -proxy set -> setting -upnp=0 \n", __FUNCTION__);
            }
        }

        // to protect privacy, do not discover addresses by default
        if (SoftSetBoolArg("-discover", false))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -proxy set -> setting -discover=0 \n", __FUNCTION__);
            }
        }
    }

    if (!GetBoolArg("-listen", true))
    {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (SoftSetBoolArg("-upnp", false))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -listen=0 -> setting -upnp=0 \n", __FUNCTION__);
            }
        }

        if (SoftSetBoolArg("-discover", false))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -listen=0 -> setting -discover=0 \n", __FUNCTION__);
            }
        }
    }

    if (mapArgs.count("-externalip"))
    {
        // if an explicit public IP is specified, do not try to find others
        if (SoftSetBoolArg("-discover", false))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -externalip set -> setting -discover=0 \n", __FUNCTION__);
            }
        }
    }

    if (GetBoolArg("-salvagewallet", false))
    {
        // Rewrite just private keys: rescan to find transactions
        if (SoftSetBoolArg("-rescan", true))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - AppInit2 Parameter interaction: -salvagewallet=1 -> setting -rescan=1 \n", __FUNCTION__);
            }
        }
    }

    // ********************************************************* Step 3: parameter-to-internal-flags



    // Check for -socks - as this is a privacy risk to continue, exit here
    if (mapArgs.count("-socks"))
    {
        return InitError(_("ERROR - Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."));
    }

    if (fDaemon)
    {
        fServer = true;
    }
    else
    {
    	fServer = GetBoolArg("-server", false);
    }

    if (!fHaveGUI)
    {
       fServer = true;
    }

#ifdef ENABLE_WALLET
    bool fDisableWallet = GetBoolArg("-disablewallet", false);
#endif

    if (mapArgs.count("-timeout"))
    {
        int nNewTimeout = GetArg("-timeout", 5000);

        if (nNewTimeout > 0
            && nNewTimeout < 600000)
        {
            nConnectTimeout = nNewTimeout;
        }
    }

#ifdef ENABLE_WALLET
    if (mapArgs.count("-paytxfee"))
    {
        if (!ParseMoney(mapArgs["-paytxfee"], nTransactionFee))
        {
            return InitError(strprintf(_("ERROR - Invalid amount for -paytxfee=<amount>: '%s'"), mapArgs["-paytxfee"]));
        }

        if (nTransactionFee > 0.25 * COIN)
        {
            InitWarning(_("WARNING - Paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
        }
    }
#endif

    fConfChange = GetBoolArg("-confchange", false);

#ifdef ENABLE_WALLET
    if (mapArgs.count("-mininput"))
    {
        if (!ParseMoney(mapArgs["-mininput"], nMinimumInputValue))
        {
            return InitError(strprintf(_("ERROR - Invalid amount for -mininput=<amount>: '%s'"), mapArgs["-mininput"]));
        }
    }
#endif

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    // AppData Directory doesn't exist, create it.
    if (!boost::filesystem::is_directory(GetDataDir(true)))
    {
        fprintf(stderr, "ERROR - Specified directory does not exist. Creating directory now... Please wait. \n");

        if (boost::filesystem::create_directory(GetDataDir(true)))
        {
            fprintf(stderr, "ERROR - Created directory (wallet shutting down, restart using: phcd) \n");

            MilliSleep(10000);

            Shutdown();
        }
        else
        {            fprintf(stderr, "ERROR - Created directory failed.\n");
        }
    }

    // Initialize elliptic curve code
    ECC_Start();

    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    if (!InitSanityCheck())
    {
        return InitError(_("ERROR - Initialization sanity check failed. PHC is shutting down."));
    }

    std::string strDataDir = GetDataDir(true).string();
#ifdef ENABLE_WALLET

    std::string strWalletFileName = GetArg("-wallet", "wallet.dat");

    // strWalletFileName must be a plain filename without a directory
    if (strWalletFileName != boost::filesystem::basename(strWalletFileName) + boost::filesystem::extension(strWalletFileName))
    {
        return InitError(strprintf(_("ERROR - Wallet %s resides outside data directory %s."), strWalletFileName, strDataDir));
    }

#endif
    // Make sure only a single Bitcoin process is using the data directory.
    boost::filesystem::path pathLockFile = GetDataDir(true) / ".lock";

    // empty lock file; created if it doesn't exist.
    FILE* file = fopen(pathLockFile.string().c_str(), "a");

    if (file)
    {
        fclose(file);
    }

    static boost::interprocess::file_lock lock(pathLockFile.string().c_str());

    if (!lock.try_lock())
    {
        return InitError(strprintf(_("ERROR - Cannot obtain a lock on data directory %s. PHC is probably already running."), strDataDir));
    }

    if (GetBoolArg("-shrinkdebugfile", !fDebug))
    {
        ShrinkDebugFile();
    }

    if (fDebug)
    {

        LogPrint("init", "%s : NOTICE - PHC version %s (%s) \n", __FUNCTION__, FormatFullVersion(), CLIENT_DATE);
        LogPrint("init", "%s : NOTICE - Using OpenSSL version %s \n", __FUNCTION__, SSLeay_version(SSLEAY_VERSION));
    }

    if (!fLogTimestamps)
    {
        if (fDebug)
        {
            LogPrint("init", "%s : NOTICE - Startup time: %s \n", __FUNCTION__, DateTimeStrFormat("%x %H:%M:%S", GetTime()));
        }
    }

    if (fDebug)
    {
        LogPrint("init", "%s : NOTICE - Default data directory %s \n", __FUNCTION__, GetDefaultDataDir().string());
        LogPrint("init", "%s : NOTICE - Used data directory %s \n", __FUNCTION__, strDataDir);
    }

    std::ostringstream strErrors;

    // masternode payments priv key
    if (mapArgs.count("-masternodepaymentskey"))
    {
        if (!masternodePayments.SetPrivKey(GetArg("-masternodepaymentskey", "")))
        {
            return InitError(_("ERROR - Unable to sign masternode payment winner, wrong key?"));
        }

        if (!sporkManager.SetPrivKey(GetArg("-masternodepaymentskey", "")))
        {
            return InitError(_("ERROR - Unable to sign spork message, wrong key?"));
        }
    }

    //ignore masternodes below protocol version
    nMasternodeMinProtocol = GetArg("-masternodeminprotocol", MIN_POOL_PEER_PROTO_VERSION);

    if (fDaemon)
    {
        fprintf(stdout, "PHC server starting... Please wait. \n");
    }

    int64_t nStart;




    // ********************************************************* Step 5: Backup wallet and verify wallet database integrity
#ifdef ENABLE_WALLET
    if (!fDisableWallet)
    {

        filesystem::path backupDir = GetDataDir(true) / "backups";
        
        if (!filesystem::exists(backupDir))
        {
            // Always create backup folder to not confuse the operating system's file browser
            filesystem::create_directory(backupDir);
        }

        nWalletBackups = GetArg("-createwalletbackups", 10);
        nWalletBackups = std::max(0, std::min(10, nWalletBackups));

        if(nWalletBackups > 0)
        {
            if (filesystem::exists(backupDir))
            {
                // Create backup of the wallet
                std::string dateTimeStr = DateTimeStrFormat(".%Y-%m-%d-%H.%M", GetTime());
                std::string backupPathStr = backupDir.string();

                backupPathStr += "/" + strWalletFileName;
                std::string sourcePathStr = GetDataDir(true).string();
                sourcePathStr += "/" + strWalletFileName;

                boost::filesystem::path sourceFile = sourcePathStr;
                boost::filesystem::path backupFile = backupPathStr + dateTimeStr;

                if (fDebug)
                {
                    LogPrint("init", "%s : OK - Creating backup of %s -> %s \n", __FUNCTION__, sourceFile, backupFile);
                }

                copyfile(sourceFile.string(), backupFile.string());

                // Keep only the last 10 backups, including the new one of course
                typedef std::multimap<std::time_t, boost::filesystem::path> folder_set_t;

                folder_set_t folder_set;

                boost::filesystem::directory_iterator end_iter;
                boost::filesystem::path backupFolder = backupDir.string();

                backupFolder.make_preferred();

                // Build map of backup files for current(!) wallet sorted by last write time
                boost::filesystem::path currentFile;

                for (boost::filesystem::directory_iterator dir_iter(backupFolder); dir_iter != end_iter; ++dir_iter)
                {
                    // Only check regular files
                    if ( boost::filesystem::is_regular_file(dir_iter->status()))
                    {
                        currentFile = dir_iter->path().filename();

                        // Only add the backups for the current wallet, e.g. wallet.dat.*
                        if(currentFile.string().find(strWalletFileName) != string::npos)
                        {
                            folder_set.insert(folder_set_t::value_type(boost::filesystem::last_write_time(dir_iter->path()), *dir_iter));
                        }
                    }
                }

                // Loop backward through backup files and keep the N newest ones (1 <= N <= 10)
                int counter = 0;

                for(PAIRTYPE(const std::time_t, boost::filesystem::path) file: boost::adaptors::reverse(folder_set))
                {
                    counter++;

                    if (counter > nWalletBackups)
                    {
                        // More than nWalletBackups backups: delete oldest one(s)
                        try
                        {
                            boost::filesystem::remove(file.second);

                            if (fDebug)
                            {
                                LogPrint("init", "%s : WARNING - Old backup deleted: %s \n", __FUNCTION__, file.second);
                            }
                        }
                        catch(boost::filesystem::filesystem_error &error)
                        {
                            if (fDebug)
                            {
                                LogPrint("init", "%s : ERROR - Failed to delete backup %s \n", __FUNCTION__, error.what());
                            }
                        }
                    }
                }
            }
        }

        uiInterface.InitMessage(_("Verifying database integrity..."));

        if (!bitdb.Open(GetDataDir(true)))
        {
            // try moving the database env out of the way
            boost::filesystem::path pathDatabase = GetDataDir(true) / "database";
            boost::filesystem::path pathDatabaseBak = GetDataDir(true) / strprintf("database.%d.bak", GetTime());

            try
            {
                boost::filesystem::rename(pathDatabase, pathDatabaseBak);

                if (fDebug)
                {
                    LogPrint("init", "%s : WARNING - Moved old %s to %s. Retrying. \n", __FUNCTION__, pathDatabase.string(), pathDatabaseBak.string());
                }
            }
            catch(boost::filesystem::filesystem_error &error)
            {
                 // failure is ok (well, not really, but it's not worse than what we started with)
            }

            // try again
            if (!bitdb.Open(GetDataDir(true)))
            {
                // if it still fails, it probably means we can't even create the database env
                string msg = strprintf(_("ERROR - initializing wallet database environment %s!"), strDataDir);

                return InitError(msg);
            }
        }

        if (GetBoolArg("-salvagewallet", false))
        {
            // Recover readable keypairs:
            if (!CWalletDB::Recover(bitdb, strWalletFileName, true))
            {
                return false;
            }
        }

        if (filesystem::exists(GetDataDir(true) / strWalletFileName))
        {
            CDBEnv::VerifyResult r = bitdb.Verify(strWalletFileName, CWalletDB::Recover);

            if (r == CDBEnv::RECOVER_OK)
            {
                string msg = strprintf(_("ERROR - wallet.dat corrupt, data salvaged!"
                                         " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                         " your balance or transactions are incorrect you should"
                                         " restore from a backup."), strDataDir);
                InitWarning(msg);
            }

            if (r == CDBEnv::RECOVER_FAIL)
            {
                return InitError(_("ERROR - wallet.dat corrupt, salvage failed"));
            }
        }

    } // (!fDisableWallet)
#endif // ENABLE_WALLET
    // ********************************************************* Step 6: network initialization

    RegisterNodeSignals(GetNodeSignals());

    // format user agent, check total size
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, mapMultiArgs.count("-uacomment") ? mapMultiArgs["-uacomment"] : std::vector<string>());
    
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH)
    {
        return InitError(strprintf("ERROR - Total length of network version string %i exceeds maximum of %i characters. Reduce the number and/or size of uacomments.", strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }
    
    if (mapArgs.count("-onlynet"))
    {
        std::set<enum Network> nets;

        for(std::string snet: mapMultiArgs["-onlynet"])
        {
            enum Network net = ParseNetwork(snet);

            if(net == NET_TOR)
            {
                fOnlyTor = true;
            }

            if (net == NET_UNROUTABLE)
            {
                return InitError(strprintf(_("ERROR - Unknown network specified in -onlynet: '%s'"), snet));
            }

            nets.insert(net);
        }

        for (int n = 0; n < NET_MAX; n++)
        {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
            {
                SetLimited(net);
            }
        }
    }
    else
    {
        SetReachable(NET_IPV4);
        SetReachable(NET_IPV6);
    }

    CService addrProxy;
    
    bool fProxy = false;

    if (mapArgs.count("-proxy"))
    {
        addrProxy = CService(mapArgs["-proxy"], 9050);
        
        if (!addrProxy.IsValid())
        {
            return InitError(strprintf(_("ERROR - Invalid -proxy address: '%s'"), mapArgs["-proxy"]));
        }

        if (!IsLimited(NET_IPV4))
        {
            SetProxy(NET_IPV4, addrProxy);
        }

        if (!IsLimited(NET_IPV6))
        {
            SetProxy(NET_IPV6, addrProxy);
        }

        SetNameProxy(addrProxy);

        fProxy = true;
    }

    // -tor can override normal proxy, -notor disables tor entirely
    if (!(mapArgs.count("-tor")
        && mapArgs["-tor"] == "0")
        && (fProxy || mapArgs.count("-tor")))
    {
        CService addrOnion;

        if (!mapArgs.count("-tor"))
        {
            addrOnion = addrProxy;
        }
        else
        {
            addrOnion = CService(mapArgs["-tor"], 9050);
        }

        if (!addrOnion.IsValid())
        {
            return InitError(strprintf(_("ERROR - Invalid -tor address: '%s'"), mapArgs["-tor"]));
        }
        
        SetProxy(NET_TOR, addrOnion);
        
        SetReachable(NET_TOR);
    }

    // see Step 2: parameter interactions for more information about these
    fNoListen = !GetBoolArg("-listen", true);
    fDiscover = GetBoolArg("-discover", true);
    fNameLookup = GetBoolArg("-dns", true);

    bool fBound = false;

    if (!fNoListen)
    {
        std::string strError;

        if (mapArgs.count("-bind"))
        {
            for(std::string strBind: mapMultiArgs["-bind"])
            {
                CService addrBind;

                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                {
                    return InitError(strprintf(_("ERROR - Cannot resolve -bind address: '%s' "), strBind));
                }

                fBound |= Bind(addrBind);
            }
        }
        else
        {
            struct in_addr inaddr_any;
            
            inaddr_any.s_addr = INADDR_ANY;

            if (!IsLimited(NET_IPV6))
            {
                fBound |= Bind(CService(in6addr_any, GetListenPort()), false);
            }
            
            if (!IsLimited(NET_IPV4))
            {
                fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound);
            }
        }

        if (!fBound)
        {
            return InitError(_("ERROR - Failed to listen on any port. Use -listen=0 if you want this."));
        }
    }

    if (mapArgs.count("-externalip"))
    {
        for(string strAddr: mapMultiArgs["-externalip"])
        {
            CService addrLocal(strAddr, GetListenPort(), fNameLookup);

            if (!addrLocal.IsValid())
            {
                return InitError(strprintf(_("ERROR - Cannot resolve -externalip address: '%s' "), strAddr));
            }

            AddLocal(CService(strAddr, GetListenPort(), fNameLookup), LOCAL_MANUAL);
        }
    }

#ifdef ENABLE_WALLET
    // ppcoin: reserve balance amount
    if (mapArgs.count("-reservebalance"))
    {
        if (!ParseMoney(mapArgs["-reservebalance"], nReserveBalance))
        {
            InitError(_("ERROR - Invalid amount for -reservebalance=<amount>"));

            return false;
        }
    }
#endif

    for(string strDest: mapMultiArgs["-seednode"])
    {
        AddOneShot(strDest);
    }

    // ********************************************************* Step 7: load blockchain

    uiInterface.InitMessage(_("Loading block index..."));

    nStart = GetTimeMillis();

    bool DbsLoaded = false;

    // Rebuilds local blockchain Database
    if(GetBoolArg("-clearchainfiles", false))
    {
        filesystem::path pathBlockchain = GetDataDir(true) / "blk0001.dat";
        filesystem::path pathDatabase = GetDataDir(true) / "database";
        filesystem::path pathsmsgDB = GetDataDir(true) / "smsgDB";
        filesystem::path pathTxleveldb = GetDataDir(true) / "txleveldb";
        filesystem::path pathMncache = GetDataDir(true) / "mncache.dat";

        filesystem::remove_all(pathBlockchain);
        filesystem::remove_all(pathDatabase);
        filesystem::remove_all(pathsmsgDB);
        filesystem::remove_all(pathTxleveldb);
        filesystem::remove_all(pathMncache);

        return InitError(strprintf("%s : ERROR - Removal of local blockchain files complete, start wallet again to re-sync fresh, or Bootstrap manually.", __FUNCTION__));
    }

    // Rebuilds local blockchain Database
    if(GetBoolArg("-rebuild", false))
    {
        uiInterface.InitMessage(("Rebuilding local blockchain... \n"));
        fprintf(stdout, "Rebuilding local blockchain... \n");

        filesystem::path pathBlockchain = GetDataDir(true) / "blk0001.dat";
        filesystem::path pathBootstrap = GetDataDir(true) / "bootstrap.dat";
        filesystem::path pathDatabase = GetDataDir(true) / "database";
        filesystem::path pathsmsgDB = GetDataDir(true) / "smsgDB";
        filesystem::path pathTxleveldb = GetDataDir(true) / "txleveldb";
        filesystem::path pathMncache = GetDataDir(true) / "mncache.dat";

        if (filesystem::exists(pathBlockchain))
        {
            filesystem::rename(pathBlockchain, pathBootstrap);
            filesystem::remove_all(pathDatabase);
            filesystem::remove_all(pathsmsgDB);
            filesystem::remove_all(pathTxleveldb);
            filesystem::remove_all(pathMncache);
        }

        MilliSleep(1000);

        // Load bootstrap
        if (filesystem::exists(pathBootstrap))
        {
            FILE *file = fopen(pathBootstrap.string().c_str(), "rb");

            if (file)
            {
                filesystem::path pathBootstrapOld = GetDataDir(true) / "bootstrap.dat.old";

                uiInterface.InitMessage(("Bootstraping after rebuild.. \n"));
                fprintf(stdout, "Bootstraping after rebuild... \n");

                DbsLoaded = LoadExternalBlockFile(file);
                
                RenameOver(pathBootstrap, pathBootstrapOld);

                uiInterface.InitMessage(("Bootstraping completed. \n"));
                fprintf(stdout, "Bootstrap completed. \n");
            }
        }

        return InitError(strprintf("%s : WARNING - Rebuild local blockchain complete, restart wallet again (phc-qt or phcd) to auto-bootstrap local blockchain index.", __FUNCTION__)); 
    }

    // Bootstraps local blockchain from ProfitHuntersCoin.com/bootstraps/bootstrap.dat (not working)
    // TO-DO
    if(GetBoolArg("-bootstrap", false))
    {
        uiInterface.InitMessage(("Clearing local blockchain files... \n"));
        
        fprintf(stdout, "Clearing local blockchain files... \n");

        filesystem::path pathBlockchain = GetDataDir(true) / "blk0001.dat";
        filesystem::path pathBootstrap = GetDataDir(true) / "bootstrap.dat";
        filesystem::path pathDatabase = GetDataDir(true) / "database";
        filesystem::path pathsmsgDB = GetDataDir(true) / "smsgDB";
        filesystem::path pathTxleveldb = GetDataDir(true) / "txleveldb";
        filesystem::path pathMncache = GetDataDir(true) / "mncache.dat";

        if (filesystem::exists(pathBlockchain))
        {
            filesystem::rename(pathBlockchain, pathBootstrap);
            filesystem::remove_all(pathDatabase);
            filesystem::remove_all(pathsmsgDB);
            filesystem::remove_all(pathTxleveldb);
            filesystem::remove_all(pathMncache);
        }

        MilliSleep(1000);

        uiInterface.InitMessage(("Downloading Bootstrap... \n"));
        fprintf(stdout, "Downloading Bootstrap... \n");

        download_bootstrap(pathBootstrap.string());

        return InitError(strprintf("%s : ERROR - Bootstrap downloaded, please restart wallet (phc-qt or phcd) to begin importing blockchain data.", __FUNCTION__));
    }

    // Loads Blockchain database normally if -rebuild is not present in params
    DbsLoaded = LoadBlockIndex();
    
    MilliSleep(1000);

    if (DbsLoaded == false)
    {
        // try again (low memory machines will display "error", during BlockIndex loading process)
        DbsLoaded = LoadBlockIndex();
    }

    // Rollbackchain local database X amount of blocks (default: 100")
    int nBlockCount = GetArg( "-rollbackchain", 0);

    if (nBlockCount > 0)
    {
        nBestHeight = CChain::RollbackChain(nBlockCount);

        return InitError(strprintf("%s : WARNING - Rollback completed %d blocks total removed from local height.", __FUNCTION__, nBlockCount));
    }

    // Rollbacktoblock local database to block height (default: 100000)
    if (mapArgs.count("-backtoblock"))
    {
        int nNewHeight = CChain::Backtoblock(GetArg("-backtoblock", 100000));

        return InitError(strprintf("%s : WARNING - Backtoblock completed: %d is the new local block height.", __FUNCTION__, nNewHeight));
    }

    if (GetBoolArg("-loadblockindextest", false))
    {
        CTxDB txdb("r");

        txdb.LoadBlockIndex();

        PrintBlockTree();

        return false;
    }

    if (DbsLoaded == false)
    {
        return InitError("ERROR - Error loading block database");
    }

    // as LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill bitcoin-qt during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        if (fDebug)
        {
            LogPrint("init", "%s : WARNING - Shutdown requested. Exiting. \n", __FUNCTION__);
        }

        return false;
    }

    if (fDebug)
    {
        LogPrint("init", "%s : NOTICE - Block index %15dms \n", __FUNCTION__, GetTimeMillis() - nStart);
    }

    uiInterface.InitMessage(_("WARNING - Prune Orphans in block index..."));

    CChain::PruneOrphanBlocks();

    //uiInterface.InitMessage(_("Rolling back block index..."));
    //RollbackChain(101);

    if (GetBoolArg("-printblockindex", false)
        || GetBoolArg("-printblocktree", false))
    {
        PrintBlockTree();

        return false;
    }

    if (mapArgs.count("-printblock"))
    {
        string strMatch = mapArgs["-printblock"];

        int nFound = 0;

        for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        {
            uint256 hash = (*mi).first;

            if (strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0)
            {
                CBlockIndex* pindex = (*mi).second;

                CBlock block;

                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();

                if (fDebug)
                {
                    LogPrint("init", "%s : NOTICE - %s \n", __FUNCTION__, block.ToString());
                }

                nFound++;
            }
        }

        if (nFound == 0)
        {
            if (fDebug)
            {
                LogPrint("init", "%s : ERROR - No blocks matching %s were found \n", __FUNCTION__, strMatch);
            }
        }

        return false;
    }

    // ********************************************************* Step 8: load wallet
#ifdef ENABLE_WALLET
    if (fDisableWallet)
    {
        pwalletMain = NULL;

        if (fDebug)
        {
            LogPrint("init", "%s : WARNING - Wallet disabled! \n", __FUNCTION__);
        }
    }
    else
    {
        uiInterface.InitMessage(_("Loading wallet..."));

        nStart = GetTimeMillis();
        bool fFirstRun = true;

        pwalletMain = new CWallet(strWalletFileName);
        DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);

        if (nLoadWalletRet != DB_LOAD_OK)
        {
            if (nLoadWalletRet == DB_CORRUPT)
            {
                strErrors << _("ERROR - Loading wallet.dat: Wallet corrupted") << "\n";
            }
            else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
            {
                string msg(_("WARNING - Unable to read wallet.dat! All keys read correctly, but transaction data"
                             " or address book entries might be missing or incorrect."));

                InitWarning(msg);
            }
            else if (nLoadWalletRet == DB_TOO_NEW)
            {
                strErrors << _("ERROR - Loading wallet.dat: Wallet requires newer version of PHC") << "\n";
            }
            else if (nLoadWalletRet == DB_NEED_REWRITE)
            {
                strErrors << _("ERROR - Wallet needed to be rewritten: restart PHC to complete") << "\n";

                if (fDebug)
                {
                    LogPrint("init", "%s : %s \n", __FUNCTION__, strErrors.str());
                }

                return InitError(strErrors.str());
            }
            else
            {
                strErrors << _("ERROR - loading wallet.dat") << "\n";
            }
        }

        if (GetBoolArg("-upgradewallet", fFirstRun))
        {
            int nMaxVersion = GetArg("-upgradewallet", 0);

            // the -upgradewallet without argument case
            if (nMaxVersion == 0)
            {
                if (fDebug)
                {
                    LogPrint("init", "%s : NOTICE - Performing wallet upgrade to %i \n", __FUNCTION__, FEATURE_LATEST);
                }

                nMaxVersion = CLIENT_VERSION;

                // permanently upgrade the wallet immediately
                pwalletMain->SetMinVersion(FEATURE_LATEST);
            }
            else
            {
                if (fDebug)
                {
                    LogPrint("init", "%s : WARNING - Allowing wallet upgrade up to %i \n", __FUNCTION__, nMaxVersion);
                }
            }

            if (nMaxVersion < pwalletMain->GetVersion())
            {
                strErrors << _("ERROR - Cannot downgrade wallet") << "\n";
            }

            pwalletMain->SetMaxVersion(nMaxVersion);
        }

        if (fFirstRun)
        {
            // Create new keyUser and set as default key
            RandAddSeedPerfmon();

            CPubKey newDefaultKey;
            if (pwalletMain->GetKeyFromPool(newDefaultKey))
            {
                pwalletMain->SetDefaultKey(newDefaultKey);

                if (!pwalletMain->SetAddressBookName(pwalletMain->vchDefaultKey.GetID(), ""))
                {
                    strErrors << _("ERROR - Cannot write default address") << "\n";
                }
            }

            pwalletMain->SetBestChain(CBlockLocator(pindexBest));
        }

        if (fDebug)
        {
            LogPrint("init", "%s : NOTICE - %s", __FUNCTION__, strErrors.str());
            LogPrint("init", "%s : NOTICE - wallet      %15dms \n", __FUNCTION__, GetTimeMillis() - nStart);
        }

        RegisterWallet(pwalletMain);

        CBlockIndex *pindexRescan = pindexBest;

        if (GetBoolArg("-rescan", false))
        {
            pindexRescan = pindexGenesisBlock;
        }
        else
        {
            CWalletDB walletdb(strWalletFileName);
            CBlockLocator locator;

            if (walletdb.ReadBestBlock(locator))
            {
                pindexRescan = locator.GetBlockIndex();
            }
            else
            {
                pindexRescan = pindexGenesisBlock;
            }

        }

        if (pindexBest != pindexRescan && pindexBest && pindexRescan
            && pindexBest->nHeight > pindexRescan->nHeight)
        {
            uiInterface.InitMessage(_("Rescanning..."));
            
            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - Rescanning last %i blocks (from block %i)... \n", __FUNCTION__, pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
            }

            nStart = GetTimeMillis();
            pwalletMain->ScanForWalletTransactions(pindexRescan, true);

            if (fDebug)
            {
                LogPrint("init", "%s : NOTICE - rescan      %15dms \n", __FUNCTION__, GetTimeMillis() - nStart);
            }

            pwalletMain->SetBestChain(CBlockLocator(pindexBest));
            nWalletDBUpdated++;
        }
    } // (!fDisableWallet)

#else // ENABLE_WALLET
    if (fDebug)
    {
        LogPrint("init", "%s : WARNING - No wallet compiled in! \n", __FUNCTION__);
    }
#endif // !ENABLE_WALLET
    // ********************************************************* Step 9: import blocks

    std::vector<boost::filesystem::path> vImportFiles;
    
    if (mapArgs.count("-loadblock"))
    {
        for(string strFile: mapMultiArgs["-loadblock"])
        {
            vImportFiles.push_back(strFile);
        }
    }

    threadGroup.create_thread(boost::bind(&ThreadImport, vImportFiles));

    // ********************************************************* Step 10: load peers

    uiInterface.InitMessage(_("NOTICE - Loading addresses..."));

    nStart = GetTimeMillis();

    // Global Namespace Start
    {
        CAddrDB adb;

        if (!adb.Read(addrman))
        {
            if (fDebug)
            {
                LogPrint("init", "%s : WARNING - Invalid or missing peers.dat; recreating \n", __FUNCTION__);
            }
        }
    }
    // Global Namespace End

    if (fDebug)
    {
        LogPrint("init", "%s : OK - Loaded %i addresses from peers.dat  %dms \n", __FUNCTION__, addrman.size(), GetTimeMillis() - nStart);
    }

    // ********************************************************* Step 10.1: startup secure messaging
    
    SecureMsgStart(fNoSmsg, GetBoolArg("-smsgscanchain", false));

    // ********************************************************* Step 11: start node

    if (!CheckDiskSpace())
    {
        return false;
    }

    if (!strErrors.str().empty())
    {
        return InitError(strErrors.str());
    }

    uiInterface.InitMessage(_("NOTICE - Loading masternode cache..."));

    CMasternodeDB mndb;
    CMasternodeDB::ReadResult readResult = mndb.Read(mnodeman);

    if (readResult == CMasternodeDB::FileError)
    {
        if (fDebug)
        {
            LogPrint("init", "%s : NOTICE - Missing masternode cache file - mncache.dat, will try to recreate \n", __FUNCTION__);
        }
    }
    else if (readResult != CMasternodeDB::Ok)
    {
        if (fDebug)
        {
            LogPrint("init", "%s : NOTICE - reading mncache.dat: ", __FUNCTION__);
        }

        if(readResult == CMasternodeDB::IncorrectFormat)
        {
            if (fDebug)
            {
                LogPrint("init", "%s : WARNING - magic is ok but data has invalid format, will try to recreate \n", __FUNCTION__);
            }
        }
        else
        {
            if (fDebug)
            {
                LogPrint("init", "%s : ERROR - file format is unknown or invalid, please fix it manually \n", __FUNCTION__);
            }
        }
    }

    fMasterNode = GetBoolArg("-masternode", false);

    if(fMasterNode)
    {
        if (fDebug)
        {
            LogPrint("init", "%s : NOTICE - IS DARKSEND MASTER NODE \n", __FUNCTION__);
        }

        strMasterNodeAddr = GetArg("-masternodeaddr", "");

        if (fDebug)
        {
            LogPrint("init", "%s : NOTICE - Addr %s\n", __FUNCTION__, strMasterNodeAddr.c_str());
        }

        if(!strMasterNodeAddr.empty())
        {
            CService addrTest = CService(strMasterNodeAddr, fNameLookup);

            if (!addrTest.IsValid())
            {
                return InitError("ERROR - Invalid -masternodeaddr address: " + strMasterNodeAddr);
            }
        }

        strMasterNodePrivKey = GetArg("-masternodeprivkey", "");

        if(!strMasterNodePrivKey.empty())
        {
            std::string errorMessage;

            CKey key;
            CPubKey pubkey;

            if(!darkSendSigner.SetKey(strMasterNodePrivKey, errorMessage, key, pubkey))
            {
                return InitError(_("ERROR - Invalid masternodeprivkey. Please see documenation."));
            }

            activeMasternode.pubKeyMasternode = pubkey;

        }
        else
        {
            return InitError(_("ERROR - You must specify a masternodeprivkey in the configuration. Please see documentation for help."));
        }

        activeMasternode.ManageStatus();
    }

    if(GetBoolArg("-mnconflock", false))
    {
        if (fDebug)
        {
            LogPrint("init", "%s : NOTICE - Locking Masternodes: \n", __FUNCTION__);
        }

        uint256 mnTxHash;

        for(CMasternodeConfig::CMasternodeEntry mne: masternodeConfig.getEntries())
        {
            if (fDebug)
            {
                LogPrint("init", "%s : %s %s \n", __FUNCTION__, mne.getTxHash(), mne.getOutputIndex());
            }

            mnTxHash.SetHex(mne.getTxHash());

            COutPoint outpoint = COutPoint(mnTxHash, boost::lexical_cast<unsigned int>(mne.getOutputIndex()));

            pwalletMain->LockCoin(outpoint);
        }
    }

    fEnableDarksend = GetBoolArg("-enabledarksend", false);

    nDarksendRounds = GetArg("-darksendrounds", 2);

    if(nDarksendRounds > 16)
    {
        nDarksendRounds = 16;
    }

    if(nDarksendRounds < 1)
    {
        nDarksendRounds = 1;
    }

    //0-100
    nLiquidityProvider = GetArg("-liquidityprovider", 0);

    if(nLiquidityProvider != 0)
    {
        darkSendPool.SetMinBlockSpacing(std::min(nLiquidityProvider,100)*15);

        fEnableDarksend = true;
        nDarksendRounds = 99999;
    }

    nAnonymizeAmount = GetArg("-AnonymizeAmount", 0);

    if(nAnonymizeAmount > 999999)
    {
        nAnonymizeAmount = 999999;
    }

    if(nAnonymizeAmount < 2)
    {
        nAnonymizeAmount = 2;
    }

    fEnableInstantX = GetBoolArg("-enableinstantx", fEnableInstantX);

    nInstantXDepth = GetArg("-instantxdepth", nInstantXDepth);
    nInstantXDepth = std::min(std::max(nInstantXDepth, 0), 60);

    //lite mode disables all Masternode and Darksend related functionality
    fLiteMode = GetBoolArg("-litemode", false);

    if(fMasterNode && fLiteMode)
    {
        return InitError("You can not start a masternode in litemode");
    }

    if (fDebug)
    {
        LogPrint("init", "%s : NOTICE - fLiteMode %d \n", __FUNCTION__, fLiteMode);
        LogPrint("init", "%s : NOTICE - nInstantXDepth %d \n", __FUNCTION__, nInstantXDepth);
        LogPrint("init", "%s : NOTICE - Darksend rounds %d \n", __FUNCTION__, nDarksendRounds);
        LogPrint("init", "%s : NOTICE - Anonymize PHC Amount %d \n", __FUNCTION__, nAnonymizeAmount);
    }

    /* Denominations
       A note about convertability. Within Darksend pools, each denomination
       is convertable to another.
       For example:
       1PHC+1000 == (.1PHC+100)*10
       10PHC+10000 == (1PHC+1000)*10
    */
    darkSendDenominations.push_back( (1000  * COIN) + 1000000 );
    darkSendDenominations.push_back( (100   * COIN) + 100000 );
    darkSendDenominations.push_back( (10    * COIN) + 10000 );
    darkSendDenominations.push_back( (1     * COIN) + 1000 );
    darkSendDenominations.push_back( (.1    * COIN) + 100 );
    /* Disabled till we need them
    darkSendDenominations.push_back( (.01      * COIN)+10 );
    darkSendDenominations.push_back( (.001     * COIN)+1 );
    */

    darkSendPool.InitCollateralAddress();

    threadGroup.create_thread(boost::bind(&ThreadCheckDarkSendPool));

    RandAddSeedPerfmon();

    // reindex addresses found in blockchain database
    if(GetBoolArg("-reindex", false))
    {
        uiInterface.InitMessage(_("NOTICE - Rebuilding address index..."));

        CBlockIndex *pblockAddrIndex = pindexBest;

        CTxDB txdbAddr("rw");

        while(pblockAddrIndex)
        {
            uiInterface.InitMessage(strprintf("WARNING - Rebuilding address index, block %i", pblockAddrIndex->nHeight));
            
            bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true);
            
            CBlock pblockAddr;

            if(pblockAddr.ReadFromDisk(pblockAddrIndex, true))
            {
                pblockAddr.RebuildAddressIndex(txdbAddr);
            }

            pblockAddrIndex = pblockAddrIndex->pprev;
        }
    }

    if (fDebug)
    {
        //// debug print
        LogPrint("init", "%s : NOTICE - mapBlockIndex.size() = %u \n", __FUNCTION__,   mapBlockIndex.size());
        LogPrint("init", "%s : NOTICE - nBestHeight = %d\n", __FUNCTION__,            nBestHeight);
#ifdef ENABLE_WALLET
        LogPrint("init", "%s : NOTICE - setKeyPool.size() = %u \n", __FUNCTION__,      pwalletMain ? pwalletMain->setKeyPool.size() : 0);
        LogPrint("init", "%s : NOTICE - mapWallet.size() = %u \n", __FUNCTION__,       pwalletMain ? pwalletMain->mapWallet.size() : 0);
        LogPrint("init", "%s : NOTICE - mapAddressBook.size() = %u \n", __FUNCTION__,  pwalletMain ? pwalletMain->mapAddressBook.size() : 0);
#endif
    }

    StartNode(threadGroup);
#ifdef ENABLE_WALLET
    // InitRPCMining is needed here so getwork/getblocktemplate in the GUI debug console works properly.
    InitRPCMining();
#endif
    if (fServer)
    {
        StartRPCThreads();
    }

#ifdef ENABLE_WALLET
    fStaking = GetBoolArg("-staking", false);

    // Mine proof-of-stake blocks in the background (Enabled by default)
    if (!fStaking)
    {
        if (fDebug)
        {
            LogPrint("init", "%s : NOTICE - Staking disabled \n", __FUNCTION__); 
        }
    }
    else if (pwalletMain)
    {
        threadGroup.create_thread(boost::bind(&ThreadStakeMiner, pwalletMain));

        if (fDebug)
        {
            LogPrint("init", "%s : OK - Staking enabled \n", __FUNCTION__); 
        }
    }

    // Generate coins using internal miner
    if (pwalletMain)
    {
        GeneratePoWcoins(GetBoolArg("-gen", false), pwalletMain);
    }
#endif

    // ********************************************************* Step 12: finished

    uiInterface.InitMessage(("Done loading"));

#ifdef ENABLE_WALLET
    if (pwalletMain)
    {
        // Add wallet transactions that aren't already in a block to mapTransactions
        pwalletMain->ReacceptWalletTransactions();

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(boost::bind(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile)));
    }
#endif

    if (fDaemon)
    {
        fprintf(stdout, "OK - Done loading PHC server. \n");
    }

    return !fRequestShutdown;
}