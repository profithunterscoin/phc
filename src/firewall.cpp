/*
    ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
    ||||                                                                                            ||||
    |||| Bitcoin Firewall 2.0.0.4 (Oct, 2019)                                                       ||||
    ||||                                                                                            ||||
    |||| Copyright (c) 2016 Biznatch Enterprises                                                    ||||
    |||| Copyright (c) 2017 BATA Development                                                        ||||
    |||| Copyright (c) 2018-2019 Profit Hunters Coin                                                ||||
    ||||                                                                                            ||||
    |||| https://github.com/BiznatchEnterprises/BitcoinFirewall                                     ||||
    ||||                                                                                            ||||
    |||| Distributed under the MIT/X11 software license, see the accompanying                       ||||
    |||| file COPYING or http://www.opensource.org/licenses/mit-license.php.                        ||||
    ||||                                                                                            ||||
    ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
*/


#include "firewall.h"
#include "util.h"
#include "main.h"
#include "consensus.h"


using namespace CBan;


// FirewallData Namespace Start
namespace FirewallData
{
    PeerMap::PeerMap()
    {
        IP = "";
        Version = "";
        TimeConnected = 0;
        SendBytes = 0;
        ReceiveBytes = 0;
        AddrRecvCount = 0;
    }

    PeerMap::PeerMap(std::string IP_in)
    {
        IP = IP_in;
        Version = "";
        TimeConnected = 0;
        SendBytes = 0;
        ReceiveBytes = 0;
        AddrRecvCount = 0;
    }

    PeerMap::PeerMap(std::string IP_in, std::string Version_in)
    {
        IP = IP_in;
        Version = Version_in;
        TimeConnected = 0;
        SendBytes = 0;
        ReceiveBytes = 0;
        AddrRecvCount = 0;
    }

    PeerMap::PeerMap(std::string IP_in, std::string Version_in, int TimeConnected_in)
    {
        IP = IP_in;
        Version = Version_in;
        TimeConnected = TimeConnected_in;
        SendBytes = 0;
        ReceiveBytes = 0;
        AddrRecvCount = 0;
    }

    PeerMap::PeerMap(std::string IP_in, std::string Version_in, int TimeConnected_in, uint64_t SendBytes_in)
    {
        IP = IP_in;
        Version = Version_in;
        TimeConnected = TimeConnected_in;
        SendBytes = SendBytes_in;
        ReceiveBytes = 0;
        AddrRecvCount = 0;
    }

    PeerMap::PeerMap(std::string IP_in, std::string Version_in, int TimeConnected_in, uint64_t SendBytes_in, uint64_t ReceiveBytes_in)
    {
        IP = IP_in;
        Version = Version_in;
        TimeConnected = TimeConnected_in;
        SendBytes = SendBytes_in;
        ReceiveBytes = ReceiveBytes_in;
        AddrRecvCount = 0;
    }

    PeerMap::PeerMap(std::string IP_in, std::string Version_in, int TimeConnected_in, uint64_t SendBytes_in, uint64_t ReceiveBytes_in, int AddrRecvCount_in)
    {
        IP = IP_in;
        Version = Version_in;
        TimeConnected = TimeConnected_in;
        SendBytes = SendBytes_in;
        ReceiveBytes = ReceiveBytes_in;
        AddrRecvCount = AddrRecvCount_in;
    }
}
// FirewallData Namespace End


// Firewall Namespace Start
namespace Firewall
{
    /* ------------------- */
    /* Settings Class */

    /* VARIABLES: Global Firewall Variables */
    std::string Settings::ModuleName = "[Firewall 2.0.0.4]";                            /* String */

    int Settings::AllCheck_Timer = GetTime();                                           /* Start Time */
    int Settings::AllCheck_MaxTimer = GetArg("-fw:allmaxtimer", 3);                     /* Minutes interval for some detection settings */

    /* VARIABLES: Firewall Settings (General) */
    bool Settings::Enabled = GetBoolArg("-fw:enabled", true);                           /* True/False */
    bool Settings::Denied_Autoclear = GetBoolArg("-fw:cleardenied", false);             /* True/False */
    bool Settings::Banned_Autoclear = GetBoolArg("-fw:clearban", false);                /* True/False */
    int Settings::Banned_MinNodes = GetArg("-fw:allmaxtimer", 10);                      /* Minimum connected nodes to auto-clear */

    /* VARIABLES: Firewall Settings (Exam) */
    int Settings::Average_Tolerance = GetArg("-fw:avgtolerance", 2);                    /* Reduce for minimal fluctuation 2 Blocks tolerance */
    int Settings::Average_Range = GetArg("-fw:avgrange", 100);                          /* + or - Starting Height Range */
    double Settings::Traffic_Tolerance = GetArg("-fw:traffictolerance", 0);             /* Reduce for minimal fluctuation */
    double Settings::Traffic_Zone = GetArg("-fw:trafficzone>", 4);                      /* + or - Traffic Range */

    /* ------------------- */
    /* Lists Class */

    // PeerStatsMap
    std::vector<pair<int, FirewallData::PeerMap>> Stats::PeerMap; // vector of pair: Timestamp, PeerMapEntry

    /* VARIABLE (Array): Firewall Allowed list
    (ignore pnode->addrName)
    */
    std::string Lists::Allowed[256] =
    {

    };

    /* VARIABLE (Array): Firewall Denied List
    (autoban/disconnect pnode->addrName)
    */
    std::string Lists::Denied[256] =
    {

    };


    /* FUNCTION: Lists::Check */
    bool Lists::Check(CNode *pnode, std::string ListType)
    {
        // To-Do: Convert Allowed and Denied to vector

        int i;

        int ListCount;

        if (ListType == "Allowed")
        {
            ListCount = CountStringArray(Allowed);
        }
        else
        {
            ListCount = CountStringArray(Denied);
        }

        if (ListCount > 0)
        {
            for (i = 0; i < ListCount; i++)
            {  

                if (ListType == "Allowed")
                {
                    if (pnode->addrName == Allowed[i])
                    {   
                        // Banned IP FOUND! (Allowed)
                        return true;
                    }
                }
                else
                {
                    if (pnode->addrName == Denied[i])
                    {   
                        // Banned IP FOUND! (Denied)
                        return true;
                    }
                }
            }
        }

        // Banned IP not found
        return false;
    }


    /* FUNCTION: Lists::Add */
    bool Lists::Add(CNode *pnode, std::string ListType)
    {
        int ListCount;
        ListCount = CountStringArray(Denied);

            /** Restart Denied count **/
            if (ListCount >  255)
            {
                ListCount = 0;
            }

            if (Lists::Check(pnode, ListType) == false)
            {
                /** increase Denied count **/
                ListCount = ListCount + 1;

                /** Add node IP to Denied **/
                Denied[ListCount] = pnode->addrName;

                if (LiveDebug::Enabled == true)
                {
                    if (LiveDebug::Denied == true)
                    {
                        cout << Settings::ModuleName << " Denieded: " << pnode->addrName << "]\n" << endl;
                    }
                }

                /** Append Denied to debug.log **/
                if (fDebug)
                {
                    LogPrint("firewall", "%s Denieded: %s\n", Settings::ModuleName.c_str(), pnode->addrName.c_str());
                }

                return true;
            }

        return false;
    }


    /* FUNCTION: Lists::Remove */
    bool Lists::Remove(CNode *pnode, std::string ListType)
    {

        return false;
    }


    /* FUNCTION: Lists::Count */
    int Lists::Count(std::string ListType)
    {

        return false;
    }

    /* FUNCTION: Lists::Clear */
    bool Lists::Clear(std::string ListType)
    {

        return false;
    }


    /* ------------------- */


    /* ------------------- */
    /* Stats Class */

    /* VARIABLES: Average Blockheight among Peers */
    int Stats::AverageHeight = 0;                                            /* Peers Average Block Height */
    int Stats::AverageHeight_Min = 0;                                        /* Peers Average Block Height Minimum Range */
    int Stats::AverageHeight_Max = 0;                                        /* Peers Average Block Height Maximum Range */
    double Stats::AverageTraffic = 0;                                        /* Peers Average Traffic Ratio */
    double Stats::AverageTraffic_Min = 0;                                    /* Peers Average Traffic Ratio Minimum */
    double Stats::AverageTraffic_Max = 0;                                    /* Peers Average Traffic Ratio Maximum */
    int Stats::AverageSend = 0;                                              /* Peers Average Send Bytes */
    int Stats::AverageRecv = 0;                                              /* Peers Average Recv Bytes */

    /* ------------------- */


    /* ------------------- */
    /* LiveDebug Class */

    /* VARIABLES: Firewall Controls (LiveDebug Output) */
    bool LiveDebug::Enabled = GetBoolArg("-fw:livedebug", false);                                       /* True/False */
    bool LiveDebug::Exam = GetBoolArg("-fw:livedebug:exam", true);                                      /* True/False */
    bool LiveDebug::CheckAttack = GetBoolArg("-fw:livedebug:checkattack", true);                        /* True/False */
    bool LiveDebug::Bans = GetBoolArg("-fw:livedebug:bans", true);                                      /* True/False */
    bool LiveDebug::Denied = GetBoolArg("-fw:livedebug:denied", true);                                  /* True/False */
    bool LiveDebug::Disconnect = GetBoolArg("-fw:livedebug:disconnect", true);                          /* True/False */
    bool LiveDebug::BandwidthAbuse = GetBoolArg("-fw:livedebug:bandwidthabuse", true);                  /* True/False */
    bool LiveDebug::DoubleSpend = GetBoolArg("-fw:livedebug:doublespend", true);                        /* True/False */
    bool LiveDebug::InvalidWallet = GetBoolArg("-fw:livedebug:invalidwallet", true);                    /* True/False */
    bool LiveDebug::ForkedWallet = GetBoolArg("-fw:livedebug:forkedwallet", true);                      /* True/False */
    bool LiveDebug::FloodingWallet = GetBoolArg("-fw:livedebug:floodingwallet", true);                  /* True/False */
    bool LiveDebug::DDoSWallet = GetBoolArg("-fw:livedebug:ddoswallet", true);                          /* True/False */
    bool LiveDebug::EclipseWallet = GetBoolArg("-fw:livedebug:eclipsewallet", true);                    /* True/False */
    bool LiveDebug::ErebusWallet = GetBoolArg("-fw:livedebug:erebuswallet", true);                      /* True/False */
    bool LiveDebug::BGPWallet = GetBoolArg("-fw:livedebug:bgpwallet", true);                            /* True/False */
    bool LiveDebug::ResettingSyncWallet = GetBoolArg("-fw:livedebug:resetsyncwallet", true);            /* True/False */

    /* ------------------- */


    /* ------------------- */
    /* BandwidthAbuse Class */

    /* VARIABLES: Firewall Settings (Bandwidth Abuse) */
    bool BandwidthAbuse::Detect = GetBoolArg("-fw:bandwidthabuse:detect", true);                        /* true/false */
    bool BandwidthAbuse::Denied = GetBoolArg("-fw:bandwidthabuse:denied", false);                       /* True/False */
    bool BandwidthAbuse::Ban = GetBoolArg("-fw:bandwidthabuse:ban", false);                             /* True/False */
    int BandwidthAbuse::BanTime = GetArg("-fw:bandwidthabuse:bantime", 0);                              /* 24 hours */
    bool BandwidthAbuse::Disconnect = GetBoolArg("-fw:bandwidthabuse:disconnect", false);               /* True/False */
    int BandwidthAbuse::MinCheck = GetArg("-fw:bandwidthabuse:mincheck", 20);                           /* Seconds */

    /* FUNCTION: BandwidthAbuse::Check */
    std::string BandwidthAbuse::Check(CNode *pnode, int SyncHeight, int TimeConnected)
    {
        std::string AttackCheckName = "Bandwidth Abuse";
        std::string Attack_Type;

        if (BandwidthAbuse::Detect == true)
        {
            /** Determines Node bandwidth abuse based upon calculated
                ratio between Recieved bytes and Sent Bytes
                Compared with the average ratio of all nodes
            **/
            
            /** --------------------------
                Attack Detection
            **/
            if ((int)TimeConnected > BandwidthAbuse::MinCheck)
            {
                /** Node is further ahead on the chain than average minimum **/
                if (SyncHeight > Stats::AverageHeight_Min)
                {
                    if (pnode->nTrafficAverage < Stats::AverageTraffic_Min)
                    {
                        /** too low bandiwidth ratio limits **/
                        Attack_Type = "1-LowBW-HighHeight";
                    }

                    if (pnode->nTrafficAverage > Stats::AverageTraffic_Max)
                    {
                        /** too high bandiwidth ratio limits **/
                        Attack_Type = "2-HighBW-HighHeight";
                    }
                }

                /** Node is behind on the chain than average minimum **/
                if (SyncHeight < Stats::AverageHeight_Min)
                {  
                    if (pnode->nTrafficAverage < Stats::AverageTraffic_Min)
                    {
                        /** too low bandiwidth ratio limits **/
                        Attack_Type = "3-LowBW-LowHeight";
                    }

                    if (pnode->nTrafficAverage > Stats::AverageTraffic_Max)
                    {
                        /** too high bandiwidth ratio limits **/
                        Attack_Type = "4-HighBW-LowHeight";
                    }
                }
            }
            /** -------------------------- **/

            /** -------------------------- 
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::BandwidthAbuse == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Traffic Average: " << pnode->nTrafficAverage << "] " <<
                    "\n" << endl;
            }
            /** -------------------------- **/

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}";
            }
            /** -------------------------- **/
        }

        /** -------------------------- 
            Attack NOT Detected Output
        **/
        return "";
        /** -------------------------- **/
    }
    /* ------------------- */


    /* ------------------- */
    /* DoubleSpend Class */

    /* VARIABLES: Firewall Settings (Double Spend Attack) */
    bool DoubleSpend::Detect = GetBoolArg("-fw:doublespend:detect", true);                              /* True/False */
    bool DoubleSpend::Denied = GetBoolArg("-fw:doublespend:denied", true);                              /* True/False */
    bool DoubleSpend::Ban = GetBoolArg("-fw:doublespend:ban", true);                                    /* True/False */
    int DoubleSpend::BanTime = GetArg("-fw:doublespend:bantime", 0);                                    /* 24 hours */
    bool DoubleSpend::Disconnect = GetBoolArg("-fw:doublespend:disconnect", true);                      /* True/False */
    int DoubleSpend::MinCheck = GetArg("-fw:doublespend:mincheck", 30);                                 /* Seconds */
    double DoubleSpend::MinAttack = 17.1;                                                               /* Traffic Average Ratio Mimumum */
    double DoubleSpend::MaxAttack = 17.2;                                                               /* Traffic Average Ratio Maximum */

    /* FUNCTION: DoubleSpend::Check */
    std::string DoubleSpend::Check(CNode *pnode, int SyncHeight, int TimeConnected, std::string BandwidthAbuse_Output)
    {
        std::string AttackCheckName = "Double Spend Wallet";
        std::string Attack_Type;

        if (DoubleSpend::Detect == true)
        {
            /** -------------------------- 
                Attack Detection
                Calculate the ratio between Recieved bytes and Sent Bytes
                Detect a valid syncronizaion vs. a flood attack
            **/
            if ((int)TimeConnected > DoubleSpend::MinCheck)
            {
                /** Node is ahead on the chain than average minimum **/
                if (SyncHeight > Stats::AverageHeight
                    && pnode->nTrafficAverage > Stats::AverageTraffic_Max
                    )
                {  
                    /** Too high bandiwidth ratio limits
                        Detected by default from above conditions
                    **/
                    Attack_Type = "Pattern Detected"; // By default
                
                    double tnTraffic = pnode->nSendBytes / pnode->nRecvBytes;

                    if (BandwidthAbuse_Output != "2-HighBW-HighHeight")
                    {
                        /** DOES NOT MATCH High bandwidth, High block height (possible 51%)
                            No Attack Detected
                        **/
                        Attack_Type = "";
                    }

                    if (pnode->nTrafficAverage > Stats::AverageTraffic_Min
                        && pnode->nTrafficAverage < Stats::AverageTraffic_Max
                        )
                    {
                        if (tnTraffic < DoubleSpend::MinAttack || tnTraffic > DoubleSpend::MaxAttack)
                        {
                            /** wallet full sync
                                No Attack Detected
                            **/
                            Attack_Type = "";
                        }
                    }                
                }
            }
            /** -------------------------- **/

            /** -------------------------- 
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::DoubleSpend == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Send Bytes: " << pnode->nSendBytes << "] " <<
                    "[Recv Bytes: " << pnode->nRecvBytes << "] " <<
                    "[Traffic Average: " << pnode->nTrafficAverage << "] " <<
                    "\n" << endl;
            }
            /** -------------------------- **/

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}";
            }
            /** -------------------------- **/
        }

        /** -------------------------- 
            Attack NOT Detected Output
        **/
        return "";
        /** -------------------------- **/

    }
    /* ------------------- */


    /* ------------------- */
    /* InvalidWallet Class */

    /* VARIABLES: Firewall Settings (Invalid Peer Wallets) */
    bool InvalidWallet::Detect = GetBoolArg("-fw:invalidwallet:detect", true);                              /* True/False */
    bool InvalidWallet::Denied = GetBoolArg("-fw:invalidwallet:denied", true);                              /* True/False */
    bool InvalidWallet::Ban = GetBoolArg("-fw:invalidwallet:ban", true);                                    /* True/False */
    int InvalidWallet::BanTime = GetArg("-fw:invalidwallet:bantime", 0);                                    /* 24 hours */
    bool InvalidWallet::Disconnect = GetBoolArg("-fw:invalidwallet:disconnect", true);                      /* True/False */
    int InvalidWallet::MinimumProtocol = MIN_PEER_PROTO_VERSION;                                            /* Version */
    int InvalidWallet::MinCheck = GetArg("-fw:invalidwallet:minattack", 120);                               /* Seconds */

    /* FUNCTION: InvalidWallet::Check */
    std::string InvalidWallet::Check(CNode *pnode, int SyncHeight, int TimeConnected)
    {
        std::string AttackCheckName = "Invalid Wallet";
        std::string Attack_Type;

        if (InvalidWallet::Detect == true)
        {
            /** -------------------------- 
                Attack Detection #1 (A)
                Start Height = -1
                Check for more than MinCheck minutes connection length
            **/
            if ((int)TimeConnected > InvalidWallet::MinCheck
                && pnode->nStartingHeight == -1
                )
            {
                /** Detetected **/
                Attack_Type = "1-StartHeight-Invalid";
            }
            /** -------------------------- **/

            /** -------------------------- 
                Attack Detection #1 (B)
                Start Height < 0
                Check for more than MinCheck minutes connection length
            **/
            if ((int)TimeConnected > InvalidWallet::MinCheck
                && pnode->nStartingHeight < 0
                )
            {
                /** Detected **/
                Attack_Type = "1-StartHeight-Invalid";
            }
            /** -------------------------- **/
            
            /** -------------------------- 
                Attack Detection #2 (A)
                Protocol: 0
                Check for more than InvalidWallet::MinCheck minutes connection length
            **/
            if ((int)TimeConnected > InvalidWallet::MinCheck
                && pnode->nRecvVersion == 0
                )
            {
                /** Detected **/
                Attack_Type = "2-Protocol-Invalid";
            }
            /** -------------------------- **/

            /** -------------------------- 
                Attack Detection #2 (B)
                Protocol: lower than 1
                Check for more than InvalidWallet::MinCheck minutes connection length
            **/
            if ((int)TimeConnected > InvalidWallet::MinCheck
                && pnode->nRecvVersion < 1
                )
            {
                /** Detected **/
                Attack_Type = "2-Protocol-Invalid";
            }
            /** -------------------------- **/

            /** -------------------------- 
                Attack Detection #2 (C)
                Protocol: lower than mimimum protocol
                Check for more than InvalidWallet::MinCheck minutes connection length
            **/
            if ((int)TimeConnected > InvalidWallet::MinCheck
                && pnode->nRecvVersion < InvalidWallet::MinimumProtocol
                && pnode->nRecvVersion > 209
                )
            {
                /** Detected **/
                Attack_Type = "2-Protocol-Invalid";
            }
            /** -------------------------- **/

            /** -------------------------- 
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::InvalidWallet == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Start Height: " << pnode->nStartingHeight << "] " <<
                    "[Recv Version: " << pnode->nRecvVersion << "] " <<
                    "\n" << endl;
            }
            //--------------------------

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
            }
        }
        // ----------------

        return ""; // no attack detected

    }
    /* ------------------- */


    /* ------------------- */
    /* ForkedWallet Class */

    /* VARIABLES: Firewall Settings (Forked Wallet) */
    bool ForkedWallet::Detect = GetBoolArg("-fw:forkedwallet:detect", true);                                /* True/False */
    bool ForkedWallet::Denied = GetBoolArg("-fw:forkedwallet:denied", true);                                /* True/False */
    bool ForkedWallet::Ban = GetBoolArg("-fw:forkedwallet:ban", true);                                      /* True/False */
    bool ForkedWallet::Disconnect = GetBoolArg("-fw:forkedwallet:disconnect", true);                        /* True/False */
    int ForkedWallet::BanTime = GetArg("-fw:forkedwallet:bantime", 0);                                      /* 24 hours */
    int ForkedWallet::MinCheck = GetArg("-fw:forkedwallet:minattack", 120);                                 /* Seconds */

    /* VARIABLES: FORKLIST */
    int ForkedWallet::NodeHeight[256] =
    {
        10000,
        39486,
        48405
    };


    /* FUNCTION: ForkedWallet::Check */
    std::string ForkedWallet::Check(CNode *pnode, int SyncHeight, int TimeConnected)
    {
        std::string AttackCheckName = "Forked Wallet";
        std::string Attack_Type;

        if (ForkedWallet::Detect == true)
        {
            /** -------------------------- 
                Attack Detection
                Check for Forked Wallet (stuck on blocks)
            **/
            int i;
            int HeightCount;
            HeightCount = CountIntArray(ForkedWallet::NodeHeight) - 2;
            
            if (HeightCount > 0)
            {
                for (i = 0; i < HeightCount; i++)
                { 
                    if (SyncHeight == (int)ForkedWallet::NodeHeight[i])
                    {
                        Attack_Type = (int)ForkedWallet::NodeHeight[i];
                    }
                }          
            }
            /** -------------------------- **/

            /** -------------------------- 
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::ForkedWallet == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "\n" << endl;
            }
            /** -------------------------- **/

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}";
            }
            /** -------------------------- **/
        }

        /** -------------------------- 
            Attack NOT Detected Output
        **/
        return "";
        /** -------------------------- **/

    }
    /* ------------------- */


    /* ------------------- */
    /* FloodingWallet Class */

    /* VARIABLES: Firewall Settings (Flooding Peer Wallets) */
    bool FloodingWallet::Detect = GetBoolArg("-fw:floodingwallet:detect", true);                            /* True/False */
    bool FloodingWallet::Denied = GetBoolArg("-fw:floodingwallet:denied", true);                            /* True/False */
    bool FloodingWallet::Ban = GetBoolArg("-fw:floodingwallet:ban", true);                                  /* True/False */
    int FloodingWallet::BanTime = GetArg("-fw:forkedwallet:bantime", 2600000);                              /* 30 days */
    bool FloodingWallet::Disconnect = GetBoolArg("-fw:floodingwallet:disconnect", true);                    /* True/False */
    uint64_t FloodingWallet::MinBytes = GetArg("-fw:forkedwallet:minbytes", 1000000);                       /* 1 MB Minimum Bytes */
    uint64_t FloodingWallet::MaxBytes = GetArg("-fw:forkedwallet:maxbytes", 10000000);                      /* 10 MB Maximum Bytes */
    double FloodingWallet::MinTrafficAverage = GetArg("-fw:forkedwallet:mintrafficavg", 2000);              /* Ratio Up/Down Minimum */
    double FloodingWallet::MaxTrafficAverage = GetArg("-fw:forkedwallet:maxtrafficavg", 2000);              /* Ratio Up/Down Maximum */
    int FloodingWallet::MinCheck = GetArg("-fw:forkedwallet:mincheck", 30);                                 /* 30 Seconds Minimum */
    int FloodingWallet::MaxCheck = GetArg("-fw:forkedwallet:maxcheck", 90);                                 /* 90 Seconds Maximum */

    /* VARIABLES (Array): Flooding Wallet Attack Patterns */
    std::string FloodingWallet::Patterns[256] =
    {
        "~1~4~6~8~10~12~15~17~18~20~22~27~{Bandwidth Abuse:4-HighBW-LowHeight}",
        "~1~5~6~8~10~12~15~17~18~19~22~27~{Bandwidth Abuse:4-HighBW-LowHeight}",
        "~1~2~3~4~6~8~10~12~15~17~18~19~22~27",
        "~1~4~6~8~10~12~15~17~18~19~22~27",
        "~1~2~3~4~6~9~11~13~15~17~18~20~22~27"
    };

    /* VARIABLES (Array): Flooding Wallet Ignored Patterns */
    std::string FloodingWallet::Ignored[256] =
    {

    };

    /* FUNCTION: FloodingWallet::Check */
    std::string FloodingWallet::Check(CNode *pnode, int SyncHeight, bool DetectedAttack, int TimeConnected, std::string BandwidthAbuse_Output)
    {
        std::string AttackCheckName = "Flooding Wallet";
        std::string Attack_Type;
        std::string Warnings;

        if (FloodingWallet::Detect == true)
        {
            /** -------------------------- 
                WARNING #1
                Too high of bandwidth with low BlockHeight
            **/
            if (SyncHeight < Stats::AverageHeight_Min)
            {  
                if (pnode->nStartingHeight > Stats::AverageTraffic_Max)
                {
                    Warnings = Warnings + "~1";
                }
            }
            /** -------------------------- **/
            
            /** -------------------------- 
                WARNING #2
                Send Bytes below minimum
            **/
            if (pnode->nSendBytes < FloodingWallet::MinBytes)
            {
                Warnings = Warnings + "~2";
            }
            /** -------------------------- **/

            /** -------------------------- 
                WARNING #3
                Send Bytes above minimum
            **/
            if (pnode->nSendBytes < FloodingWallet::MinBytes)
            {
                Warnings = Warnings + "~3";
            }
            /** -------------------------- **/

            /** -------------------------- 
                WARNING #4
                Send Bytes below maximum
            **/
            if (pnode->nSendBytes < FloodingWallet::MaxBytes)
            {
                Warnings = Warnings + "~4";
            }
            /** -------------------------- **/

            /** -------------------------- 
                WARNING #5
                Send Bytes above maximum
            **/
            if (pnode->nSendBytes > FloodingWallet::MaxBytes)
            {
                Warnings = Warnings + "~5";
            }
            /** -------------------------- **/

            /** -------------------------- 
                WARNING #6
                Recv Bytes above min 
            **/
            if (pnode->nRecvBytes > FloodingWallet::MinBytes / 2)
            {
                Warnings = Warnings + "~6";
            }
            /** ------------------------- **/

            /** -------------------------- 
                WARNING #7
                Recv Bytes below min
            **/
            if (pnode->nRecvBytes < FloodingWallet::MinBytes / 2)
            {
                Warnings = Warnings + "~7";
            }
            /** ------------------------- **/

            /** -------------------------- 
                WARNING #8
                Recv Bytes above max 
            **/
            if (pnode->nRecvBytes > FloodingWallet::MaxBytes / 2)
            {
                Warnings = Warnings + "~8";
            }
            /** ------------------------- **/

            /** -------------------------- 
                WARNING #9
                Recv Bytes below max
            **/
            if (pnode->nRecvBytes < FloodingWallet::MaxBytes / 2)
            {
                Warnings = Warnings + "~9";
            }
            /** ------------------------- **/

            /** -------------------------- 
                WARNING #10
                Recv Bytes above min 
            **/
            if (pnode->nSendBytes > FloodingWallet::MinBytes / 2)
            {
                Warnings = Warnings + "~10";
            }

            /** -------------------------- 
                WARNING #11
                Recv Bytes below min
            **/
            if (pnode->nSendBytes < FloodingWallet::MinBytes / 2)
            {
                Warnings = Warnings + "~11";
            }
            /** ------------------------- **/

            /** -------------------------- 
                WARNING #12
                Recv Bytes above max 
            **/
            if (pnode->nSendBytes > FloodingWallet::MinBytes / 2)
            {
                Warnings = Warnings + "~12";
            }
            /** ------------------------- **/

            /** -------------------------- 
                WARNING #13
                Recv Bytes below max
            **/
            if (pnode->nSendBytes < FloodingWallet::MinBytes / 2)
            {
                Warnings = Warnings + "~13";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #14
                Node Traffic Average is bigger than Minimum Traffic Average set for FloodingWallet
            **/
            if (pnode->nTrafficAverage > FloodingWallet::MinTrafficAverage)
            {
                Warnings = Warnings + "~14";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #15
                Node Traffic Average is smaller than Minimum Traffic Average set for FloodingWallet
            **/
            if (pnode->nTrafficAverage < FloodingWallet::MinTrafficAverage)
            {
                Warnings = Warnings + "~15";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #16
                Node Traffic Average is bigger than MaximumTraffic Average set for FloodingWallet
            **/
            if (pnode->nTrafficAverage > FloodingWallet::MaxTrafficAverage)
            {
                Warnings = Warnings + "~16";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #17
                Node Traffic Average is smaller than Maximum Traffic Average set for FloodingWallet
            **/
            if (pnode->nTrafficAverage < FloodingWallet::MaxTrafficAverage)
            {
                Warnings = Warnings + "~17";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #18
                Starting Height = SyncHeight above max
            **/
            if (pnode->nStartingHeight == SyncHeight)
            {
                Warnings = Warnings + "~18";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #19
                Connected Time above min
            **/
            if ((int)TimeConnected > FloodingWallet::MinCheck * 60)
            {
                Warnings = Warnings + "~19";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #20 - Connected Time below min
            **/
            if ((int)TimeConnected < FloodingWallet::MinCheck * 60)
            {
                Warnings = Warnings + "~20";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #21 - Connected Time above max
            **/
            if ((int)TimeConnected > FloodingWallet::MaxCheck * 60)
            {
                Warnings = Warnings + "~21";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #22 - Connected Time below max
            **/
            if ((int)TimeConnected < FloodingWallet::MaxCheck * 60)
            {
                Warnings = Warnings + "~22";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #23 - Current BlockHeight
            **/
            if (SyncHeight > Stats::AverageHeight)
            {  
                if (SyncHeight < Stats::AverageHeight_Max)
                {  
                    Warnings = Warnings + "~23";
                }
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #24 - Sync Height is small than Average Height Max
            **/
            if (SyncHeight < Stats::AverageHeight_Max)
            {
                if (SyncHeight > Stats::AverageHeight_Min)
                {
                    Warnings = Warnings + "~24";
                }
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #25 - Previously Detected Attack during CheckAttack()
            **/
            if (DetectedAttack == true)
            {
                Warnings = Warnings + "~25";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #26 - Invalid Packets
            **/
            if (pnode->nInvalidRecvPackets > 0)
            {
                Warnings = Warnings + "~26";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #27 - ChainBuddy (Has consensus)
            **/
            if (Consensus::ChainBuddy::WalletHasConsensus() == false)
            {
                Warnings = Warnings + "~27";
            }
            /** ------------------------- **/

            /** --------------------------
                WARNING #28 - ChainBuddy (Has consensus)
            **/
            /**
            if (Consensus::ChainBuddy::NodeHasConsensus(pnode) == false)
            {
                Warnings = Warnings + "~28";
            }
            **/
            /** ------------------------- **/

            /** --------------------------
                WARNING #29 - Output from BandwidthAbuse_Check()
            **/
            if (BandwidthAbuse_Output != "")
            {
                Warnings = Warnings + "~" + BandwidthAbuse_Output;
            }
            /** ------------------------- **/

            /** --------------------------
                Auto-Trigger Flooding Patterns
                IF Warnings is matched to pattern DetectedAttack = TRUE
            **/
            int i;
            int PatternsCount;

            PatternsCount = CountStringArray(FloodingWallet::Patterns);

            if (PatternsCount > 0)
            {
                for (i = 0; i < PatternsCount; i++)
                {  
                    if (FloodingWallet::Patterns[i] != ""
                        && Warnings == FloodingWallet::Patterns[i]
                        )
                    {
                        Attack_Type = Warnings;
                    }
                }
            }
            /** ------------------------- **/

            /** --------------------------
                Ignore Flooding Patterns
                IF Warnings is matched to pattern Attack_Detected = FALSE
            **/
            int IgnoredCount;

            IgnoredCount = CountStringArray(FloodingWallet::Ignored);

            if (IgnoredCount > 0)
            {
                for (i = 0; i < IgnoredCount; i++)
                {  
                    if (FloodingWallet::Ignored[i] != ""
                        && Warnings == FloodingWallet::Ignored[i]
                        )
                    {

                        Attack_Type = "";
                    }
                }
            }
            /** ------------------------- **/

            /** --------------------------
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::FloodingWallet == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Start Height: " << pnode->nStartingHeight << "] " <<
                    "[Prev Detected: " << DetectedAttack << "] " <<
                    "[Send Bytes: " << pnode->nSendBytes << "] " <<
                    "[Recv Bytes: " << pnode->nRecvBytes << "] " <<
                    "[Traffic Average: " << pnode->nTrafficAverage << "] " <<
                    "[Warnings: " << Warnings << "] " <<
                    "\n" << endl;
            }
            /** ------------------------- **/

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}";
            }
            /** ------------------------- **/
        }

        /** -------------------------- 
            Attack NOT Detected Output
        **/
        return "";
        /** ------------------------- **/
    }
    /* ------------------- */

    /* ------------------- */
    /* DDoSWallet Class */

    /* VARIABLES: Firewall Settings (DDOS Wallet) */
    bool DDoSWallet::Detect = GetBoolArg("-fw:ddoswallet:detect", true);                                    /* True/False                                           */
    bool DDoSWallet::Denied = GetBoolArg("-fw:ddoswallet:denied", true);                                    /* True/False                                           */
    bool DDoSWallet::Ban = GetBoolArg("-fw:ddoswallet:ban", true);                                          /* True/False                                           */
    int DDoSWallet::BanTime = GetArg("-fw:ddoswallet:bantime", 0);                                          /* 24 hours                                             */
    bool DDoSWallet::Disconnect = GetBoolArg("-fw:ddoswallet:disconnect", true);                            /* True/False                                           */
    int DDoSWallet::MinCheck = GetArg("-fw:ddoswallet:mincheck", 120);                                      /* 30 Seconds                                           */

    /* FUNCTION: DDoSWallet::Check */
    std::string DDoSWallet::Check(CNode *pnode, int TimeConnected, std::string BandwidthAbuse_Output)
    {
        std::string AttackCheckName = "DDoS Wallet";
        std::string Attack_Type;

        if (DDoSWallet::Detect == true)
        {
            /** --------------------------
                Attack Detection
                Simple DDoS using invalid P2P packets/commands
            **/

            if ((int)TimeConnected > DDoSWallet::MinCheck)
            {
                if (pnode->nInvalidRecvPackets > 0
                    && pnode->nRecvBytes / 1000 > 0
                    )
                {
                    double InvalidPacketRatio = (pnode->nInvalidRecvPackets / (pnode->nRecvBytes / 1000));

                    if (InvalidPacketRatio > 1)
                    {
                        Attack_Type = "Invalid Packets";
                    }
                }
            }

            /** ------------------------- **/

            /** --------------------------
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::DDoSWallet == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Invalid Packets: " << pnode->nInvalidRecvPackets << "] " <<
                    "[Recv Bytes: " << pnode->nRecvBytes << "] " <<
                    "\n" << endl;
            }
            /** ------------------------- **/

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}";
            }
            /** ------------------------- **/
        }

        /** -------------------------- 
            Attack NOT Detected Output
        **/
        return "";
        /** ------------------------- **/
    }


    /* ------------------- */
    /* EclipseWallet Class */
    bool EclipseWallet::Detect = GetBoolArg("-fw:eclipsewallet:detect", true);                                      /* True/False */
    bool EclipseWallet::Denied = GetBoolArg("-fw:eclipsewallet:denied", true);                                      /* True/False */
    bool EclipseWallet::Ban = GetBoolArg("-fw:eclipsewallet:ban", true);                                            /* True/False */
    int EclipseWallet::BanTime = GetArg("-fw:eclipsewallet:bantime", 0);                                            /* 24 hours */
    bool EclipseWallet::Disconnect = GetBoolArg("-fw:eclipsewallet:disconnect", true);                              /* True/False */
    int EclipseWallet::MinCheck = GetArg("-fw:eclipsewallet:mincheck", 30);                                         /* 30 Seconds */

    /* FUNCTION: EclipseWallet::Check */
    std::string EclipseWallet::Check(CNode *pnode, int SyncHeight, int TimeConnected)
    {
        std::string AttackCheckName = "Eclipse";
        std::string Attack_Type;

        if (EclipseWallet::Detect == true)
        {
            /** -------------------------- 
                Eclipse Attack

                This attack allows an adversary controlling a sufficient number of IP addresses to monopolize all connections
                Whitepaper Report: https://eprint.iacr.org/2015/263.pdf
                Discovered by: Ethan Heilman, Alison Kendler, Aviv Zohar, Sharon Goldberg, Hebrew University/MSR Israel

                See: doc/Firewall.txt for more information

                Related source code patches (Bitcoin Core 10):
                    https://github.com/bitcoin/bitcoin/pull/6355/commits/caad33fb232b7d217a3f218ba50f8dd299cd41a6
                    https://github.com/bitcoin/bitcoin/pull/9037
                    https://github.com/bitcoin/bitcoin/pull/8282
                    https://github.com/sickpig/BitcoinUnlimited/commit/562fe5d41760c3accb1222df73895ca655693ddf
                    https://github.com/bitcoin/bitcoin/pull/6355
                    https://github.com/bitcoin/bitcoin/pull/6355/commits/caad33fb232b7d217a3f218ba50f8dd299cd41a6
                    https://github.com/bitcoin/bitcoin/issues/8470
                    https://github.com/bitcoin/bitcoin/commit/a36834f10b80cd349ed35e4d2a04c50a8e02f269
                    https://github.com/bitcoin/bitcoin/commit/e1d6e2af6d89935f6edf027e5d4ea1d2ec6c7f41
                    https://github.com/bitcoin/bitcoin/pull/6355/commits/caad33fb232b7d217a3f218ba50f8dd299cd41a6


                Attack identification (Biznatch Enterprises)

                1- Detect peer attempting to fill connection slot by connecting, disconnecting but sending no data
                2- Detect peer with signature of #1 and sending ADDR msg then shortly after disconnecting
                3- hashAskedFor equals  uint256 NullHash


                DRAFT only
                if ((int)TimeConnected > Eclipse)
                {
                    std::vector<int, EclipseMap::PeerMap>::iterator it;

                    it = std::find (PeerMap.begin(), PeerMap.end(), ser);

                    if (it != PeerMap.end()) 
                    { 
                        // Update Existing Peer entry in the PeerMap
                        // Position: it - PeerMap.begin() + 1
                    }
                    else
                    {
                        // Add new peer entry in the PeerMap

                    }
                }

            */
            /** -------------------------- **/

            /** -------------------------- 
                Detection & Mitigation
            **/
            
            //Attack_Type = "Invalid Packets";

            /** -------------------------- **/

            /** -------------------------- 
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::EclipseWallet == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Start Height: " << pnode->nStartingHeight << "] " <<
                    "[Recv Version: " << pnode->nRecvVersion << "] " <<
                    "\n" << endl;
            }
            //--------------------------

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
            }
        }
        // ----------------

        return ""; // no attack detected

    }
    /* ------------------- */


    /* ------------------- */
    /* ErebusWallet Class */
    bool ErebusWallet::Detect = GetBoolArg("-fw:erebuswallet:detect", true);                                            /* True/False */
    bool ErebusWallet::Denied = GetBoolArg("-fw:erebuswallet:denied", true);                                            /* True/False */
    bool ErebusWallet::Ban = GetBoolArg("-fw:erebuswallet:ban", true);                                                  /* True/False */
    int ErebusWallet::BanTime = GetArg("-fw:erebuswallet:bantime", 0);                                                  /* 24 hours */
    bool ErebusWallet::Disconnect = GetBoolArg("-fw:erebuswallet:bantime", true);                                       /* True/False */
    int ErebusWallet::MinCheck = GetArg("-fw:erebuswallet:mincheck", 30);                                               /* 30 Seconds */

    /* FUNCTION: Erebus::Check */
    std::string ErebusWallet::Check(CNode *pnode, int SyncHeight, int TimeConnected)
    {
        std::string AttackCheckName = "Erebus";
        std::string Attack_Type;

        if (ErebusWallet::Detect == true)
        {
            /** -------------------------- 
                Erebus Attack

                Allows large malicious Internet Service Providers (ISPs) to isolate any targeted public nodes from the peer-to-peer network
                Report: https://erebus-attack.comp.nus.edu.sg/erebus-attack.pdf
                Discovered by: Muoi Tran, Inho Choi, Gi Jun Moon, Anh V. Vu, Min Suk Kang (National University of Singapore, Korea University,
                Japan Advanced Institute of Science and Technolog)

                See: doc/Firewall.txt for more information

                Related source code patches (Bitcoin Core 20):
                    https://github.com/bitcoin/bitcoin/pull/16702
                    https://github.com/naumenkogs/bitcoin/tree/asn_buckets

                Proposed patches:

                Development patches:
                    https://stackoverflow.com/questions/15458438/implementing-traceroute-using-icmp-in-c

            **/

            /*
            if ((int)TimeConnected > InvalidWallet_MinCheck)
            {
                PeerPrefixMap

                // check connections for duplicate prefixes

                // check addr log for duplicate prefixes

            }
            */

            /** -------------------------- **/          

            /** -------------------------- 
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::ErebusWallet == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Start Height: " << pnode->nStartingHeight << "] " <<
                    "[Recv Version: " << pnode->nRecvVersion << "] " <<
                    "\n" << endl;
            }
            //--------------------------

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
            }
        }
        // ----------------

        return ""; // no attack detected

    }
    /* ------------------- */


    /* ------------------- */
    /* BGPWallet Class */
    bool BGPWallet::Detect = GetBoolArg("-fw:bgpwallet:detect", true);                                                  /* True/False */
    bool BGPWallet::Denied = GetBoolArg("-fw:bgpwallet:denied", true);                                                  /* True/False */
    bool BGPWallet::Ban = GetBoolArg("-fw:bgpwallet:ban", true);                                                        /* True/False */
    int BGPWallet::BanTime = GetArg("-fw:bgpwallet:bantime", 0);                                                        /* 24 hours */
    bool BGPWallet::Disconnect = GetBoolArg("-fw:bgpwallet:disconnect", true);                                          /* True/False */
    int BGPWallet::MinCheck = GetArg("-fw:bgpwallet:minbytes", 30);                                                     /* 30 Seconds */

    /* FUNCTION: BGPWallet::Check */
    std::string BGPWallet::Check(CNode *pnode, int SyncHeight, int TimeConnected)
    {
        std::string AttackCheckName = "BGP";
        std::string Attack_Type;

        if (BGPWallet::Detect == true)
        {
            /** -------------------------- 
                BGP Protection (Apostolaki Hijack)

                By manipulating routing advertisements (BGP hijacks) or by naturally intercepting traffic, Autonomous Systems (ASes) can intercept
                and manipulate a large fraction of Bitcoin traffic
                Whitepaper Report: https://btc-hijack.ethz.ch/files/btc_hijack.pdf
                Discovered by: Maria Apostolaki, Aviv Zohar, Laurent Vanbever (The Hebrew University, ETH Zürich)

                See: doc/Firewall.txt for more information
            **/

            /* Firewall detections & mitigation



            */

            /*
            if ((int)TimeConnected > InvalidWallet_MinCheck)
            {

                uint256 hashAskedFor;
                uint256 hashReceived;
                int BGPWarnings;

            }
            */

            /** -------------------------- **/        

            /** -------------------------- 
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::BGPWallet == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Start Height: " << pnode->nStartingHeight << "] " <<
                    "[Recv Version: " << pnode->nRecvVersion << "] " <<
                    "\n" << endl;
            }
            //--------------------------

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
            }
        }
        // ----------------

        return ""; // no attack detected

    }
    /* ------------------- */


    /* ------------------- */
    /* ResettingSyncWallet Class */
    bool ResettingSyncWallet::Detect = GetBoolArg("-fw:resetsyncwallet:detect", true);                                  /* True/False */
    bool ResettingSyncWallet::Denied = GetBoolArg("-fw:resetsyncwallet:denied", true);                                  /* True/False */
    bool ResettingSyncWallet::Ban = GetBoolArg("-fw:resetsyncwallet:ban", true);                                        /* True/False */
    int ResettingSyncWallet::BanTime = GetArg("-fw:resetsyncwallet:bantime", 0);                                        /* 24 hours */
    bool ResettingSyncWallet::Disconnect = GetBoolArg("-fw:resetsyncwallet:disconnect", true);                          /* True/False */
    int ResettingSyncWallet::MinCheck = GetArg("-fw:resetsyncwallet:mincheck", 30);                                     /* 30 Seconds */

    /* FUNCTION: ResettingSyncAttack */
    std::string ResettingSyncWallet::Check(CNode *pnode, int SyncHeight, int TimeConnected)
    {
        std::string AttackCheckName = "ResettingSync";
        std::string Attack_Type;

        if (ResettingSyncWallet::Detect == true)
        {
            /** -------------------------- 
                Attack Detection #7
                NOT USED
                Resetting sync Height
            **/
            /**
            if (TimeConnected > 60)
            {
                if (pnode->nSyncHeight > pnode->nSyncHeightCache)
                {
                    pnode->nSyncHeightCache = pnode->nSyncHeight;
                }

                if (pnode->nSyncHeight < pnode->nSyncHeightCache - AVERAGE_RANGE)
                {
                    Trigger Denied
                    ATTACK_TYPE = "4-SyncReset";
                }

            }
            **/
            /** -------------------------- **/

            /** -------------------------- 
                Live Debug Output
            **/
            if (LiveDebug::Enabled == true
                && LiveDebug::ResettingSyncWallet == true
                )
            {
                cout << Settings::ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Start Height: " << pnode->nStartingHeight << "] " <<
                    "[Recv Version: " << pnode->nRecvVersion << "] " <<
                    "\n" << endl;
            }
            //--------------------------

            /** -------------------------- 
                Attack Detected Output
            **/
            if (Attack_Type != "")
            {
                return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
            }
        }
        // ----------------

        return ""; // no attack detected

    }
    /* ------------------- */


    /* ------------------- */
    /* HighBanScoreCheck Class */

    /* FUNCTION: HighBanScoreCheck
    NOT USED!
    */
    /*
    string HighBanScoreCheck()
    {
        if (DETECT_HIGH_BANSCORE == true)
        {
            Attack_Detected = false;

            nMisbehavior
            checkbanned function integration *todo*

            if (Attack_Detected == true)
            {
                if (Denied_HIGH_BANSCORE == true)
                {
                    Attack_Denied = true;
                }

                if (BAN_HIGH_BANSCORE == true)
                {
                    Attack_Ban = true;
                    Attack_BanTime = BANTIME_HIGH_BANSCORE;
                }

            }
        }
    }
    */
    /* ------------------- */


    /* ------------------- */
    /* Operations Class */

    /* FUNCTION: Operations::ForceDisconnectNode */
    bool Operations::ForceDisconnectNode(CNode *pnode, string FromFunction)
    {
        TRY_LOCK(pnode->cs_vSend, lockSend);

        if (lockSend)
        {
            /** release outbound grant (if any) **/
            pnode->CloseSocketDisconnect();

            if (fDebug)
            {
                LogPrint("firewall", "%s (%s) Panic Disconnect: %s\n", Settings::ModuleName.c_str(), FromFunction, pnode->addrName.c_str());
            }

            if (LiveDebug::Enabled == true
                && LiveDebug::Disconnect == true
                )
            {
                cout << Settings::ModuleName << " Panic Disconnect: " << pnode->addrName << "]\n" << endl;
            }

            return true;

        }
        else
        {
            pnode->vSendMsg.end();
        }

        return false;
    }

    /* FUNCTION: AddBan */
    bool Operations::AddBan(CNode *pnode, BanReason BannedFor, int BanTime)
    {
        CNode::Ban(pnode->addr, BannedFor, BanTime, false);

        if (fDebug)
        {
            LogPrint("firewall", "%s Banned: %s\n", Settings::ModuleName.c_str(), pnode->addrName);
        }

        if (LiveDebug::Enabled == true)
        {
            if (LiveDebug::Bans == true)
            {
                cout << Settings::ModuleName << " Banned: " << pnode->addrName << "]\n" << endl;
            }
        }

        return true;
    }

    /* FUNCTION: AddDenied */
    bool Operations::AddDenied(CNode *pnode)
    {
        // TO FINISH

        return false;
    }

    /* FUNCTION: Operations::CheckBanned */
    bool Operations::CheckBanned(CNode *pnode)
    {
        if (CNode::IsBanned(pnode->addr) == true)
        {
            // Yes Node is Banned!
            return true;
        }

        // No Banned!
        return false;
    }

    /* FUNCTION: CheckDenied */
    bool Operations::CheckDenied(CNode *pnode)
    {
        // TO FINISH

        return false;
    }

    /* ------------------- */


    /* ------------------- */
    /* Monitoring Class */

    /* FUNCTION: LegacySyncHeight */
    int Monitoring::LegacySyncHeight(CNode *pnode)
    {
        /** Is the tx in a block that's in the main chain
            ppcoin: known sent sync-checkpoint 
        **/

        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pnode->hashCheckpointKnown);

        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;

            if (pindex && pindex->IsInMainChain())
            {
                return pindex->nHeight; 
            }
        }

        return 0;
    }


    /* FUNCTION: CheckAttack
        Artificially Intelligent Attack Detection & Mitigation
    */
    bool Monitoring::CheckAttack(CNode *pnode, string FromFunction)
    {
        bool Attack_Detected = false;
        bool Attack_Denied = false;
        int Attack_BanTime = 0; /** Default 24 hours **/
        bool Attack_Ban = false;
        bool Attack_Disconnect = false;

        BanReason Attack_BanReason{};

        string Attack_CheckLog;
        string LIVE_DEBUG_LOG;

        int TimeConnected = GetTime() - pnode->nTimeConnected; // In seconds


        /** -------------------------- 
            Sync Height
        **/
        int SyncHeight;

        SyncHeight = pnode->dCheckpointRecv.height; /** Use Dynamic Checkpoints by default **/

        if (SyncHeight == 0)
        {
            SyncHeight = Monitoring::LegacySyncHeight(pnode); /** ppcoin: known sent sync-checkpoint **/
        }

        if (SyncHeight == 0)
        {
            SyncHeight = pnode->nStartingHeight;
        }

        if (SyncHeight < pnode->nStartingHeight)
        {
            SyncHeight = pnode->nStartingHeight;
        }
        /** -------------------------- **/
    

        /** -------------------------- 
            Bandwidth Abuse Check & Attack Mitigation
        **/
        std::string Attack_BandwidthAbuse = BandwidthAbuse::Check(pnode, SyncHeight, TimeConnected);

        if (Attack_BandwidthAbuse != "")
        {
            if (BandwidthAbuse::Denied == true)
            {
                Attack_Denied = true;
                Attack_Detected = true;
            }

            if (BandwidthAbuse::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = BandwidthAbuse::BanTime;
                Attack_BanReason = BanReasonBandwidthAbuse;
                Attack_Detected = true;
            }

            if (BandwidthAbuse::Disconnect == true)
            {
                Attack_Disconnect = true;
                Attack_Detected = true;
            }

            /** -------------------------- **/
            // Low Bandwidth Mode
            // Override default Attack settings
            // Protocol: lower than mimimum protocol (// 30 Seconds)
            if (GetBoolArg("-lowbandwidth", false) == true)
            {
                if (Attack_BandwidthAbuse == "2-HighBW-HighHeight"
                    || Attack_BandwidthAbuse == "4-HighBW-LowHeight"
                    || (int)TimeConnected > BandwidthAbuse::MinCheck
                    )
                {
                    if (pindexBest->nHeight - pnode->nStartingHeight > 1000)
                    {
                        Attack_Ban = true;
                        Attack_BanTime = BandwidthAbuse::BanTime;
                        Attack_BanReason = BanReasonBandwidthAbuse;
                        Attack_Detected = true;
                    }
                }             
            }

            /** -------------------------- **/

            Attack_CheckLog = Attack_CheckLog + Attack_BandwidthAbuse;
        }
        /** -------------------------- **/


        /** -------------------------- 
            Double Spend Check & Attack Mitigation
        **/
        std::string Attack_Output = DoubleSpend::Check(pnode, SyncHeight, TimeConnected, Attack_BandwidthAbuse);
        
        if (Attack_Output != "")
        {
            if (DoubleSpend::Denied == true)
            {
                Attack_Denied = true;
            }

            if (DoubleSpend::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = DoubleSpend::BanTime;
                Attack_BanReason = BanReasonDoubleSpendWallet;
            }

            if (DoubleSpend::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/


        /** -------------------------- 
            Invalid Wallet Check & Attack Mitigation
        **/
        Attack_Output = InvalidWallet::Check(pnode, SyncHeight, TimeConnected);
        
        if (Attack_Output != "")
        {
            if (InvalidWallet::Denied == true)
            {
                Attack_Denied = true;
            }

            if (InvalidWallet::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = InvalidWallet::BanTime;
                Attack_BanReason = BanReasonInvalidWallet;
            }

            if (InvalidWallet::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/


        /** -------------------------- 
            Forked Wallet Check & Attack Mitigation
        **/
        Attack_Output = ForkedWallet::Check(pnode, SyncHeight, TimeConnected);
        
        if (Attack_Output != "")
        {
            if (ForkedWallet::Denied == true)
            {
                Attack_Denied = true;
            }

            if (ForkedWallet::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = ForkedWallet::BanTime;
                Attack_BanReason = BanReasonForkedWallet;
            }

            if (ForkedWallet::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/


        /** -------------------------- 
            Flooding Wallet Check & Attack Mitigation
        **/
        Attack_Output = FloodingWallet::Check(pnode, SyncHeight, Attack_Detected, TimeConnected, Attack_BandwidthAbuse);
        
        if (Attack_Output != "")
        {
            if (FloodingWallet::Denied == true)
            {
                Attack_Denied = true;
            }

            if (FloodingWallet::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = FloodingWallet::BanTime;
                Attack_BanReason = BanReasonFloodingWallet;
            }

            if (FloodingWallet::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/


        /** -------------------------- 
            DDoS Check & Attack Mitigation ###
        **/
        Attack_Output = DDoSWallet::Check(pnode, TimeConnected, Attack_BandwidthAbuse);
        
        if (Attack_Output != "")
        {
            if (DDoSWallet::Denied == true)
            {
                Attack_Denied = true;
            }

            if (DDoSWallet::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = DDoSWallet::BanTime;
                Attack_BanReason = BanReasonDDoSWallet;
            }

            if (DDoSWallet::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/


        /** -------------------------- 
            Eclipse & Attack Mitigation ###
        **/
        Attack_Output = EclipseWallet::Check(pnode, SyncHeight, TimeConnected);
        
        if (Attack_Output != "")
        {
            if (EclipseWallet::Denied == true)
            {
                Attack_Denied = true;
            }

            if (EclipseWallet::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = EclipseWallet::BanTime;
                Attack_BanReason = BanReasonEclipseWallet;
            }

            if (EclipseWallet::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/


        /** -------------------------- 
        Erebus Mitigation ###
        **/
        Attack_Output = ErebusWallet::Check(pnode, SyncHeight, TimeConnected);
        
        if (Attack_Output != "")
        {
            if (ErebusWallet::Denied == true)
            {
                Attack_Denied = true;
            }

            if (ErebusWallet::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = ErebusWallet::BanTime;
                Attack_BanReason = BanReasonErebusWallet;
            }

            if (ErebusWallet::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/    


        /** -------------------------- 
        BGP Wallet Mitigation ###
        **/
        Attack_Output = BGPWallet::Check(pnode, SyncHeight, TimeConnected);
        
        if (Attack_Output != "")
        {
            if (BGPWallet::Denied == true)
            {
                Attack_Denied = true;
            }

            if (BGPWallet::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = BGPWallet::BanTime;
                Attack_BanReason = BanReasonBGPWallet;
            }

            if (BGPWallet::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/    

        // Slowloris Attack
        // https://arxiv.org/pdf/1808.05357.pdf


        /** -------------------------- 
        ResettingSyncWallet Mitigation ###
        **/
        Attack_Output = ResettingSyncWallet::Check(pnode, SyncHeight, TimeConnected);
        
        if (Attack_Output != "")
        {
            if (DDoSWallet::Denied == true)
            {
                Attack_Denied = true;
            }

            if (DDoSWallet::Ban == true)
            {
                Attack_Ban = true;
                Attack_BanTime = DDoSWallet::BanTime;
                Attack_BanReason = BanReasonResettingSyncWallet;
            }

            if (DDoSWallet::Disconnect == true)
            {
                Attack_Disconnect = true;
            }

            Attack_Detected = true;
            Attack_CheckLog = Attack_CheckLog + Attack_Output;
        }
        /** -------------------------- **/    


        /** -------------------------- 
            ATTACK DETECTED (TRIGGER)
        **/
        if (Attack_Detected == true)
        {
            if (Attack_CheckLog != "")
            {
                /** -------------------------- 
                    Live Debug Output
                **/
                if (LiveDebug::Enabled == true)
                {
                    if (LiveDebug::CheckAttack == true)
                    {
                        cout << Settings::ModuleName <<
                        " [Attack Node: " << Attack_CheckLog <<
                        "] [Detected from: " << pnode->addrName <<
                        "] [Node Traffic: " << pnode->nTrafficRatio <<
                        "] [Node Traffic Avrg: " << pnode->nTrafficAverage <<
                        "] [Traffic Avrg: " << Stats::AverageTraffic <<
                        "] [Sent Bytes: " << pnode->nSendBytes <<
                        "] [Recv Bytes: " << pnode->nRecvBytes <<
                        "] [Start Height: " << pnode->nStartingHeight <<
                        "] [Sync Height: " << SyncHeight <<
                        "] [Protocol: " << pnode->nRecvVersion <<
                        "] [HashAskedFor: " << pnode->hashAskedFor.ToString() <<
                        "] [HashReceived: " << pnode->hashReceived.ToString() <<
                        "]\n" << endl;
                    }
                }
                /** -------------------------- **/

                /** -------------------------- 
                    Debug Log Output
                **/
                if (fDebug)
                {
                    LogPrint("firewall", "%s [Attack Node: %s] "
                                            "[Detected from: %s] "
                                            "[Node Traffic: %d] "
                                            "[Node Traffic Avrg: %d] "
                                            "[Traffic Avrg: %d] "
                                            "[Sent Bytes: %d] "
                                            "[Recv Bytes: %d] "
                                            "[Start Height: %i] "
                                            "[Sync Height: %i] "
                                            "[Protocol: %i] "
                                            "[HashAskedFor: %i] "
                                            "[HashReceived: %i] "
                                            "\n",

                                            Settings::ModuleName.c_str(),
                                            Attack_CheckLog.c_str(),
                                            pnode->addrName.c_str(),
                                            pnode->nTrafficRatio,
                                            pnode->nTrafficAverage,
                                            Stats::AverageTraffic,
                                            pnode->nSendBytes,
                                            pnode->nRecvBytes,
                                            pnode->nStartingHeight,
                                            SyncHeight,
                                            pnode->nRecvVersion,
                                            pnode->hashAskedFor.ToString(),
                                            pnode->hashReceived.ToString()
                                            );
                }
                /** -------------------------- **/

                /** -------------------------- 
                    Denied IP on Attack detection
                    Add node/peer IP to Denied
                **/
                if (Attack_Denied == true)
                {
                    Operations::AddDenied(pnode);
                }
                /** -------------------------- **/

                /** -------------------------- 
                    Peer/Node Ban if required
                **/
                if (Attack_Ban == true)
                {
                    Operations::AddBan(pnode, Attack_BanReason, Attack_BanTime);
                }
                /** -------------------------- **/

                /** -------------------------- 
                    Peer/Node Panic Disconnect
                **/
                if (Attack_Disconnect == true)
                {
                    Operations::ForceDisconnectNode(pnode, FromFunction);
                }
                /** -------------------------- **/

                /** -------------------------- 
                    Attack Detected Output
                **/
                return true;
                /** -------------------------- **/
            }
        }
        /** -------------------------- **/

        /** -------------------------- 
            Attack NOT Detected Output
        **/
        return false;
        /** -------------------------- **/
    }


    /* FUNCTION: Monitoring::Examination
        Calculate new Height Average from all peers connected
    */
    void Monitoring::Examination(CNode *pnode, string FromFunction)
    {
        bool UpdateNodeStats = false;

        int SyncHeight;

        int TimeConnected = GetTime() - pnode->nTimeConnected; // In seconds

        /** Use Dynamic Checkpoints by default **/
        SyncHeight = pnode->dCheckpointRecv.height;

        if (SyncHeight == 0)
        {
            /** ppcoin: known sent sync-checkpoint **/
            SyncHeight = Monitoring::LegacySyncHeight(pnode);
        }

        if (SyncHeight == 0)
        {
            SyncHeight = pnode->nStartingHeight;
        }

        if (SyncHeight < pnode->nStartingHeight)
        {
            SyncHeight = pnode->nStartingHeight;
        }
    
        /** Update current average if increased **/
        if (SyncHeight > Stats::AverageHeight) 
        {
            Stats::AverageHeight = Stats::AverageHeight + SyncHeight; 
            Stats::AverageHeight = Stats::AverageHeight / 2;
            Stats::AverageHeight = Stats::AverageHeight - Settings::Average_Tolerance; /** reduce with tolerance **/
            Stats::AverageHeight_Min = Stats::AverageHeight - Settings::Average_Range;
            Stats::AverageHeight_Max = Stats::AverageHeight + Settings::Average_Range;
        }

        if (pnode->nRecvBytes > 0)
        {
            pnode->nTrafficRatio = pnode->nSendBytes / (double)pnode->nRecvBytes;

            if (pnode->nTrafficTimestamp == 0)
            {
                UpdateNodeStats = true;
            }

            if (GetTime() - pnode->nTrafficTimestamp > 5){
                UpdateNodeStats = true;
            }

                pnode->nTrafficAverage = pnode->nTrafficAverage + (double)pnode->nTrafficRatio / 2;
                pnode->nTrafficTimestamp = GetTime();

            if (UpdateNodeStats == true)
            {   
                Stats::AverageTraffic = Stats::AverageTraffic + (double)pnode->nTrafficAverage;
                Stats::AverageTraffic = Stats::AverageTraffic / (double)2;
                Stats::AverageTraffic = Stats::AverageTraffic - (double)Settings::Average_Tolerance; /** reduce with tolerance **/
                Stats::AverageTraffic_Min = Stats::AverageTraffic - (double)Settings::Average_Range;
                Stats::AverageTraffic_Max = Stats::AverageTraffic + (double)Settings::Average_Range;
                
                if (vNodes.size() > 0)
                {
                    Stats::AverageSend = Stats::AverageSend + pnode->nSendBytes / vNodes.size();
                    Stats::AverageRecv = Stats::AverageRecv + pnode->nRecvBytes / vNodes.size();         
                }

                if (LiveDebug::Enabled == true)
                {
                    if (LiveDebug::Exam == true)
                    {
                        cout << Settings::ModuleName <<
                            " [Denieded Nodes/Peers: " << CountStringArray(Lists::Denied) <<
                            "] [Traffic: " << Stats::AverageTraffic <<
                            "] [Traffic Min: " << Stats::AverageTraffic_Min <<
                            "] [Traffic Max: " << Stats::AverageTraffic_Max <<
                            "]" << " [Safe Height: " << Stats::AverageHeight <<
                            "] [Height Min: " << Stats::AverageHeight_Min <<
                            "] [Height Max: " << Stats::AverageHeight_Max <<
                            "] [Send Avrg: " << Stats::AverageSend << 
                            "] [Rec Avrg: " << Stats::AverageRecv <<
                            "]\n" <<endl;

                        cout << Settings::ModuleName <<
                            " [Check Node: " << pnode->addrName.c_str() <<
                            "] [Traffic: " << pnode->nTrafficRatio <<
                            "] [Traffic Average: " << pnode->nTrafficAverage <<
                            "] [Starting Height: " << pnode->nStartingHeight <<
                            "] [Sync Height: " << pnode->dCheckpointRecv.height <<
                            "] [Node Sent: " << pnode->nSendBytes <<
                            "] [Node Recv: " << pnode->nRecvBytes <<
                            "] [Protocol: " << pnode->nRecvVersion <<
                            "] [Time Connected: " << TimeConnected << "] " <<
                            "] [HashAskedFor: " << pnode->hashAskedFor.ToString() <<
                            "] [HashReceived: " << pnode->hashReceived.ToString() <<
                            "]\n" << endl;
                    }
                }
            }

            CheckAttack(pnode, FromFunction);
        }
    }


    /* FUNCTION: Monitoring::Init
        Firewall Inititalization (Node)
    */
    bool Monitoring::Init(CNode *pnode, string FromFunction)
    {
        if (Settings::Enabled == false)
        {
            return false;
        }

        int i;
        int ListCount = CountStringArray(Lists::Allowed);

        if (ListCount > 0)
        {
            for (i = 0; i < ListCount; i++)
            {  
                /** Check for Alloweded Seed Node **/
                if (pnode->addrName == Lists::Allowed[i])
                {
                    return false;
                }
            }
        }

        if (Settings::Banned_Autoclear == true)
        {
            if ((int)vNodes.size() <= Settings::Banned_MinNodes)
            {
                pnode->ClearBanned();

                int ListCount = CountStringArray(Lists::Denied);
                
                std::fill_n(Lists::Denied, ListCount, 0);
                
                if (fDebug)
                {
                    LogPrint("firewall", "%s Cleared ban: %s\n", Settings::ModuleName.c_str(), pnode->addrName.c_str());
                }
            }
        }

        if (Operations::CheckDenied(pnode) == true)
        {
            FromFunction = "CheckDenied";

            if (fDebug)
            {
                LogPrint("firewall", "%s Disconnected Denieded IP: %s\n", Settings::ModuleName.c_str(), pnode->addrName.c_str());
            }

            /** Peer/Node Panic Disconnect **/
            Operations::ForceDisconnectNode(pnode, FromFunction);

            return true;
        }

        if (Operations::CheckBanned(pnode) == true)
        {
            FromFunction = "CheckBanned";

            if (fDebug)
            {
                LogPrint("firewall", "%s Disconnected Banned IP: %s\n", Settings::ModuleName.c_str(), pnode->addrName.c_str());
            }

            /** Peer/Node Panic Disconnect **/
            Operations::ForceDisconnectNode(pnode, FromFunction);

            return true;
        }

        /** Perform a Node consensus examination **/
        Monitoring::Examination(pnode, FromFunction);

        /** Peer/Node Safe  **/
        return false;
    }

    /* ------------------- */

    

    /* ------------------- */

}
// Firewall Namespace End

/*
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
**/