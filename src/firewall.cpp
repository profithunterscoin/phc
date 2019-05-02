/*
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
   ||||                                                                                             ||||
   |||| Bitcoin Firewall 2.0.0.2  April, 2019                                                       ||||
   |||| Biznatch Enterprises & Profit Hunters Coin (PHC) & BATA Development (bata.io)               ||||
   |||| https://github.com/BiznatchEnterprises/BitcoinFirewall                                      ||||
   |||| Distributed under the MIT/X11 software license, see the accompanying                        ||||
   |||| file COPYING or http://www.opensource.org/licenses/mit-license.php.                         ||||
   ||||                                                                                             ||||
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
*/

#include "firewall.h"
#include "util.h"
#include "main.h"

using namespace std;
using namespace CBan;

/* VARIABLES: Global Firewall Variables */
string Firewall::ModuleName = "[Bitcoin Firewall 2.0.0.2]";                 /* String                                               */
bool Firewall::FirstRun = false;                                            /* True/False                                           */
int Firewall::AllCheck_Timer = GetTime();                                   /* Start Time                                           */
int Firewall::AllCheck_MaxTimer = 3;                                        /* Minutes interval for some detection settings         */

/* VARIABLES: Firewall Settings (General) */
bool Firewall::Enabled = true;                                              /* True/False                                           */
bool Firewall::Blacklist_Autoclear = false;                                 /* True/False                                           */
bool Firewall::Bans_Autoclear = false;                                      /* True/False                                           */
int Firewall::Bans_MinNodes = 10;                                           /* Minimum connected nodes to auto-clear                */

/* VARIABLES: Average Blockheight among Peers */
int Firewall::AverageHeight = 0;                                            /* Peers Average Block Height                           */
int Firewall::AverageHeight_Min = 0;                                        /* Peers Average Block Height Minimum Range             */
int Firewall::AverageHeight_Max = 0;                                        /* Peers Average Block Height Maximum Range             */
double Firewall::AverageTraffic = 0;                                        /* Peers Average Traffic Ratio                          */
double Firewall::AverageTraffic_Min = 0;                                    /* Peers Average Traffic Ratio Minimum                  */
double Firewall::AverageTraffic_Max = 0;                                    /* Peers Average Traffic Ratio Maximum                  */
int Firewall::AverageSend = 0;                                              /* Peers Average Send Bytes                             */
int Firewall::AverageRecv = 0;                                              /* Peers Average Recv Bytes                             */

/* VARIABLES: Firewall Settings (Exam) */
int Firewall::Average_Tolerance = 2;                                        /* Reduce for minimal fluctuation 2 Blocks tolerance    */
int Firewall::Average_Range = 100;                                          /* + or - Starting Height Range                         */
double Firewall::Traffic_Tolerance;                                         /* Reduce for minimal fluctuation                       */
double Firewall::Traffic_Zone = 4;                                          /* + or - Traffic Range                                 */

/* VARIABLES: Firewall Controls (LiveDebug Output) */
bool Firewall::LiveDebug_Enabled = false;                                   /* True/False                                           */
bool Firewall::LiveDebug_Exam = true;                                       /* True/False                                           */
bool Firewall::LiveDebug_Bans = true;                                       /* True/False                                           */
bool Firewall::LiveDebug_Blacklist = true;                                  /* True/False                                           */
bool Firewall::LiveDebug_Disconnect = true;                                 /* True/False                                           */
bool Firewall::LiveDebug_BandwidthAbuse = true;                             /* True/False                                           */
bool Firewall::LiveDebug_DoubleSpend = true;                                /* True/False                                           */
bool Firewall::LiveDebug_InvalidWallet = true;                              /* True/False                                           */
bool Firewall::LiveDebug_ForkedWallet = true;                               /* True/False                                           */
bool Firewall::LiveDebug_FloodingWallet = true;                             /* True/False                                           */
bool Firewall::LiveDebug_DDoSWallet = true;                                 /* True/False                                           */

/* VARIABLES: Firewall Settings (Bandwidth Abuse) */
bool Firewall::BandwidthAbuse_Detect = true;                                /* true/false                                           */
bool Firewall::BandwidthAbuse_Blacklist = false;                            /* True/False                                           */
bool Firewall::BandwidthAbuse_Ban = false;                                  /* True/False                                           */
int Firewall::BandwidthAbuse_BanTime = 0;                                   /* 24 hours                                             */
bool Firewall::BandwidthAbuse_Disconnect = false;                           /* True/False                                           */
int Firewall::BandwidthAbuse_Mincheck = 20;

/* VARIABLES: Firewall Settings (Double Spend Attack) */
bool Firewall::DoubleSpend_Detect = true;                                   /* True/False                                           */
bool Firewall::DoubleSpend_Blacklist = true;                                /* True/False                                           */
bool Firewall::DoubleSpend_Ban = true;                                      /* True/False                                           */
int Firewall::DoubleSpend_BanTime = 0;                                      /* 24 hours                                             */
bool Firewall::DoubleSpend_Disconnect = true;                               /* True/False                                           */
int Firewall::DoubleSpend_Mincheck = 30;                                    /* Seconds                                              */
double Firewall::DoubleSpend_MinAttack = 17.1;                              /* Traffic Average Ratio Mimumum                        */
double Firewall::DoubleSpend_MaxAttack = 17.2;                              /* Traffic Average Ratio Maximum                        */

/* VARIABLES: Firewall Settings (Invalid Peer Wallets) */
bool Firewall::InvalidWallet_Detect = true;                                 /* True/False                                           */
bool Firewall::InvalidWallet_Blacklist = true;                              /* True/False                                           */
bool Firewall::InvalidWallet_Ban = true;                                    /* True/False                                           */
int Firewall::InvalidWallet_BanTime = 0;                                    /* 24 hours                                             */
bool Firewall::InvalidWallet_Disconnect = true;                             /* True/False                                           */
int Firewall::InvalidWallet_MinimumProtocol = MIN_PEER_PROTO_VERSION;       /* Version                                              */
int Firewall::InvalidWallet_MinCheck = 120;                                 /* Seconds                                              */

/* VARIABLES: Firewall Settings (Forked Wallet) */
bool Firewall::ForkedWallet_Detect = true;                                  /* True/False                                           */
bool Firewall::ForkedWallet_Blacklist = true;                               /* True/False                                           */
bool Firewall::ForkedWallet_Ban = true;                                     /* True/False                                           */
bool Firewall::ForkedWallet_Disconnect = true;                              /* True/False                                           */
int Firewall::ForkedWallet_BanTime = 0;                                     /* 24 hours                                             */

/* VARIABLES: FORKLIST */
int Firewall::ForkedWallet_NodeHeight[256] =
{
    10000,
    39486,
    48405
};

/* VARIABLES: Firewall Settings (Flooding Peer Wallets) */
bool Firewall::FloodingWallet_Detect = true;                                /* True/False                                           */
bool Firewall::FloodingWallet_Blacklist = true;                             /* True/False                                           */
bool Firewall::FloodingWallet_Ban = true;                                   /* True/False                                           */
int Firewall::FloodingWallet_BanTime = 2600000;                             /* 30 days                                              */
bool Firewall::FloodingWallet_Disconnect = true;                            /* True/False                                           */
uint64_t Firewall::FloodingWallet_MinBytes = 1000000;                       /* 1 MB Minimum Bytes                                   */
uint64_t Firewall::FloodingWallet_MaxBytes = 10000000;                      /* 10 MB Maximum Bytes                                  */
double Firewall::FloodingWallet_MinTrafficAverage = 2000;                   /* Ratio Up/Down Minimum                                */
double Firewall::FloodingWallet_MaxTrafficAverage = 2000;                   /* Ratio Up/Down Maximum                                */
int Firewall::FloodingWallet_MinCheck = 30;                                 /* 30 Seconds Minimum                                   */
int Firewall::FloodingWallet_MaxCheck = 90;                                 /* 90 Seconds Maximum                                   */

/* VARIABLES (Array): Flooding Wallet Attack Patterns */
string Firewall::FloodingWallet_Patterns[256] =
{

};

/* VARIABLES (Array): Flooding Wallet Ignored Patterns */
string Firewall::FloodingWallet_Ignored[256] =
{

};

/* VARIABLES: Firewall Settings (DDOS Wallet) */
bool Firewall::DDoSWallet_Detect = true;                                    /* True/False                                               */
bool Firewall::DDoSWallet_Blacklist = true;                                 /* True/False                                               */
bool Firewall::DDoSWallet_Ban = true;                                       /* True/False                                               */
int Firewall::DDoSWallet_BanTime = 0;                                       /* 24 hours                                                 */
bool Firewall::DDoSWallet_Disconnect = true;                                /* True/False                                               */
int Firewall::DDoSWallet_MinCheck = 30;                                     /* 30 Seconds                                               */

/* VARIABLE (Array): Firewall Whitelist
   (ignore pnode->addrName)
*/
string Firewall::WhiteList[256] =
{

};

/* VARIABLE (Array): Firewall BlackList
   (autoban/disconnect pnode->addrName)
*/
string Firewall::BlackList[256] =
{

};

/* FUNCTION: LoadFirewallSettings */
void Firewall::LoadFirewallSettings()
{
    /** Load Firewall Settings From (phc.conf & cmd args) **/

    /** Firewall Settings (General) **/
    Firewall::Enabled = GetBoolArg("-firewallenabled", Firewall::Enabled);
    Firewall::Blacklist_Autoclear = GetBoolArg("-firewallclearblacklist", Firewall::Blacklist_Autoclear);
    Firewall::Bans_Autoclear = GetBoolArg("-firewallclearbanlist", Firewall::Bans_Autoclear);

    /** Firewall Settings (Exam) **/
    Firewall::Traffic_Tolerance = GetArg("-firewalltraffictolerance", Firewall::Traffic_Tolerance);
    Firewall::Traffic_Zone = GetArg("-firewalltrafficzone", Firewall::Traffic_Zone);

    /** Firewall Debug (Live Output) **/
    Firewall::LiveDebug_Enabled = GetBoolArg("-firewalldebug", Firewall::LiveDebug_Enabled);
    Firewall::LiveDebug_Exam = GetBoolArg("-firewalldebugexam", Firewall::LiveDebug_Exam);
    Firewall::LiveDebug_Bans = GetBoolArg("-firewalldebugbans", Firewall::LiveDebug_Bans);
    Firewall::LiveDebug_Blacklist = GetBoolArg("-firewalldebugblacklist", Firewall::LiveDebug_Blacklist);
    Firewall::LiveDebug_Disconnect = GetBoolArg("-firewalldebugdisconnect", Firewall::LiveDebug_Disconnect);
    Firewall::LiveDebug_BandwidthAbuse = GetBoolArg("-firewalldebugbandwidthabuse", Firewall::LiveDebug_BandwidthAbuse);
    Firewall::LiveDebug_DoubleSpend = GetBoolArg("-firewalldebugdoublespend", Firewall::LiveDebug_DoubleSpend);
    Firewall::LiveDebug_InvalidWallet = GetBoolArg("-firewalldebuginvalidwallet", Firewall::LiveDebug_InvalidWallet);
    Firewall::LiveDebug_ForkedWallet = GetBoolArg("-firewalldebugforkedwallet", Firewall::LiveDebug_ForkedWallet);
    Firewall::LiveDebug_FloodingWallet = GetBoolArg("-firewalldebugfloodingwallet", Firewall::LiveDebug_FloodingWallet);

    /** Firewall Settings (Bandwidth Abuse) **/
    Firewall::BandwidthAbuse_Detect = GetBoolArg("-firewalldetectbandwidthabuse", Firewall::BandwidthAbuse_Detect);
    Firewall::BandwidthAbuse_Blacklist = GetBoolArg("-firewallblacklistbandwidthabuse", Firewall::BandwidthAbuse_Blacklist);
    Firewall::BandwidthAbuse_Ban = GetBoolArg("-firewallbanbandwidthabuse", Firewall::BandwidthAbuse_Ban);
    Firewall::BandwidthAbuse_BanTime = GetArg("-firewallbantimebandwidthabuse", Firewall::BandwidthAbuse_BanTime);
    Firewall::BandwidthAbuse_Disconnect = GetBoolArg("-firewalldisconnectbandwidthabuse", Firewall::BandwidthAbuse_Disconnect);
    Firewall::BandwidthAbuse_Mincheck = GetArg("-firewallbandwidthabusemincheck", Firewall::BandwidthAbuse_Mincheck);

    /** Firewall Settings (DoubleSpend Abuse) **/
    Firewall::DoubleSpend_Detect = GetBoolArg("-firewalldetectdoublespend", Firewall::DoubleSpend_Detect);
    Firewall::DoubleSpend_Blacklist = GetBoolArg("-firewallblacklistdoublespend", Firewall::DoubleSpend_Blacklist);
    Firewall::DoubleSpend_Ban = GetBoolArg("-firewallbandoublespend", Firewall::DoubleSpend_Ban);
    Firewall::DoubleSpend_BanTime = GetArg("-firewallbantimedoublespend", Firewall::DoubleSpend_BanTime);
    Firewall::DoubleSpend_Disconnect = GetBoolArg("-firewalldisconnectdoublespend", Firewall::DoubleSpend_Disconnect);
    Firewall::DoubleSpend_Mincheck = GetArg("-firewalldoublespendmincheck", Firewall::DoubleSpend_Mincheck);
    Firewall::DoubleSpend_MinAttack = GetArg("-firewalldoublespendminattack", Firewall::DoubleSpend_MinAttack);
    Firewall::DoubleSpend_MaxAttack = GetArg("-firewalldoublespendmaxattack", Firewall::DoubleSpend_MaxAttack);

    /** Firewall Settings (Invalid Peer Wallets) **/
    Firewall::InvalidWallet_Detect = GetBoolArg("-firewalldetectinvalidwallet", Firewall::InvalidWallet_Detect);
    Firewall::InvalidWallet_Blacklist = GetBoolArg("-firewallblacklistinvalidwallet", Firewall::InvalidWallet_Blacklist);
    Firewall::InvalidWallet_Ban = GetBoolArg("-firewallbaninvalidwallet", Firewall::InvalidWallet_Ban);
    Firewall::InvalidWallet_MinimumProtocol = GetArg("-firewallinvalidwalletminprotocol", Firewall::InvalidWallet_MinimumProtocol);
    Firewall::InvalidWallet_Ban = GetArg("-firewallbaninvalidwallet", Firewall::InvalidWallet_Ban);
    Firewall::InvalidWallet_BanTime = GetArg("-firewallbantimeinvalidwallet", Firewall::InvalidWallet_BanTime);
    Firewall::InvalidWallet_Disconnect = GetArg("-firewalldisconnectinvalidwallet", Firewall::InvalidWallet_Disconnect);
    Firewall::InvalidWallet_MinCheck = GetArg("-firewallinvalidwalletmincheck", Firewall::InvalidWallet_MinCheck);

    /** Firewall Settings (Forked Peer Wallets) **/
    Firewall::ForkedWallet_Detect = GetBoolArg("-firewalldetectforkedwallet", Firewall::ForkedWallet_Detect);
    Firewall::ForkedWallet_Blacklist = GetBoolArg("-firewallblacklistforkedwallet", Firewall::ForkedWallet_Blacklist);
    Firewall::ForkedWallet_Ban = GetBoolArg("-firewallbanforkedwallet", Firewall::ForkedWallet_Ban);
    Firewall::ForkedWallet_BanTime = GetArg("-firewallbantimeforkedwallet", Firewall::ForkedWallet_BanTime);
    Firewall::ForkedWallet_Disconnect = GetBoolArg("-firewalldisconnectforkedwallet", Firewall::ForkedWallet_Disconnect);

    /** Firewall Settings (Flooding Peer Wallets) **/
    Firewall::FloodingWallet_Detect = GetBoolArg("-firewalldetectfloodingwallet", Firewall::FloodingWallet_Detect);
    Firewall::FloodingWallet_Blacklist = GetBoolArg("-firewallblacklistfloodingwallet", Firewall::FloodingWallet_Blacklist);
    Firewall::FloodingWallet_Ban = GetBoolArg("-firewallbanfloodingwallet", Firewall::FloodingWallet_Ban);
    Firewall::FloodingWallet_BanTime = GetArg("-firewallbantimefloodingwallet", Firewall::FloodingWallet_BanTime);
    Firewall::FloodingWallet_Disconnect = GetBoolArg("-firewalldisconnectfloodingwallet", Firewall::FloodingWallet_Disconnect);
    Firewall::FloodingWallet_MinBytes = GetArg("-firewallfloodingwalletminbytes", Firewall::FloodingWallet_MinBytes);
    Firewall::FloodingWallet_MaxBytes = GetArg("-firewallfloodingwalletmaxbytes", Firewall::FloodingWallet_MaxBytes);
    if (GetArg("-firewallfloodingwalletattackpattern", "-") != "-")
    {
        Firewall::FloodingWallet_Patterns[CountStringArray(Firewall::FloodingWallet_Patterns)] = GetArg("-firewallfloodingwalletattackpattern", "");
    }
    Firewall::FloodingWallet_MinTrafficAverage = GetArg("-firewallfloodingwalletmintrafficavg", Firewall::FloodingWallet_MinTrafficAverage);
    Firewall::FloodingWallet_MaxTrafficAverage = GetArg("-firewallfloodingwalletmaxtrafficavg", Firewall::FloodingWallet_MaxTrafficAverage);
    Firewall::FloodingWallet_MinCheck = GetArg("-firewallfloodingwalletmincheck", Firewall::FloodingWallet_MinCheck);
    Firewall::FloodingWallet_MaxCheck = GetArg("-firewallfloodingwalletmaxcheck", Firewall::FloodingWallet_MaxCheck);

    /** Firewall Settings (DDoS Wallets) **/
    Firewall::DDoSWallet_Detect = GetBoolArg("-firewalldetectddoswallet", Firewall::DDoSWallet_Detect);
    Firewall::DDoSWallet_Blacklist = GetBoolArg("-firewallblacklistddoswallet", Firewall::DDoSWallet_Blacklist);
    Firewall::DDoSWallet_Ban = GetBoolArg("-firewallbanddoswallet", Firewall::DDoSWallet_Ban);
    Firewall::DDoSWallet_BanTime = GetArg("-firewallbantimeddoswallet", Firewall::DDoSWallet_BanTime);
    Firewall::DDoSWallet_Disconnect = GetBoolArg("-firewalldisconnectddoswallet", Firewall::DDoSWallet_Disconnect);
    Firewall::DDoSWallet_MinCheck = GetArg("-firewallmincheckddoswallet", Firewall::DDoSWallet_MinCheck);

    return;

}


/* FUNCTION: LegacySyncHeight */
int Firewall::LegacySyncHeight(CNode *pnode)
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


/* FUNCTION: ForceDisconnectNode */
bool Firewall::ForceDisconnectNode(CNode *pnode, string FromFunction)
{
    TRY_LOCK(pnode->cs_vSend, lockSend);

    if (lockSend)
    {
        /** release outbound grant (if any) **/
        pnode->CloseSocketDisconnect();

        if (fDebug)
        {
            LogPrint("firewall", "%s (%s) Panic Disconnect: %s\n", ModuleName.c_str(), FromFunction, pnode->addrName.c_str());
        }

        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_Disconnect == true)
            {
                cout << ModuleName << " Panic Disconnect: " << pnode->addrName << "]\n" << endl;
            }
        }

        return true;

    }
    else
    {
        pnode->vSendMsg.end();
    }

    return false;
}


/* FUNCTION: CheckBlackList */
bool Firewall::CheckBlackList(CNode *pnode)
{
    int i;
    int TmpBlackListCount;
    TmpBlackListCount = CountStringArray(Firewall::BlackList);

    if (TmpBlackListCount > 0)
    {
        for (i = 0; i < TmpBlackListCount; i++)
        {  
            if (pnode->addrName == Firewall::BlackList[i])
            {   
                // Banned IP FOUND!
                return true;
            }
        }
    }

    // Banned IP not found
    return false;
}


/* FUNCTION: CheckBanned */
bool Firewall::CheckBanned(CNode *pnode)
{
    if (CNode::IsBanned(pnode->addr) == true)
    {
        // Yes Banned!
        return true;
    }

    // No Banned!
    return false;
}


/* FUNCTION: AddToBlackList */
bool Firewall::AddToBlackList(CNode *pnode)
{
    int TmpBlackListCount;
    TmpBlackListCount = CountStringArray(Firewall::BlackList);

        /** Restart Blacklist count **/
        if (TmpBlackListCount >  255)
        {
            TmpBlackListCount = 0;
        }

        if (CheckBlackList(pnode) == false)
        {
            /** increase Blacklist count **/
            TmpBlackListCount = TmpBlackListCount + 1;

            /** Add node IP to blacklist **/
            Firewall::BlackList[TmpBlackListCount] = pnode->addrName;

            if (Firewall::LiveDebug_Enabled == true)
            {
                if (Firewall::LiveDebug_Blacklist == true)
                {
                    cout << ModuleName << " Blacklisted: " << pnode->addrName << "]\n" << endl;
                }
            }

            /** Append Blacklist to debug.log **/
            if (fDebug)
            {
                LogPrint("firewall", "%s Blacklisted: %s\n", ModuleName.c_str(), pnode->addrName.c_str());
            }

            return true;
        }

    return false;
}


/* FUNCTION: AddToBanList */
bool Firewall::AddToBanList(CNode *pnode, BanReason BannedFor, int BanTime)
{
    CNode::Ban(pnode->addr, BannedFor, BanTime, false);

    if (fDebug)
    {
        LogPrint("firewall", "%s Banned: %s\n", ModuleName.c_str(), pnode->addrName);
    }

    if (Firewall::LiveDebug_Enabled == true)
    {
        if (Firewall::LiveDebug_Bans == true)
        {
            cout << ModuleName << " Banned: " << pnode->addrName << "]\n" << endl;
        }
    }

    return true;
}


/* FUNCTION: BandwidthAbuseCheck */
string Firewall::BandwidthAbuseCheck(CNode *pnode, int SyncHeight, int TimeConnected)
{
    std::string AttackCheckName = "Bandwidth Abuse";
    std::string Attack_Type;

    if (Firewall::BandwidthAbuse_Detect == true)
    {
        /** Determines Node bandwidth abuse based upon calculated
            ratio between Recieved bytes and Sent Bytes
            Compared with the average ratio of all nodes
        **/
        
        /** --------------------------
            Attack Detection
        **/
        if ((int)TimeConnected > Firewall::BandwidthAbuse_Mincheck)
        {
            /** Node is further ahead on the chain than average minimum **/
            if (SyncHeight > Firewall::AverageHeight_Min)
            {
                if (pnode->nTrafficAverage < Firewall::AverageTraffic_Min)
                {
                    /** too low bandiwidth ratio limits **/
                    Attack_Type = "1-LowBW-HighHeight";
                }

                if (pnode->nTrafficAverage > Firewall::AverageTraffic_Max)
                {
                    /** too high bandiwidth ratio limits **/
                    Attack_Type = "2-HighBW-HighHeight";
                }
            }

            /** Node is behind on the chain than average minimum **/
            if (SyncHeight < Firewall::AverageHeight_Min)
            {  
                if (pnode->nTrafficAverage < Firewall::AverageTraffic_Min)
                {
                    /** too low bandiwidth ratio limits **/
                    Attack_Type = "3-LowBW-LowHeight";
                }

                if (pnode->nTrafficAverage > Firewall::AverageTraffic_Max)
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
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_BandwidthAbuse == true)
            {
                cout << ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Traffic Average: " << pnode->nTrafficAverage << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
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


/* FUNCTION: DoubleSpendCheck */
string Firewall::DoubleSpendCheck(CNode *pnode, int SyncHeight, int TimeConnected, std::string BandwidthAbuse_Output)
{
    std::string AttackCheckName = "Double Spend Wallet";
    std::string Attack_Type;

    if (Firewall::DoubleSpend_Detect == true)
    {
        /** -------------------------- 
            Attack Detection
            Calculate the ratio between Recieved bytes and Sent Bytes
            Detect a valid syncronizaion vs. a flood attack
        **/
        if ((int)TimeConnected > Firewall::DoubleSpend_Mincheck)
        {
            /** Node is ahead on the chain than average minimum **/
            if (SyncHeight > Firewall::AverageHeight &&
                pnode->nTrafficAverage > Firewall::AverageTraffic_Max)
            {  
                /** Too high bandiwidth ratio limits
                    Detected by default from above conditions
                **/
                Attack_Type = "Pattern Detected";
            
                double tnTraffic = pnode->nSendBytes / pnode->nRecvBytes;

                if (BandwidthAbuse_Output != "2-HighBW-HighHeight")
                {
                    /** DOES NOT MATCH High bandwidth, High block height (possible 51%)
                        No Attack Detected
                    **/
                    Attack_Type = "";
                }

                if (pnode->nTrafficAverage > Firewall::AverageTraffic_Min && pnode->nTrafficAverage < Firewall::AverageTraffic_Max)
                {
                    if (tnTraffic < Firewall::DoubleSpend_MinAttack || tnTraffic > Firewall::DoubleSpend_MaxAttack)
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
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_DoubleSpend == true)
            {
                cout << ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Send Bytes: " << pnode->nSendBytes << "] " <<
                    "[Recv Bytes: " << pnode->nRecvBytes << "] " <<
                    "[Traffic Average: " << pnode->nTrafficAverage << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
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


/* FUNCTION: InvalidWalletCheck */
string Firewall::InvalidWalletCheck(CNode *pnode, int SyncHeight, int TimeConnected)
{
    std::string AttackCheckName = "Invalid Wallet";
    std::string Attack_Type;

    if (Firewall::InvalidWallet_Detect == true)
    {
        /** -------------------------- 
            Attack Detection #1 (A)
            Start Height = -1
            Check for more than Firewall::InvalidWallet_MinCheck minutes connection length
        **/
        if ((int)TimeConnected > Firewall::InvalidWallet_MinCheck)
        {
            if (pnode->nStartingHeight == -1)
            {
                /** Detetected **/
                Attack_Type = "1-StartHeight-Invalid";
            }
        }
        /** -------------------------- **/

        /** -------------------------- 
            Attack Detection #1 (B)
            Start Height < 0
            Check for more than Firewall::InvalidWallet_MinCheck minutes connection length
        **/
        if ((int)TimeConnected > Firewall::InvalidWallet_MinCheck)
        {
            if (pnode->nStartingHeight < 0)
            {
                /** Detected **/
                Attack_Type = "1-StartHeight-Invalid";
            }
        }
        /** -------------------------- **/
        
        /** -------------------------- 
            Attack Detection #2 (A)
            Protocol: 0
            Check for more than Firewall::InvalidWallet_MinCheck minutes connection length
        **/
        if ((int)TimeConnected > Firewall::InvalidWallet_MinCheck)
        {
            if (pnode->nRecvVersion == 0)
            {
                /** Detected **/
                Attack_Type = "2-Protocol-Invalid";
            }
        }
        /** -------------------------- **/

        /** -------------------------- 
            Attack Detection #2 (B)
            Protocol: lower than 1
            Check for more than Firewall::InvalidWallet_MinCheck minutes connection length
        **/
        if ((int)TimeConnected > Firewall::InvalidWallet_MinCheck)
        {
            if (pnode->nRecvVersion < 1)
            {
                /** Detected **/
                Attack_Type = "2-Protocol-Invalid";
            }
        }
        /** -------------------------- **/

        /** -------------------------- 
            Attack Detection #2 (C)
            Protocol: lower than mimimum protocol
            Check for more than Firewall::InvalidWallet_MinCheck minutes connection length
        **/
        if ((int)TimeConnected > Firewall::InvalidWallet_MinCheck)
        {
            if (pnode->nRecvVersion < InvalidWallet_MinimumProtocol && pnode->nRecvVersion > 209)
            {
                /** Detected **/
                Attack_Type = "2-Protocol-Invalid";
            }
        }
        /** -------------------------- **/

        /** -------------------------- 
            Attack Detection #3
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

            if (pnode->nSyncHeight < pnode->nSyncHeightCache - Firewall::AVERAGE_RANGE)
            {
                Trigger Blacklisting
                ATTACK_TYPE = "1-SyncReset";
            }

        }
        **/
        /** -------------------------- **/

        /** -------------------------- 
            Live Debug Output
        **/
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_InvalidWallet == true)
            {
                cout << ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Start Height: " << pnode->nStartingHeight << "] " <<
                    "[Recv Version: " << pnode->nRecvVersion << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
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


/* FUNCTION: ForkedWalletCheck */
string Firewall::ForkedWalletCheck(CNode *pnode, int SyncHeight, int TimeConnected)
{
    std::string AttackCheckName = "Forked Wallet";
    std::string Attack_Type;

    if (Firewall::ForkedWallet_Detect == true)
    {
        /** -------------------------- 
            Attack Detection
            Check for Forked Wallet (stuck on blocks)
        **/
        int i;
        int TmpSyncHeightCount;
        TmpSyncHeightCount = CountIntArray(Firewall::ForkedWallet_NodeHeight) - 2;
        
        if (TmpSyncHeightCount > 0)
        {
            for (i = 0; i < TmpSyncHeightCount; i++)
            { 
                if (SyncHeight == (int)Firewall::ForkedWallet_NodeHeight[i])
                {
                    Attack_Type = (int)Firewall::ForkedWallet_NodeHeight[i];
                }
            }          
        }
        /** -------------------------- **/

        /** -------------------------- 
            Live Debug Output
        **/
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_ForkedWallet == true)
            {
                cout << ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
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


/* FUNCTION: FloodingWalletCheck */
string Firewall::FloodingWalletCheck(CNode *pnode, int SyncHeight, bool DetectedAttack, int TimeConnected, std::string BandwidthAbuse_Output)
{
    std::string AttackCheckName = "Flooding Wallet";
    std::string Attack_Type;
    std::string Warnings;

    if (Firewall::FloodingWallet_Detect == true)
    {
        /** -------------------------- 
            WARNING #1
            Too high of bandwidth with low BlockHeight
        **/
        if (SyncHeight < Firewall::AverageHeight_Min)
        {  
            if (pnode->nStartingHeight > Firewall::AverageTraffic_Max)
            {
                Warnings = Warnings + "~1";
            }
        }
        /** -------------------------- **/
        
        /** -------------------------- 
            WARNING #2
            Send Bytes below minimum
        **/
        if (pnode->nSendBytes < Firewall::FloodingWallet_MinBytes)
        {
            Warnings = Warnings + "~2";
        }
        /** -------------------------- **/

        /** -------------------------- 
            WARNING #3
            Send Bytes above minimum
        **/
        if (pnode->nSendBytes < Firewall::FloodingWallet_MinBytes)
        {
            Warnings = Warnings + "~3";
        }
        /** -------------------------- **/

        /** -------------------------- 
            WARNING #4
            Send Bytes below maximum
        **/
        if (pnode->nSendBytes < Firewall::FloodingWallet_MaxBytes)
        {
            Warnings = Warnings + "~4";
        }
        /** -------------------------- **/

        /** -------------------------- 
            WARNING #5
            Send Bytes above maximum
        **/
        if (pnode->nSendBytes > Firewall::FloodingWallet_MaxBytes)
        {
            Warnings = Warnings + "~5";
        }
        /** -------------------------- **/

        /** -------------------------- 
            WARNING #6
            Recv Bytes above min 
        **/
        if (pnode->nRecvBytes > Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "~6";
        }
        /** ------------------------- **/

        /** -------------------------- 
            WARNING #7
            Recv Bytes below min
        **/
        if (pnode->nRecvBytes < Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "~7";
        }
        /** ------------------------- **/

        /** -------------------------- 
            WARNING #8
            Recv Bytes above max 
        **/
        if (pnode->nRecvBytes > Firewall::FloodingWallet_MaxBytes / 2)
        {
            Warnings = Warnings + "~8";
        }
        /** ------------------------- **/

        /** -------------------------- 
            WARNING #9
            Recv Bytes below max
        **/
        if (pnode->nRecvBytes < Firewall::FloodingWallet_MaxBytes / 2)
        {
            Warnings = Warnings + "~9";
        }
        /** ------------------------- **/

        /** -------------------------- 
            WARNING #10
            Recv Bytes above min 
        **/
        if (pnode->nSendBytes > Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "~10";
        }

        /** -------------------------- 
            WARNING #11
            Recv Bytes below min
        **/
        if (pnode->nSendBytes < Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "~11";
        }
        /** ------------------------- **/

        /** -------------------------- 
            WARNING #12
            Recv Bytes above max 
        **/
        if (pnode->nSendBytes > Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "~12";
        }
        /** ------------------------- **/

        /** -------------------------- 
            WARNING #13
            Recv Bytes below max
        **/
        if (pnode->nSendBytes < Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "~13";
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #14
            Node Traffic Average is bigger than Minimum Traffic Average set for FloodingWallet
        **/
        if (pnode->nTrafficAverage > Firewall::FloodingWallet_MinTrafficAverage)
        {
            Warnings = Warnings + "~14";
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #15
            Node Traffic Average is smaller than Minimum Traffic Average set for FloodingWallet
        **/
        if (pnode->nTrafficAverage < Firewall::FloodingWallet_MinTrafficAverage)
        {
            Warnings = Warnings + "~15";
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #16
            Node Traffic Average is bigger than MaximumTraffic Average set for FloodingWallet
        **/
        if (pnode->nTrafficAverage > Firewall::FloodingWallet_MaxTrafficAverage)
        {
            Warnings = Warnings + "~16";
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #17
            Node Traffic Average is smaller than Maximum Traffic Average set for FloodingWallet
        **/
        if (pnode->nTrafficAverage < Firewall::FloodingWallet_MaxTrafficAverage)
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
        if ((int)TimeConnected > Firewall::FloodingWallet_MinCheck * 60)
        {
            Warnings = Warnings + "~19";
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #20 - Connected Time below min
        **/
        if ((int)TimeConnected < Firewall::FloodingWallet_MinCheck * 60)
        {
            Warnings = Warnings + "~20";
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #21 - Connected Time above max
        **/
        if ((int)TimeConnected > Firewall::FloodingWallet_MaxCheck * 60)
        {
            Warnings = Warnings + "~21";
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #22 - Connected Time below max
        **/
        if ((int)TimeConnected < Firewall::FloodingWallet_MaxCheck * 60)
        {
            Warnings = Warnings + "~22";
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #23 - Current BlockHeight
        **/
        if (SyncHeight > Firewall::AverageHeight)
        {  
            if (SyncHeight < Firewall::AverageHeight_Max)
            {  
                Warnings = Warnings + "~23";
            }
        }
        /** ------------------------- **/

        /** --------------------------
            WARNING #24 - Sync Height is small than Average Height Max
        **/
        if (SyncHeight < Firewall::AverageHeight_Max)
        {
            if (SyncHeight > Firewall::AverageHeight_Min)
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
        int TmpFloodingWallet_PatternsCount;

        TmpFloodingWallet_PatternsCount = CountStringArray(Firewall::FloodingWallet_Patterns);

        if (TmpFloodingWallet_PatternsCount > 0)
        {
            for (i = 0; i < TmpFloodingWallet_PatternsCount; i++)
            {  
                if (Firewall::FloodingWallet_Patterns[i] != "")
                {
                    if (Warnings == Firewall::FloodingWallet_Patterns[i])
                    {
                        Attack_Type = Warnings;
                    }
                }
            }
        }
        /** ------------------------- **/

        /** --------------------------
            Ignore Flooding Patterns
            IF Warnings is matched to pattern DETECTED_ATTACK = FALSE
        **/
        int TmpFloodingWallet_IgnoredCount;

        TmpFloodingWallet_IgnoredCount = CountStringArray(Firewall::FloodingWallet_Ignored);

        if (TmpFloodingWallet_IgnoredCount > 0)
        {
            for (i = 0; i < TmpFloodingWallet_IgnoredCount; i++)
            {  
                if (Firewall::FloodingWallet_Ignored[i] != "")
                {
                    if (Warnings == Firewall::FloodingWallet_Ignored[i])
                    {
                        Attack_Type = "";
                    }
                }
            }
        }
        /** ------------------------- **/

        /** --------------------------
            Live Debug Output
        **/
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_InvalidWallet == true)
            {
                cout << ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Start Height: " << pnode->nStartingHeight << "] " <<
                    "[Prev Detected: " << DetectedAttack << "] " <<
                    "[Send Bytes: " << pnode->nSendBytes << "] " <<
                    "[Recv Bytes: " << pnode->nRecvBytes << "] " <<
                    "[Traffic Average: " << pnode->nTrafficAverage << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "[Warnings: " << Warnings << "] " <<
                    "\n" << endl;
            }
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


/* FUNCTION: DDoSCheck */
string Firewall::DDoSCheck(CNode *pnode, int TimeConnected, std::string BandwidthAbuse_Output)
{
    std::string AttackCheckName = "DDoS Wallet";
    std::string Attack_Type;

    if (Firewall::DDoSWallet_Detect == true)
    {
        /** --------------------------
            Attack Detection
            Simple DDoS using invalid P2P packets/commands
        **/
        if ((int)TimeConnected > Firewall::DDoSWallet_MinCheck * 60)
        {
            if (pnode->nInvalidRecvPackets > 0)
            {
                if (pnode->nRecvBytes > 0)
                {
                    double InvalidPacketRatio = (pnode->nInvalidRecvPackets / (pnode->nRecvBytes / 1000));

                    if (InvalidPacketRatio > 1)
                    {
                        Attack_Type = "Invalid Packets";
                    }
                }
            }
        }
        /** ------------------------- **/

        /** --------------------------
            Live Debug Output
        **/
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_DDoSWallet == true)
            {
                cout << ModuleName <<
                    " [Checking: " << pnode->addrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Invalid Packets: " << pnode->nInvalidRecvPackets << "] " <<
                    "[Recv Bytes: " << pnode->nRecvBytes << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
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


/* FUNCTION: HighBanScoreCheck
    NOT USED!
*/
/*
string Firewall::HighBanScoreCheck()
{
    if (DETECT_HIGH_BANSCORE == true)
    {
        DETECTED_ATTACK = false;

        nMisbehavior
        checkbanned function integration *todo*

        if (DETECTED_ATTACK == true)
        {
            if (BlackList_HIGH_BANSCORE == true)
            {
                BLACKLIST_ATTACK = true;
            }

            if (BAN_HIGH_BANSCORE == true)
            {
                BAN_ATTACK = true;
                BAN_TIME = BANTIME_HIGH_BANSCORE;
            }

        }
    }
}
*/


/* FUNCTION: CheckAttack
    Artificially Intelligent Attack Detection & Mitigation
*/
bool Firewall::CheckAttack(CNode *pnode, string FromFunction)
{
    bool DETECTED_ATTACK = false;
    bool BLACKLIST_ATTACK = false;
    int BAN_TIME = 0; /** Default 24 hours **/
    bool BAN_ATTACK = false;
    bool DISCONNECT_ATTACK = false;

    BanReason BAN_REASON{};

    string ATTACK_CHECK_LOG;
    string LIVE_DEBUG_LOG;

    int TimeConnected = GetTime() - pnode->nTimeConnected;

    /** -------------------------- 
        Sync Height
    **/
    int SyncHeight;

    SyncHeight = pnode->dCheckpointRecv.height; /** Use Dynamic Checkpoints by default **/

    if (SyncHeight == 0)
    {
        SyncHeight = LegacySyncHeight(pnode); /** ppcoin: known sent sync-checkpoint **/
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
    std::string Attack_BandwidthAbuse;
    Attack_BandwidthAbuse = BandwidthAbuseCheck(pnode, SyncHeight, TimeConnected);

    if (Attack_BandwidthAbuse != "")
    {
        if (Firewall::BandwidthAbuse_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
            DETECTED_ATTACK = true;
        }

        if (Firewall::BandwidthAbuse_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::BandwidthAbuse_BanTime;
            BAN_REASON = BanReasonBandwidthAbuse;
            DETECTED_ATTACK = true;
        }

        if (Firewall::BandwidthAbuse_Disconnect == true)
        {
            DISCONNECT_ATTACK = true;
            DETECTED_ATTACK = true;
        }

        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_BandwidthAbuse;
    }
    /** -------------------------- **/

    /** -------------------------- 
        Double Spend Check & Attack Mitigation
    **/
    std::string Attack_Output;
    Attack_Output = DoubleSpendCheck(pnode, SyncHeight, TimeConnected, Attack_BandwidthAbuse);
    
    if (Attack_Output != "")
    {
        if (Firewall::DoubleSpend_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::DoubleSpend_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::DoubleSpend_BanTime;
            BAN_REASON = BanReasonDoubleSpendWallet;
        }

        if (Firewall::DoubleSpend_Disconnect == true)
        {
            DISCONNECT_ATTACK = true;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    /** -------------------------- **/

    /** -------------------------- 
        Invalid Wallet Check & Attack Mitigation
    **/
    Attack_Output = InvalidWalletCheck(pnode, SyncHeight, TimeConnected);
    
    if (Attack_Output != "")
    {
        if (Firewall::InvalidWallet_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::InvalidWallet_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::InvalidWallet_BanTime;
            BAN_REASON = BanReasonInvalidWallet;
        }

        if (Firewall::InvalidWallet_Disconnect == true)
        {
            DISCONNECT_ATTACK = true;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    /** -------------------------- **/

    /** -------------------------- 
        Forked Wallet Check & Attack Mitigation
    **/
    Attack_Output = ForkedWalletCheck(pnode, SyncHeight, TimeConnected);
    
    if (Attack_Output != "")
    {
        if (Firewall::ForkedWallet_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::ForkedWallet_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::ForkedWallet_BanTime;
            BAN_REASON = BanReasonForkedWallet;
        }

        if (Firewall::ForkedWallet_Disconnect == true)
        {
            DISCONNECT_ATTACK = true;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    /** -------------------------- **/

    /** -------------------------- 
        Flooding Wallet Check & Attack Mitigation
    **/
    Attack_Output = FloodingWalletCheck(pnode, SyncHeight, DETECTED_ATTACK, TimeConnected, Attack_BandwidthAbuse);
    
    if (Attack_Output != "")
    {
        if (Firewall::FloodingWallet_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::FloodingWallet_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::FloodingWallet_BanTime;
            BAN_REASON = BanReasonFloodingWallet;
        }

        if (Firewall::FloodingWallet_Disconnect == true)
        {
            DISCONNECT_ATTACK = true;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    /** -------------------------- **/

    /** -------------------------- 
        DDoS Check & Attack Mitigation ###
    **/
    Attack_Output = DDoSCheck(pnode, TimeConnected, Attack_BandwidthAbuse);
    
    if (Attack_Output != "")
    {
        if (Firewall::DDoSWallet_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::DDoSWallet_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::DDoSWallet_BanTime;
            BAN_REASON = BanReasonDDoSWallet;
        }

        if (Firewall::DDoSWallet_Disconnect == true)
        {
            DISCONNECT_ATTACK = true;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    /** -------------------------- **/

    /** -------------------------- 
        ATTACK DETECTED (TRIGGER)
    **/
    if (DETECTED_ATTACK == true)
    {
        if (ATTACK_CHECK_LOG != "")
        {
            /** -------------------------- 
                Live Debug Output
            **/
            if (Firewall::LiveDebug_Enabled == true)
            {
                cout << ModuleName <<
                " [Attacks: " << ATTACK_CHECK_LOG <<
                "] [Detected from: " << pnode->addrName <<
                "] [Node Traffic: " << pnode->nTrafficRatio <<
                "] [Node Traffic Avrg: " << pnode->nTrafficAverage <<
                "] [Traffic Avrg: " << Firewall::AverageTraffic <<
                "] [Sent Bytes: " << pnode->nSendBytes <<
                "] [Recv Bytes: " << pnode->nRecvBytes <<
                "] [Start Height: " << pnode->nStartingHeight <<
                "] [Sync Height: " << SyncHeight <<
                "] [Protocol: " << pnode->nRecvVersion <<
                "]\n" << endl;
            }
            /** -------------------------- **/

            /** -------------------------- 
                Debug Log Output
            **/
            if (fDebug)
            {
                LogPrint("firewall", "%s [Attacks: %s] "
                                        "[Detected from: %s] "
                                        "[Node Traffic: %d] "
                                        "[Node Traffic Avrg: %d] "
                                        "[Traffic Avrg: %d] "
                                        "[Sent Bytes: %d] "
                                        "[Recv Bytes: %d] "
                                        "[Start Height: %i] "
                                        "[Sync Height: %i] "
                                        "[Protocol: %i]"
                                        "\n",

                                        ModuleName.c_str(),
                                        ATTACK_CHECK_LOG.c_str(),
                                        pnode->addrName.c_str(),
                                        pnode->nTrafficRatio,
                                        pnode->nTrafficAverage,
                                        Firewall::AverageTraffic,
                                        pnode->nSendBytes,
                                        pnode->nRecvBytes,
                                        pnode->nStartingHeight,
                                        SyncHeight,
                                        pnode->nRecvVersion
                                        );
            }
            /** -------------------------- **/

            /** -------------------------- 
                Blacklist IP on Attack detection
                Add node/peer IP to blacklist
            **/
            if (BLACKLIST_ATTACK == true)
            {
                AddToBlackList(pnode);
            }
            /** -------------------------- **/

            /** -------------------------- 
                Peer/Node Ban if required
            **/
            if (BAN_ATTACK == true)
            {
                if (BAN_REASON > -1)
                {
                    AddToBanList(pnode, BAN_REASON, BAN_TIME);
                }
            }
            /** -------------------------- **/

            /** -------------------------- 
                Peer/Node Panic Disconnect
            **/
            if (DISCONNECT_ATTACK == true)
            {
                ForceDisconnectNode(pnode, FromFunction);
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


/* FUNCTION: Examination
    Calculate new Height Average from all peers connected
*/
void Firewall::Examination(CNode *pnode, string FromFunction)
{
    bool UpdateNodeStats = false;

    int SyncHeight;

    /** Use Dynamic Checkpoints by default **/
    SyncHeight = pnode->dCheckpointRecv.height;

    if (SyncHeight == 0)
    {
        /** ppcoin: known sent sync-checkpoint **/
        SyncHeight = LegacySyncHeight(pnode);
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
    if (SyncHeight > Firewall::AverageHeight) 
    {
        Firewall::AverageHeight = Firewall::AverageHeight + SyncHeight; 
        Firewall::AverageHeight = Firewall::AverageHeight / 2;
        Firewall::AverageHeight = Firewall::AverageHeight - Firewall::Average_Tolerance; /** reduce with tolerance **/
        Firewall::AverageHeight_Min = Firewall::AverageHeight - Firewall::Average_Range;
        Firewall::AverageHeight_Max = Firewall::AverageHeight + Firewall::Average_Range;
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
            Firewall::AverageTraffic = Firewall::AverageTraffic + (double)pnode->nTrafficAverage;
            Firewall::AverageTraffic = Firewall::AverageTraffic / (double)2;
            Firewall::AverageTraffic = Firewall::AverageTraffic - (double)Firewall::Average_Tolerance; /** reduce with tolerance **/
            Firewall::AverageTraffic_Min = Firewall::AverageTraffic - (double)Firewall::Average_Range;
            Firewall::AverageTraffic_Max = Firewall::AverageTraffic + (double)Firewall::Average_Range;
            
            if (vNodes.size() > 0)
            {
                Firewall::AverageSend = Firewall::AverageSend + pnode->nSendBytes / vNodes.size();
                Firewall::AverageRecv = Firewall::AverageRecv + pnode->nRecvBytes / vNodes.size();         
            }

            if (Firewall::LiveDebug_Enabled == true)
            {
                if (Firewall::LiveDebug_Exam == true)
                {
                    cout << ModuleName <<
                        " [BlackListed Nodes/Peers: " << CountStringArray(Firewall::BlackList) <<
                        "] [Traffic: " << Firewall::AverageTraffic <<
                        "] [Traffic Min: " << Firewall::AverageTraffic_Min <<
                        "] [Traffic Max: " << Firewall::AverageTraffic_Max <<
                        "]" << " [Safe Height: " << Firewall::AverageHeight <<
                        "] [Height Min: " << Firewall::AverageHeight_Min <<
                        "] [Height Max: " << Firewall::AverageHeight_Max <<
                        "] [Send Avrg: " << Firewall::AverageSend << 
                        "] [Rec Avrg: " << Firewall::AverageRecv <<
                        "]\n" <<endl;

                    cout << ModuleName <<
                        "[Check Node IP: " << pnode->addrName.c_str() <<
                        "] [Traffic: " << pnode->nTrafficRatio <<
                        "] [Traffic Average: " << pnode->nTrafficAverage <<
                        "] [Starting Height: " << pnode->nStartingHeight <<
                        "] [Sync Height: " << pnode->dCheckpointRecv.height <<
                        "] [Node Sent: " << pnode->nSendBytes <<
                        "] [Node Recv: " << pnode->nRecvBytes <<
                        "] [Protocol: " << pnode->nRecvVersion <<
                        "]\n" << endl;
                }
            }
        }

        CheckAttack(pnode, FromFunction);
    }
}


/* FUNCTION: Init
    Firewall Inititalization (Node)
*/
bool Firewall::Init(CNode *pnode, string FromFunction)
{
    if (Firewall::FirstRun == false)
    {
        Firewall::FirstRun = true;

        LoadFirewallSettings();
    }

    if (Firewall::Enabled == false)
    {
        return false;
    }

    int i;
    int TmpWhiteListCount;

    TmpWhiteListCount = CountStringArray(Firewall::WhiteList);

    if (TmpWhiteListCount > 0)
    {
        for (i = 0; i < TmpWhiteListCount; i++)
        {  
            /** Check for Whitelisted Seed Node **/
            if (pnode->addrName == Firewall::WhiteList[i])
            {
               return false;
            }
        }
    }

    if (Firewall::Bans_Autoclear == true)
    {
        if ((int)vNodes.size() <= Firewall::Bans_MinNodes)
        {
            pnode->ClearBanned();

            int TmpBlackListCount;
            
            TmpBlackListCount = CountStringArray(Firewall::BlackList);
            
            std::fill_n(Firewall::BlackList, TmpBlackListCount, 0);
            
            if (fDebug)
            {
                LogPrint("firewall", "%s Cleared ban: %s\n", ModuleName.c_str(), pnode->addrName.c_str());
            }
        }
    }

    if (CheckBlackList(pnode) == true)
    {
        FromFunction = "CheckBlackList";

        if (fDebug)
        {
            LogPrint("firewall", "%s Disconnected Blacklisted IP: %s\n", ModuleName.c_str(), pnode->addrName.c_str());
        }

        /** Peer/Node Panic Disconnect **/
        ForceDisconnectNode(pnode, FromFunction);

        return true;
    }

    if (CheckBanned(pnode) == true)
    {
        FromFunction = "CheckBanned";

        if (fDebug)
        {
            LogPrint("firewall", "%s Disconnected Banned IP: %s\n", ModuleName.c_str(), pnode->addrName.c_str());
        }

        /** Peer/Node Panic Disconnect **/
        ForceDisconnectNode(pnode, FromFunction);

        return true;
    }

    /** Perform a Node consensus examination **/
    Examination(pnode, FromFunction);

    /** Peer/Node Safe  **/
    return false;
}

/*
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
**/