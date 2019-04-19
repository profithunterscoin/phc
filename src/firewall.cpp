// ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
// 
// [Bitcoin Firewall 2.0.0
// March, 2019 - Biznatch Enterprises & Profit Hunters Coin (PHC) & BATA Development (bata.io)
// https://github.com/BiznatchEnterprises/BitcoinFirewall
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "firewall.h"
#include "util.h"
#include "main.h"

using namespace std;
using namespace CBan;

string Firewall::ModuleName = "[Bitcoin Firewall 2.0.0]";


// * Global Firewall Variables *
bool Firewall::FirstRun = false;
int Firewall::AllCheck_Timer = GetTime();
int Firewall::AllCheck_MaxTimer = 3;  // minutes interval for some detection settings

/** Firewall Settings (General) **/
bool Firewall::Enabled = true;
bool Firewall::Blacklist_Autoclear = false;
bool Firewall::Bans_Autoclear = false;
int Firewall::Bans_MinNodes = 10;

// * Average Blockheight among Peers */
int Firewall::AverageHeight = 0;
int Firewall::AverageHeight_Min = 0;
int Firewall::AverageHeight_Max = 0;
double Firewall::AverageTraffic = 0;
double Firewall::AverageTraffic_Min = 0;
double Firewall::AverageTraffic_Max = 0;
int Firewall::AverageSend = 0;
int Firewall::AverageRecv = 0;

// * Firewall Settings (Exam) *
int Firewall::Average_Tolerance = 2;    // Reduce for minimal fluctuation 2 Blocks tolerance
int Firewall::Average_Range = 100;   // + or - Starting Height Range
double Firewall::Traffic_Tolerance;  // Reduce for minimal fluctuation
double Firewall::Traffic_Zone = 4;  // + or - Traffic Range 

// *** Firewall Settings (LiveDebug Output) ***
bool Firewall::LiveDebug_Enabled = false;
bool Firewall::LiveDebug_Exam = true;
bool Firewall::LiveDebug_Bans = true;
bool Firewall::LiveDebug_Blacklist = true;
bool Firewall::LiveDebug_Disconnect = true;
bool Firewall::LiveDebug_BandwidthAbuse = true;
bool Firewall::LiveDebug_DoubleSpend = true;
bool Firewall::LiveDebug_InvalidWallet = true;
bool Firewall::LiveDebug_ForkedWallet = true;
bool Firewall::LiveDebug_FloodingWallet = true;
bool Firewall::LiveDebug_DDoSWallet = true;

// *** Firewall Settings (Bandwidth Abuse) ***
bool Firewall::BandwidthAbuse_Detect = true;
bool Firewall::BandwidthAbuse_Blacklist = true;
bool Firewall::BandwidthAbuse_Ban = true;
int Firewall::BandwidthAbuse_BanTime = 0; // 24 hours
int Firewall::BandwidthAbuse_Maxcheck = 10;

// *** Firewall Settings (Double Spend Attack) ***
bool Firewall::DoubleSpend_Detect = true;
bool Firewall::DoubleSpend_Blacklist = true;
bool Firewall::DoubleSpend_Ban = true;
int Firewall::DoubleSpend_BanTime = 0; // 24 hours
int Firewall::DoubleSpend_Maxcheck = 10;
double Firewall::DoubleSpend_MinAttack = 17.1;
double Firewall::DoubleSpend_MaxAttack = 17.2;

// *** Firewall Settings (Invalid Peer Wallets) ***
bool Firewall::InvalidWallet_Detect = true;
bool Firewall::InvalidWallet_Blacklist = true;
bool Firewall::InvalidWallet_Ban = true;
int Firewall::InvalidWallet_BanTime = 0; // 24 hours
int Firewall::InvalidWallet_MinimumProtocol = MIN_PEER_PROTO_VERSION;
int Firewall::InvalidWallet_MaxCheck;

// * Firewall Settings (Forked Wallet)
bool Firewall::ForkedWallet_Detect = true;
bool Firewall::ForkedWallet_Blacklist = true;
bool Firewall::ForkedWallet_Ban = true;
int Firewall::ForkedWallet_BanTime = 0; //24 hours

// FORKLIST
int Firewall::ForkedWallet_NodeHeight[256] =
{
    10000,
    39486,
    48405
};

// *** Firewall Settings (Flooding Peer Wallets) ***
bool Firewall::FloodingWallet_Detect = true;
bool Firewall::FloodingWallet_Blacklist = true;
bool Firewall::FloodingWallet_Ban = true;
int Firewall::FloodingWallet_BanTime = 2600000; // 30 days
uint64_t Firewall::FloodingWallet_MinBytes = 1000000;
uint64_t Firewall::FloodingWallet_MaxBytes = 1000000;
double Firewall::FloodingWallet_MinTrafficAverage = 2000; // Ratio Up/Down
double Firewall::FloodingWallet_MaxTrafficAverage = 2000; // Ratio Up/Down
int Firewall::FloodingWallet_MinCheck = 30; // seconds
int Firewall::FloodingWallet_MaxCheck = 90; // seconds

// Flooding Wallet Attack Patterns
string Firewall::FloodingWallet_Patterns[256] =
{

};

// Flooding Wallet Ignored Patterns
string Firewall::FloodingWallet_Ignored[256] =
{
    ""
};

// * Firewall Settings (DDOS Wallet)
bool Firewall::DDoSWallet_Detect = true;
bool Firewall::DDoSWallet_Blacklist = true;
bool Firewall::DDoSWallet_Ban = true;
int Firewall::DDoSWallet_BanTime = 0; //24 hours
int Firewall::DDoSWallet_MinCheck = 30; // seconds

// Firewall Whitelist (ignore pnode->addrName)
string Firewall::WhiteList[256] =
{

};

// * Firewall BlackList (autoban/disconnect pnode->addrName)
string Firewall::BlackList[256] =
{

};

// * Function: LoadFirewallSettings (phc.conf)*
void Firewall::LoadFirewallSettings()
{
    // *** Firewall Settings (General) ***
    Firewall::Enabled = GetBoolArg("-firewallenabled", Firewall::Enabled);
    Firewall::Blacklist_Autoclear = GetBoolArg("-firewallclearblacklist", Firewall::Blacklist_Autoclear);
    Firewall::Bans_Autoclear = GetBoolArg("-firewallclearbanlist", Firewall::Bans_Autoclear);

    // * Firewall Settings (Exam) *
    Firewall::Traffic_Tolerance = GetArg("-firewalltraffictolerance", Firewall::Traffic_Tolerance);
    Firewall::Traffic_Zone = GetArg("-firewalltrafficzone", Firewall::Traffic_Zone);

    // *** Firewall Debug (Live Output) ***
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

    // *** Firewall Settings (Bandwidth Abuse) ***
    Firewall::BandwidthAbuse_Detect = GetBoolArg("-firewalldetectbandwidthabuse", Firewall::BandwidthAbuse_Detect);
    Firewall::BandwidthAbuse_Blacklist = GetBoolArg("-firewallblacklistbandwidthabuse", Firewall::BandwidthAbuse_Blacklist);
    Firewall::BandwidthAbuse_Ban = GetBoolArg("-firewallbanbandwidthabuse", Firewall::BandwidthAbuse_Ban);
    Firewall::BandwidthAbuse_BanTime = GetArg("-firewallbantimebandwidthabuse", Firewall::BandwidthAbuse_BanTime);
    Firewall::BandwidthAbuse_Maxcheck = GetArg("-firewallbandwidthabusemaxcheck", Firewall::BandwidthAbuse_Maxcheck);

    // *** Firewall Settings (DoubleSpend Abuse) ***
    Firewall::DoubleSpend_Detect = GetBoolArg("-firewalldetectdoublespend", Firewall::DoubleSpend_Detect);
    Firewall::DoubleSpend_Blacklist = GetBoolArg("-firewallblacklistdoublespend", Firewall::DoubleSpend_Blacklist);
    Firewall::DoubleSpend_Ban = GetBoolArg("-firewallbandoublespend", Firewall::DoubleSpend_Ban);
    Firewall::DoubleSpend_BanTime = GetArg("-firewallbantimedoublespend", Firewall::DoubleSpend_BanTime);
    Firewall::DoubleSpend_Maxcheck = GetArg("-firewalldoublespendmaxcheck", Firewall::DoubleSpend_Maxcheck);
    Firewall::DoubleSpend_MinAttack = GetArg("-firewalldoublespendminattack", Firewall::DoubleSpend_MinAttack);
    Firewall::DoubleSpend_MaxAttack = GetArg("-firewalldoublespendmaxattack", Firewall::DoubleSpend_MaxAttack);

    // *** Firewall Settings (Invalid Peer Wallets) ***
    Firewall::InvalidWallet_Detect = GetBoolArg("-firewalldetectinvalidwallet", Firewall::InvalidWallet_Detect);
    Firewall::InvalidWallet_Blacklist = GetBoolArg("-firewallblacklistinvalidwallet", Firewall::InvalidWallet_Blacklist);
    Firewall::InvalidWallet_Ban = GetBoolArg("-firewallbaninvalidwallet", Firewall::InvalidWallet_Ban);
    Firewall::InvalidWallet_MinimumProtocol = GetArg("-firewallinvalidwalletminprotocol", Firewall::InvalidWallet_MinimumProtocol);
    Firewall::InvalidWallet_Ban = GetArg("-firewallbaninvalidwallet", Firewall::InvalidWallet_Ban);
    Firewall::InvalidWallet_BanTime = GetArg("-firewallbantimeinvalidwallet", Firewall::InvalidWallet_BanTime);
    Firewall::InvalidWallet_MaxCheck = GetArg("-firewallinvalidwalletmaxcheck", Firewall::InvalidWallet_MaxCheck);

    // *** Firewall Settings (Forked Peer Wallets) ***
    Firewall::ForkedWallet_Detect = GetBoolArg("-firewalldetectforkedwallet", Firewall::ForkedWallet_Detect);
    Firewall::ForkedWallet_Blacklist = GetBoolArg("-firewallblacklistforkedwallet", Firewall::ForkedWallet_Blacklist);
    Firewall::ForkedWallet_Ban = GetBoolArg("-firewallbanforkedwallet", Firewall::ForkedWallet_Ban);
    Firewall::ForkedWallet_BanTime = GetArg("-firewallbantimeforkedwallet", Firewall::ForkedWallet_BanTime);

    // *** Firewall Settings (Flooding Peer Wallets) ***
    Firewall::FloodingWallet_Detect = GetBoolArg("-firewalldetectfloodingwallet", Firewall::FloodingWallet_Detect);
    Firewall::FloodingWallet_Blacklist = GetBoolArg("-firewallblacklistfloodingwallet", Firewall::FloodingWallet_Blacklist);
    Firewall::FloodingWallet_Ban = GetBoolArg("-firewallbanfloodingwallet", Firewall::FloodingWallet_Ban);
    Firewall::FloodingWallet_BanTime = GetArg("-firewallbantimefloodingwallet", Firewall::FloodingWallet_BanTime);
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

    // *** Firewall Settings (DDoS Wallets) ***
    Firewall::DDoSWallet_Detect = GetBoolArg("-firewalldetectddoswallet", Firewall::DDoSWallet_Detect);
    Firewall::DDoSWallet_Blacklist = GetBoolArg("-firewallblacklistddoswallet", Firewall::DDoSWallet_Blacklist);
    Firewall::DDoSWallet_Ban = GetBoolArg("-firewallbanddoswallet", Firewall::DDoSWallet_Ban);
    Firewall::DDoSWallet_BanTime = GetArg("-firewallbantimeddoswallet", Firewall::DDoSWallet_BanTime);
    Firewall::DDoSWallet_MinCheck = GetArg("-firewallmincheckddoswallet", Firewall::DDoSWallet_MinCheck);

    return;

}


// * Function: LegacySyncHeight
int Firewall::LegacySyncHeight(CNode *pnode)
{
    // Is the tx in a block that's in the main chain
    // ppcoin: known sent sync-checkpoint

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


// * Function: ForceDisconnectNode *
bool Firewall::ForceDisconnectNode(CNode *pnode, string FromFunction)
{
    TRY_LOCK(pnode->cs_vSend, lockSend);

    if (lockSend)
    {
        // release outbound grant (if any)
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


// * Function: CheckBlackList *
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


// * Function: CheckBanned*
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


// * Function: AddToBlackList *
bool Firewall::AddToBlackList(CNode *pnode)
{
    int TmpBlackListCount;
    TmpBlackListCount = CountStringArray(Firewall::BlackList);

        // Restart Blacklist count
        if (TmpBlackListCount >  255)
        {
            TmpBlackListCount = 0;
        }

        if (CheckBlackList(pnode) == false)
        {
            // increase Blacklist count
            TmpBlackListCount = TmpBlackListCount + 1;

            // Add node IP to blacklist
            Firewall::BlackList[TmpBlackListCount] = pnode->addrName;

            if (Firewall::LiveDebug_Enabled == true)
            {
                if (Firewall::LiveDebug_Blacklist == true)
                {
                    cout << ModuleName << " Blacklisted: " << pnode->addrName << "]\n" << endl;
                }
            }

            // Append Blacklist to debug.log
            if (fDebug)
            {
                LogPrint("firewall", "%s Blacklisted: %s\n", ModuleName.c_str(), pnode->addrName.c_str());
            }

            return true;
        }

    return false;

}


// * Function: AddToBanList *
bool Firewall::AddToBanList(CNode *pnode, BanReason BannedFor, int BanTime)
{
    CNode::Ban(pnode->addr, BannedFor, BanTime, false);

    //DumpBanlist();

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

string Firewall::BandwidthAbuseCheck(std::string AddrName, int SyncHeight, double TrafficAverage, int TimeConnected)
{
    std::string AttackCheckName = "Bandwidth Abuse";
    std::string Attack_Type;

    // ---Filter 1 -------------
    if (Firewall::BandwidthAbuse_Detect == true)
    {
        // ### Attack Detection ###
        // Calculate the ratio between Recieved bytes and Sent Bytes
        // Detect a valid syncronizaion vs. a flood attack
        
        if ((int)TimeConnected > Firewall::BandwidthAbuse_Maxcheck)
        {
            // * Attack detection #2
            // Node is further ahead on the chain than average minimum
            if (SyncHeight > Firewall::AverageHeight_Min)
            {
                if (TrafficAverage < Firewall::AverageTraffic_Min)
                {
                    // too low bandiwidth ratio limits
                    Attack_Type = "2-LowBW-HighHeight";
                }

                if (TrafficAverage > Firewall::AverageTraffic_Max)
                {
                    // too high bandiwidth ratio limits
                    Attack_Type = "2-HighBW-HighHeight";
                }
            }

            // * Attack detection #3
            // Node is behind on the chain than average minimum
            if (SyncHeight < Firewall::AverageHeight_Min)
            {  
                if (TrafficAverage < Firewall::AverageTraffic_Min)
                {
                    // too low bandiwidth ratio limits
                    Attack_Type = "3-LowBW-LowHeight";
                }

                if (TrafficAverage > Firewall::AverageTraffic_Max)
                {
                    // too high bandiwidth ratio limits
                    Attack_Type = "3-HighBW-LowHeight";
                }
            }
        }

        //--------------------------
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_BandwidthAbuse == true)
            {
                cout << ModuleName <<
                    " [Checking: " << AddrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Traffic Average: " << TrafficAverage << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
        }
        //--------------------------

        if (Attack_Type != "")
        {
            return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
        }
    }
    // ----------------

    return ""; // no attack detected
}


string Firewall::DoubleSpendCheck(std::string AddrName, int SyncHeight, uint64_t SendBytes, uint64_t RecvBytes, double TrafficAverage, int TimeConnected)
{
    std::string AttackCheckName = "Double Spend Wallet";
    std::string Attack_Type;

    if (Firewall::DoubleSpend_Detect == true)
    {
        // ### Attack Detection ###
        // Calculate the ratio between Recieved bytes and Sent Bytes
        // Detect a valid syncronizaion vs. a flood attack
        
        if ((int)TimeConnected > Firewall::DoubleSpend_Maxcheck)
        {
            // Node is behind on the chain than average minimum
            if (SyncHeight < Firewall::AverageHeight_Min)
            {  
                if (TrafficAverage > Firewall::AverageTraffic_Max)
                {
                    // too high bandiwidth ratio limits
                    Attack_Type = "Pattern Detected";
                
                    double tnTraffic = SendBytes / RecvBytes;

                    if (TrafficAverage < Firewall::AverageTraffic_Max)
                    {
                        if (tnTraffic < Firewall::DoubleSpend_MinAttack || tnTraffic > Firewall::DoubleSpend_MaxAttack)
                        {
                            // wallet full sync
                            Attack_Type = ""; // No Attack Detected
                        }
                    }

                    if (SendBytes > RecvBytes)
                    {
                        // wallet full sync
                        Attack_Type = "";  // No Attack Detected
                    }
                }
            }
        }

        //--------------------------
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_DoubleSpend == true)
            {
                cout << ModuleName <<
                    " [Checking: " << AddrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Send Bytes: " << SendBytes << "] " <<
                    "[Recv Bytes: " << RecvBytes << "] " <<
                    "[Traffic Average: " << TrafficAverage << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
        }
        //--------------------------

        if (Attack_Type != "")
        {
            return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
        }
    }
    // ----------------

    return ""; // no attack detected

}


string Firewall::InvalidWalletCheck(std::string AddrName, int StartingHeight, int RecvVersion, int TimeConnected)
{
    std::string AttackCheckName = "Invalid Wallet";
    std::string Attack_Type;

    if (Firewall::InvalidWallet_Detect == true)
    {
        // ### Attack Detection ###
        // Start Height = -1
        // Check for more than Firewall::InvalidWallet_MaxCheck minutes connection length
        if ((int)TimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for -1 blockheight
            if (StartingHeight == -1)
            {
                // Detetected
                Attack_Type = "1-StartHeight-Invalid";
            }
        }

        // Check for -1 blockheight
        if ((int)TimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for -1 blockheight
            if (StartingHeight < 0)
            {
                // Detected
                Attack_Type = "1-StartHeight-Invalid";
            }
        }
        
        // (Protocol: 0
        // Check for more than Firewall::InvalidWallet_MaxCheck minutes connection length
        if ((int)TimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for 0 protocol
            if (RecvVersion == 0)
            {
                //Detected
                Attack_Type = "1-Protocol-Invalid";
            }
        }

        // (Protocol: lower than 1
        // Check for more than Firewall::InvalidWallet_MaxCheck minutes connection length
        if ((int)TimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for 
            if (RecvVersion < 1)
            {
                // Detected
                Attack_Type = "1-Protocol-Invalid";
            }
        }

        // (Protocol: lower than mimimum protocol
        // Check for more than Firewall::InvalidWallet_MaxCheck minutes connection length
        if ((int)TimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for 
            if (RecvVersion < InvalidWallet_MinimumProtocol && RecvVersion > 209)
            {
                // Detected
                Attack_Type = "1-Protocol-Invalid";
            }
        }

        //// Resetting sync Height
        //if (TimeConnected > 60)
        //{
            //if (pnode->nSyncHeight > pnode->nSyncHeightCache)
            //{
                //pnode->nSyncHeightCache = pnode->nSyncHeight;
            //}

            //if (pnode->nSyncHeight < pnode->nSyncHeightCache - Firewall::AVERAGE_RANGE)
            //{
                // Trigger Blacklisting
                //ATTACK_TYPE = "1-SyncReset";
            //}

        //}
        // ##########################

        //--------------------------
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_InvalidWallet == true)
            {
                cout << ModuleName <<
                    " [Checking: " << AddrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Start Height: " << StartingHeight << "] " <<
                    "[Recv Version: " << RecvVersion << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
        }
        //--------------------------

        if (Attack_Type != "")
        {
            return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
        }
    }
    // ----------------

    return ""; // no attack detected

}

string Firewall::ForkedWalletCheck(std::string AddrName, int SyncHeight, int TimeConnected)
{
    std::string AttackCheckName = "Forked Wallet";
    std::string Attack_Type;

    if (Firewall::ForkedWallet_Detect == true)
    {
        // ### Attack Detection ###

        int i;
        int TmpSyncHeightCount;
        TmpSyncHeightCount = CountIntArray(Firewall::ForkedWallet_NodeHeight) - 2;
        
        if (TmpSyncHeightCount > 0)
        {
            for (i = 0; i < TmpSyncHeightCount; i++)
            { 
                // Check for Forked Wallet (stuck on blocks)
                if (SyncHeight == (int)Firewall::ForkedWallet_NodeHeight[i])
                {
                    Attack_Type = (int)Firewall::ForkedWallet_NodeHeight[i];
                }
            }          
        }
        // #######################

        //--------------------------
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_InvalidWallet == true)
            {
                cout << ModuleName <<
                    " [Checking: " << AddrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
        }
        //--------------------------

        if (Attack_Type != "")
        {
            return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
        }
    }
    // ----------------

    return ""; // no attack detected
}

string Firewall::FloodingWalletCheck(std::string AddrName, int SyncHeight, int StartingHeight, bool DetectedAttack, uint64_t SendBytes, uint64_t RecvBytes, double TrafficAverage, int TimeConnected)
{
    std::string AttackCheckName = "Flooding Wallet";
    std::string Attack_Type;
    std::string Warnings;

    if (Firewall::FloodingWallet_Detect == true)
    {
        // WARNING #1 - Too high of bandwidth with low BlockHeight
        if (SyncHeight < Firewall::AverageHeight_Min)
        {  
            if (TrafficAverage > Firewall::AverageTraffic_Max)
            {
                Warnings = Warnings + "1";
            }
        }
        
        // WARNING #2 - Send Bytes below minimum
        if (SendBytes < Firewall::FloodingWallet_MinBytes)
        {
            Warnings = Warnings + "2";
        }

        // WARNING #3 - Send Bytes above minimum
        if (SendBytes < Firewall::FloodingWallet_MinBytes)
        {
            Warnings = Warnings + "3";
        }

        // WARNING #4 - Send Bytes below maximum
        if (SendBytes < Firewall::FloodingWallet_MaxBytes)
        {
            Warnings = Warnings + "4";
        }

        // WARNING #5 - Send Bytes above maximum
        if (SendBytes > Firewall::FloodingWallet_MaxBytes)
        {
            Warnings = Warnings + "5";
        }

        // WARNING #6 - Recv Bytes above min 
        if (RecvBytes > Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "6";
        }

        // WARNING #7 - Recv Bytes below min
        if (RecvBytes < Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "7";
        }

        // WARNING #8 - Recv Bytes above max 
        if (RecvBytes > Firewall::FloodingWallet_MaxBytes / 2)
        {
            Warnings = Warnings + "8";
        }

        // WARNING #9 - Recv Bytes below max
        if (RecvBytes < Firewall::FloodingWallet_MaxBytes / 2)
        {
            Warnings = Warnings + "9";
        }

        // WARNING #10 - Recv Bytes above min 
        if (SendBytes > Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "10";
        }

        // WARNING #11 - Recv Bytes below min
        if (SendBytes < Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "11";
        }

        // WARNING #12 - Recv Bytes above max 
        if (SendBytes > Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "12";
        }

        // WARNING #13 - Recv Bytes below max
        if (SendBytes < Firewall::FloodingWallet_MinBytes / 2)
        {
            Warnings = Warnings + "13";
        }

        // WARNING #14 - 
        if (TrafficAverage > Firewall::FloodingWallet_MinTrafficAverage)
        {
            Warnings = Warnings + "14";
        }

        // WARNING #15 - 
        if (TrafficAverage < Firewall::FloodingWallet_MinTrafficAverage)
        {
            Warnings = Warnings + "15";
        }

        // WARNING #16 - 
        if (TrafficAverage > Firewall::FloodingWallet_MaxTrafficAverage)
        {
            Warnings = Warnings + "16";
        }

        // WARNING #17 - 
        if (TrafficAverage < Firewall::FloodingWallet_MaxTrafficAverage)
        {
            Warnings = Warnings + "17";
        }

        // WARNING #18 - Starting Height = SyncHeight above max
        if (StartingHeight == SyncHeight)
        {
            Warnings = Warnings + "18";
        }

        // WARNING #19 - Connected Time above min
        if ((int)TimeConnected > Firewall::FloodingWallet_MinCheck * 60)
        {
            Warnings = Warnings + "19";
        }

        // WARNING #20 - Connected Time below min
        if ((int)TimeConnected < Firewall::FloodingWallet_MinCheck * 60)
        {
            Warnings = Warnings + "20";
        }

        // WARNING #21 - Connected Time above max
        if ((int)TimeConnected > Firewall::FloodingWallet_MaxCheck * 60)
        {
            Warnings = Warnings + "21";
        }

        // WARNING #22 - Connected Time below max
        if ((int)TimeConnected < Firewall::FloodingWallet_MaxCheck * 60)
        {
            Warnings = Warnings + "22";
        }

        // WARNING #23 - Current BlockHeight
        if (SyncHeight > Firewall::AverageHeight)
        {  
            if (SyncHeight < Firewall::AverageHeight_Max)
            {  
                Warnings = Warnings + "23";
            }
        }

        // WARNING #24 - 
        if (SyncHeight < Firewall::AverageHeight_Max)
        {
            if (SyncHeight > Firewall::AverageHeight_Min)
            {
                Warnings = Warnings + "24";
            }
        }

        // WARNING #25 - 
        if (DetectedAttack == true)
        {
            Warnings = Warnings + "25";
        }      
    
        // Auto-Trigger Flooding Patterns
        // IF Warnings is matched to pattern DetectedAttack = TRUE
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

        // Ignore Flooding Patterns
        // IF Warnings is matched to pattern DETECTED_ATTACK = FALSE
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

        //--------------------------
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_InvalidWallet == true)
            {
                cout << ModuleName <<
                    " [Checking: " << AddrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Sync Height: " << SyncHeight << "] " <<
                    "[Start Height: " << StartingHeight << "] " <<
                    "[Prev Detected: " << DetectedAttack << "] " <<
                    "[Send Bytes: " << SendBytes << "] " <<
                    "[Recv Bytes: " << RecvBytes << "] " <<
                    "[Traffic Average: " << TrafficAverage << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "[Warnings: " << Warnings << "] " <<
                    "\n" << endl;
            }
        }
        //--------------------------

        if (Attack_Type != "")
        {
            return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
        }
    }
    // ----------------

    return ""; // no attack detected
}

string Firewall::DDoSCheck(std::string AddrName, int InvalidRecvPackets, uint64_t RecvBytes, int TimeConnected)
{
    std::string AttackCheckName = "DDoS Wallet";
    std::string Attack_Type;

    if (Firewall::DDoSWallet_Detect == true)
    {
        // Simple DDoS using invalid P2P packets/commands
        if ((int)TimeConnected > Firewall::DDoSWallet_MinCheck * 60)
        {
            if (InvalidRecvPackets > 0)
            {
                if (RecvBytes > 0)
                {
                    double InvalidPacketRatio = (InvalidRecvPackets / (RecvBytes / 1000));

                    if (InvalidPacketRatio > 1)
                    {
                        Attack_Type = "Invalid Packets";
                    }
                }
            }
        }

        //--------------------------
        if (Firewall::LiveDebug_Enabled == true)
        {
            if (Firewall::LiveDebug_DDoSWallet == true)
            {
                cout << ModuleName <<
                    " [Checking: " << AddrName << "] "
                    "[" << AttackCheckName << "] "
                    "[Detected: " << Attack_Type << "] " <<
                    "[Invalid Packets: " << InvalidRecvPackets << "] " <<
                    "[Recv Bytes: " << RecvBytes << "] " <<
                    "[Time Connected: " << TimeConnected << "] " <<
                    "\n" << endl;
            }
        }
        //--------------------------

        if (Attack_Type != "")
        {
            return "{" + AttackCheckName + ":" + Attack_Type + "}"; //attack detected
        }
    }
    // ----------------

    return ""; // no attack detected
}

/*
string Firewall::HighBanScoreCheck()
{

    // ---Filter (not used)-------------
    //if (DETECT_HIGH_BANSCORE == true)
    //{
        //DETECTED_ATTACK = false;

        //nMisbehavior
        //checkbanned function integration *todo*

        //if (DETECTED_ATTACK == true)
        //{
            //if (BlackList_HIGH_BANSCORE == true)
            //{
                //BLACKLIST_ATTACK = true;
            //}

            //if (BAN_HIGH_BANSCORE == true)
            //{
                //BAN_ATTACK = true;
                //BAN_TIME = BANTIME_HIGH_BANSCORE;
            //}

        //}
    //}
    //--------------------------
}
*/

// * Function: CheckAttack *
// Artificially Intelligent Attack Detection & Mitigation
bool Firewall::CheckAttack(CNode *pnode, string FromFunction)
{
    bool DETECTED_ATTACK = false;
    bool BLACKLIST_ATTACK = false;
    int BAN_TIME = 0; // Default 24 hours
    bool BAN_ATTACK = false;

    BanReason BAN_REASON{};

    string ATTACK_CHECK_LOG;
    string LIVE_DEBUG_LOG;

    int TimeConnected = GetTime() - pnode->nTimeConnected;

    int SyncHeight;

    SyncHeight = pnode->dCheckpointRecv.height; // Use Dynamic Checkpoints by default

    if (SyncHeight == 0)
    {
        SyncHeight = LegacySyncHeight(pnode); // ppcoin: known sent sync-checkpoint
    }

    if (SyncHeight == 0)
    {
        SyncHeight = pnode->nStartingHeight;
    }

    if (SyncHeight < pnode->nStartingHeight)
    {
        SyncHeight = pnode->nStartingHeight;
    }
   
    std::string Attack_Output;

    // ### Bandwidth Abuse Check & Attack Mitigation ###
    //
    Attack_Output = BandwidthAbuseCheck(pnode->addrName, SyncHeight, pnode->nTrafficAverage, TimeConnected);

    if (Attack_Output != "")
    {
        if (Firewall::BandwidthAbuse_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::BandwidthAbuse_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::BandwidthAbuse_BanTime;
            BAN_REASON = BanReasonBandwidthAbuse;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    // ##########################

    // ### Double Spend Check & Attack Mitigation ###
    //
    Attack_Output = DoubleSpendCheck(pnode->addrName, SyncHeight, pnode->nSendBytes, pnode->nRecvBytes, pnode->nTrafficAverage, TimeConnected);
    
    if (Attack_Output != "")
    {
        if (Firewall::DoubleSpend_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::DoubleSpend_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::BandwidthAbuse_BanTime;
            BAN_REASON = BanReasonDoubleSpendWallet;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    // ##########################

    // ### Invalid Wallet Check & Attack Mitigation ###
    //
    Attack_Output = InvalidWalletCheck(pnode->addrName, pnode->nStartingHeight, pnode->nRecvVersion, TimeConnected);
    
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

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    // ##########################


    // ### Forked Wallet Check & Attack Mitigation ###
    //
    Attack_Output = ForkedWalletCheck(pnode->addrName, SyncHeight, TimeConnected);
    
    if (Attack_Output != "")
    {
        if (Firewall::DoubleSpend_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::DoubleSpend_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::ForkedWallet_BanTime;
            BAN_REASON = BanReasonForkedWallet;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    // ##########################


    // ### Flooding Wallet Check & Attack Mitigation ###
    //
    Attack_Output = FloodingWalletCheck(pnode->addrName, SyncHeight, pnode->nStartingHeight, DETECTED_ATTACK, pnode->nSendBytes, pnode->nRecvBytes, pnode->nTrafficAverage, TimeConnected);
    
    if (Attack_Output != "")
    {
        if (Firewall::DoubleSpend_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::DoubleSpend_Ban == true)
        {
            BAN_ATTACK = true;
            BAN_TIME = Firewall::FloodingWallet_BanTime;
            BAN_REASON = BanReasonFloodingWallet;
        }

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    // ##########################

    // ### DDoS Check & Attack Mitigation ###
    //
    Attack_Output = DDoSCheck(pnode->addrName, pnode->nInvalidRecvPackets, pnode->nRecvBytes, TimeConnected);
    
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

        DETECTED_ATTACK = true;
        ATTACK_CHECK_LOG = ATTACK_CHECK_LOG + Attack_Output;
    }
    // ##########################

    // ----------------
    // ATTACK DETECTED (TRIGGER)!
    if (DETECTED_ATTACK == true)
    {
        if (ATTACK_CHECK_LOG != "")
        {
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

            // Blacklist IP on Attack detection
            // * add node/peer IP to blacklist
            if (BLACKLIST_ATTACK == true)
            {
                AddToBlackList(pnode);
            }

            // Peer/Node Ban if required
            if (BAN_ATTACK == true)
            {
                if (BAN_REASON > -1)
                {
                    AddToBanList(pnode, BAN_REASON, BAN_TIME);
                }
            }

            // Peer/Node Panic Disconnect
            ForceDisconnectNode(pnode, FromFunction);

            // ATTACK DETECTED!
            return true;

        }

    }

    //NO ATTACK DETECTED...
    return false;
}


// * Function: Examination *
void Firewall::Examination(CNode *pnode, string FromFunction)
{
    // Calculate new Height Average from all peers connected

    bool UpdateNodeStats = false;

    int SyncHeight;

    SyncHeight = pnode->dCheckpointRecv.height; // Use Dynamic Checkpoints by default

    if (SyncHeight == 0)
    {
        SyncHeight = LegacySyncHeight(pnode); // ppcoin: known sent sync-checkpoint
    }

    if (SyncHeight == 0)
    {
        SyncHeight = pnode->nStartingHeight;
    }

    if (SyncHeight < pnode->nStartingHeight)
    {
        SyncHeight = pnode->nStartingHeight;
    }
   
    // ** Update current average if increased ****
    if (SyncHeight > Firewall::AverageHeight) 
    {
        Firewall::AverageHeight = Firewall::AverageHeight + SyncHeight; 
        Firewall::AverageHeight = Firewall::AverageHeight / 2;
        Firewall::AverageHeight = Firewall::AverageHeight - Firewall::Average_Tolerance;      // reduce with tolerance
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
            Firewall::AverageTraffic = Firewall::AverageTraffic - (double)Firewall::Average_Tolerance;      // reduce with tolerance
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
                    cout << ModuleName << " [BlackListed Nodes/Peers: " << CountStringArray(Firewall::BlackList) << "] [Traffic: " << Firewall::AverageTraffic << "] [Traffic Min: " << Firewall::AverageTraffic_Min << "] [Traffic Max: " << Firewall::AverageTraffic_Max << "]" << " [Safe Height: " << Firewall::AverageHeight << "] [Height Min: " << Firewall::AverageHeight_Min << "] [Height Max: " << Firewall::AverageHeight_Max <<"] [Send Avrg: " << Firewall::AverageSend<< "] [Rec Avrg: " << Firewall::AverageRecv << "]\n" <<endl;

                    cout << ModuleName << "[Check Node IP: " << pnode->addrName.c_str() << "] [Traffic: " << pnode->nTrafficRatio << "] [Traffic Average: " << pnode->nTrafficAverage << "] [Starting Height: " << pnode->nStartingHeight << "] [Sync Height: " << pnode->dCheckpointRecv.height << "] [Node Sent: " << pnode->nSendBytes << "] [Node Recv: " << pnode->nRecvBytes << "] [Protocol: " << pnode->nRecvVersion << "]\n" << endl;
                }

            }

        }

    CheckAttack(pnode, FromFunction);
    }
}


// * Function: Init *
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
            // Check for Whitelisted Seed Node
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

        // Peer/Node Panic Disconnect
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

        // Peer/Node Panic Disconnect
        ForceDisconnectNode(pnode, FromFunction);

        return true;
    }

    // Perform a Node consensus examination
    Examination(pnode, FromFunction);

    // Peer/Node Safe    
    return false;
}

// |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||