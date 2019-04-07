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
bool Firewall::LiveDebug_Nofalsepositive = true;
bool Firewall::LiveDebug_InvalidWallet = true;
bool Firewall::LiveDebug_ForkedWallet = true;
bool Firewall::LiveDebug_FloodingWallet = true;

// *** Firewall Settings (Bandwidth Abuse) ***
bool Firewall::BandwidthAbuse_Detect = true;
bool Firewall::BandwidthAbuse_Blacklist = true;
bool Firewall::BandwidthAbuse_Nofalsepositive;
bool Firewall::BandwidthAbuse_Ban = true;
int Firewall::BandwidthAbuse_BanTime = 0; // 24 hours
int Firewall::BandwidthAbuse_Maxcheck = 10; 
double Firewall::BandwidthAbuse_MinAttack = 17.1;
double Firewall::BandwidthAbuse_MaxAttack = 17.2;

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
int Firewall::FloodingWallet_MinBytes = 1000000;
int Firewall::FloodingWallet_MaxBytes = 1000000;
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
    "157910121416202225",
    "23479111315171922232425",
    "23479111315171922232425",
    "2347911131517182022232425",
    "1234791113151718202225",
    "23479111315171820222425",
    "23479111315172022232425",
    "1234791113151718202225",
    "23479111315171819222425",
    ""
};

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
    Firewall::LiveDebug_Nofalsepositive = GetBoolArg("-firewalldebugnofalsepositivebandwidthabuse", Firewall::LiveDebug_Nofalsepositive);
    Firewall::LiveDebug_InvalidWallet = GetBoolArg("-firewalldebuginvalidwallet", Firewall::LiveDebug_InvalidWallet);
    Firewall::LiveDebug_ForkedWallet = GetBoolArg("-firewalldebugforkedwallet", Firewall::LiveDebug_ForkedWallet);
    Firewall::LiveDebug_FloodingWallet = GetBoolArg("-firewalldebugfloodingwallet", Firewall::LiveDebug_FloodingWallet);

    // *** Firewall Settings (Bandwidth Abuse) ***
    Firewall::BandwidthAbuse_Detect = GetBoolArg("-firewalldetectbandwidthabuse", Firewall::BandwidthAbuse_Detect);
    Firewall::BandwidthAbuse_Blacklist = GetBoolArg("-firewallblacklistbandwidthabuse", Firewall::BandwidthAbuse_Blacklist);
    Firewall::BandwidthAbuse_Ban = GetBoolArg("-firewallbanbandwidthabuse", Firewall::BandwidthAbuse_Ban);
    Firewall::BandwidthAbuse_Nofalsepositive = GetBoolArg("-firewallnofalsepositivebandwidthabuse", Firewall::BandwidthAbuse_Nofalsepositive);
    Firewall::BandwidthAbuse_BanTime = GetArg("-firewallbantimebandwidthabuse", Firewall::BandwidthAbuse_BanTime);
    Firewall::BandwidthAbuse_Maxcheck = GetArg("-firewallbandwidthabusemaxcheck", Firewall::BandwidthAbuse_Maxcheck);
    Firewall::BandwidthAbuse_MinAttack = GetArg("-firewallbandwidthabuseminattack", Firewall::BandwidthAbuse_MinAttack);
    Firewall::BandwidthAbuse_MaxAttack = GetArg("-firewallbandwidthabusemaxattack", Firewall::BandwidthAbuse_MaxAttack);

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
                cout << ModuleName << "Panic Disconnect: " << pnode->addrName << "]\n" << endl;
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
                    cout << ModuleName << "Blacklisted: " << pnode->addrName << "]\n" << endl;
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
            cout << ModuleName << "Banned: " << pnode->addrName << "]\n" << endl;
        }
    }

    return true;

}


// * Function: CheckAttack *
// Artificially Intelligent Attack Detection & Mitigation
bool Firewall::CheckAttack(CNode *pnode, string FromFunction)
{
    string WARNINGS = "";

    bool DETECTED_ATTACK = false;
    
    bool BLACKLIST_ATTACK = false;

    int BAN_TIME = 0; // Default 24 hours
    bool BAN_ATTACK = false;

    BanReason BAN_REASON{};

    string ATTACK_TYPE = "";
    string ATTACK_CHECK_NAME;
    string ATTACK_CHECK_LOG;

    int nTimeConnected = GetTime() - pnode->nTimeConnected;

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
   

    // ---Filter 1 -------------
    if (Firewall::BandwidthAbuse_Detect == true)
    {
        ATTACK_CHECK_NAME = "Bandwidth Abuse";

        // ### Attack Detection ###
        // Calculate the ratio between Recieved bytes and Sent Bytes
        // Detect a valid syncronizaion vs. a flood attack
        
        if (nTimeConnected > Firewall::BandwidthAbuse_Maxcheck)
        {
            // * Attack detection #2
            // Node is further ahead on the chain than average minimum
            if (SyncHeight > Firewall::AverageHeight_Min)
            {
                if (pnode->nTrafficAverage < Firewall::AverageTraffic_Min)
                {
                    // too low bandiwidth ratio limits
                    DETECTED_ATTACK = true;
                    ATTACK_TYPE = "2-LowBW-HighHeight";
                }

                if (pnode->nTrafficAverage > Firewall::AverageTraffic_Max)
                {
                    // too high bandiwidth ratio limits
                    DETECTED_ATTACK = true;
                    ATTACK_TYPE = "2-HighBW-HighHeight";
                }
            }

            // * Attack detection #3
            // Node is behind on the chain than average minimum
            if (SyncHeight < Firewall::AverageHeight_Min)
            {  
                if (pnode->nTrafficAverage < Firewall::AverageTraffic_Min)
                {
                    // too low bandiwidth ratio limits
                    DETECTED_ATTACK = true;
                    ATTACK_TYPE = "3-LowBW-LowHeight";
                }

                if (pnode->nTrafficAverage > Firewall::AverageTraffic_Max)
                {

                    // too high bandiwidth ratio limits
                    DETECTED_ATTACK = true;
                    ATTACK_TYPE = "3-HighBW-LowHeight";
                }
            }
        }

        if (Firewall::LiveDebug_BandwidthAbuse == true)
        {
            ATTACK_CHECK_LOG = ATTACK_CHECK_LOG  + " {" +  ATTACK_CHECK_NAME + ":" + BoolToString(DETECTED_ATTACK) + "}";
        }

    }
    // ----------------

    if (Firewall::BandwidthAbuse_Nofalsepositive == true)
    {
        ATTACK_CHECK_NAME = "No False Positive - Bandwidth Abuse";
        BAN_TIME = Firewall::BandwidthAbuse_BanTime;
        BAN_REASON = BanReasonBandwidthAbuse;

        // ### AVOID FALSE POSITIVE FROM BANDWIDTH ABUSE ###
        if (DETECTED_ATTACK == true)
        {

            if (ATTACK_TYPE == "2-LowBW-HighHeight")
            {
                ATTACK_TYPE = "";
                DETECTED_ATTACK = false;
            }   

            if (ATTACK_TYPE == "2-HighBW-HighHeight")
            {
                // Node/peer is in wallet sync (catching up to full blockheight)
                ATTACK_TYPE = "";
                DETECTED_ATTACK = false;
            }

            if (ATTACK_TYPE == "3-LowBW-LowHeight")
            {
                ATTACK_TYPE = "";
                DETECTED_ATTACK = false;
            }   

            if (ATTACK_TYPE == "3-HighBW-LowHeight")
            {
                BAN_TIME = Firewall::BandwidthAbuse_BanTime;
                BAN_REASON = BanReasonDoubleSpendWallet;
                ATTACK_TYPE = "Suspected: Double-Spend Attempt";
                
                double tnTraffic = pnode->nSendBytes / pnode->nRecvBytes;
                if (pnode->nTrafficAverage < Firewall::AverageTraffic_Max)
                {
                    if (tnTraffic < Firewall::BandwidthAbuse_MinAttack || tnTraffic > Firewall::BandwidthAbuse_MaxAttack)
                    {
                        // wallet full sync
                        ATTACK_TYPE = "";
                        DETECTED_ATTACK = false;
                    }
                }

                if (pnode->nSendBytes > pnode->nRecvBytes)
                {
                    // wallet full sync
                    ATTACK_TYPE = "";
                    DETECTED_ATTACK = false;
                }
            }   
        }
        
        if (Firewall::LiveDebug_Nofalsepositive == true)
        {
            ATTACK_CHECK_LOG = ATTACK_CHECK_LOG  + " {" +  ATTACK_CHECK_NAME + ":" + BoolToString(DETECTED_ATTACK) + "}";
        }

        // ##########################
    }

    // ### Attack Mitigation ###
    if (DETECTED_ATTACK == true)
    {
        if (Firewall::BandwidthAbuse_Blacklist == true)
        {
            BLACKLIST_ATTACK = true;
        }

        if (Firewall::BandwidthAbuse_Ban == true)
        {
            BAN_ATTACK = true;
        }

    }
    // ##########################
    // ----------------

    // ---Filter 2-------------
    if (Firewall::InvalidWallet_Detect == true)
    {
        ATTACK_CHECK_NAME = "Invalid Wallet";

        // ### Attack Detection ###
        // Start Height = -1
        // Check for more than Firewall::InvalidWallet_MaxCheck minutes connection length
        if (nTimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for -1 blockheight
            if (pnode->nStartingHeight == -1)
            {
                // Trigger Blacklisting
                DETECTED_ATTACK = true;
                ATTACK_TYPE = "1-StartHeight-Invalid";
            }
        }

        // Check for -1 blockheight
        if (nTimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for -1 blockheight
            if (pnode->nStartingHeight < 0)
            {
                // Trigger Blacklisting
                DETECTED_ATTACK = true;
                ATTACK_TYPE = "1-StartHeight-Invalid";
            }
        }
        
        // (Protocol: 0
        // Check for more than Firewall::InvalidWallet_MaxCheck minutes connection length
        if (nTimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for 0 protocol
            if (pnode->nRecvVersion == 0)
            {
                // Trigger Blacklisting
                DETECTED_ATTACK = true;
                ATTACK_TYPE = "1-Protocol-Invalid";
            }
        }

        // (Protocol: lower than 1
        // Check for more than Firewall::InvalidWallet_MaxCheck minutes connection length
        if (nTimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for 
            if (pnode->nRecvVersion < 1)
            {
                // Trigger Blacklisting
                DETECTED_ATTACK = true;
                ATTACK_TYPE = "1-Protocol-Invalid";
            }
        }

        // (Protocol: lower than mimimum protocol
        // Check for more than Firewall::InvalidWallet_MaxCheck minutes connection length
        if (nTimeConnected > Firewall::InvalidWallet_MaxCheck)
        {
            // Check for 
            if (pnode->nRecvVersion < InvalidWallet_MinimumProtocol && pnode->nRecvVersion > 209)
            {
                // Trigger Blacklisting
                DETECTED_ATTACK = true;
                ATTACK_TYPE = "1-Protocol-Invalid";
            }
        }


        //// Resetting sync Height
        //if (nTimeConnected > 60)
        //{
            //if (pnode->nSyncHeight > pnode->nSyncHeightCache)
            //{
                //pnode->nSyncHeightCache = pnode->nSyncHeight;
            //}

            //if (pnode->nSyncHeight < pnode->nSyncHeightCache - Firewall::AVERAGE_RANGE)
            //{
                // Trigger Blacklisting
                //DETECTED = true;
                //ATTACK_TYPE = "1-SyncReset";
            //}

        //}
        // ##########################

        if (Firewall::LiveDebug_InvalidWallet == true)
        {
            ATTACK_CHECK_LOG = ATTACK_CHECK_LOG  + " {" +  ATTACK_CHECK_NAME + ":" + BoolToString(DETECTED_ATTACK) + "}";
        }

        // ### Attack Mitigation ###
        if (DETECTED_ATTACK == true)
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
        }
        // ##########################
    }
    //--------------------------


    // ---Filter 3-------------
    if (Firewall::ForkedWallet_Detect == true)
    {

        ATTACK_CHECK_NAME = "Forked Wallet";

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
                    DETECTED_ATTACK = true;
                    ATTACK_TYPE = ATTACK_CHECK_NAME;
                }
            }          
        }
        // #######################

        // ### LIVE DEBUG OUTPUT ####
        if (Firewall::LiveDebug_ForkedWallet == true)
        {
            ATTACK_CHECK_LOG = ATTACK_CHECK_LOG  + " {" +  ATTACK_CHECK_NAME + ":" + BoolToString(DETECTED_ATTACK) + "}";
        }
        // #######################

        // ### Attack Mitigation ###
        if (DETECTED_ATTACK == true)
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
        }
        // #######################

    }
    //--------------------------


    // ---Filter 4-------------
    if (Firewall::FloodingWallet_Detect == true)
    {
        ATTACK_CHECK_NAME = "Flooding Wallet";

        std::size_t FLOODING_MAXBYTES = Firewall::FloodingWallet_MaxBytes;
        std::size_t FLOODING_MINBYTES = Firewall::FloodingWallet_MinBytes;

        // WARNING #1 - Too high of bandwidth with low BlockHeight
        if (SyncHeight < Firewall::AverageHeight_Min)
        {  
            if (pnode->nTrafficAverage > Firewall::AverageTraffic_Max)
            {
                WARNINGS = WARNINGS + "1";
            }
        }
        
        // WARNING #2 - Send Bytes below minimum
        if (pnode->nSendBytes < FLOODING_MINBYTES)
        {
            WARNINGS = WARNINGS + "2";
        }

        // WARNING #3 - Send Bytes above minimum
        if (pnode->nSendBytes < FLOODING_MINBYTES)
        {
            WARNINGS = WARNINGS + "3";
        }

        // WARNING #4 - Send Bytes below maximum
        if (pnode->nSendBytes < FLOODING_MAXBYTES)
        {
            WARNINGS = WARNINGS + "4";
        }

        // WARNING #5 - Send Bytes above maximum
        if (pnode->nSendBytes > FLOODING_MAXBYTES)
        {
            WARNINGS = WARNINGS + "5";
        }

        // WARNING #6 - Recv Bytes above min 
        if (pnode->nRecvBytes > FLOODING_MINBYTES / 2)
        {
            WARNINGS = WARNINGS + "6";
        }

        // WARNING #7 - Recv Bytes below min
        if (pnode->nRecvBytes < FLOODING_MINBYTES / 2)
        {
            WARNINGS = WARNINGS + "7";
        }

        // WARNING #8 - Recv Bytes above max 
        if (pnode->nRecvBytes > FLOODING_MAXBYTES / 2)
        {
            WARNINGS = WARNINGS + "8";
        }

        // WARNING #9 - Recv Bytes below max
        if (pnode->nRecvBytes < FLOODING_MAXBYTES / 2)
        {
            WARNINGS = WARNINGS + "9";
        }

        // WARNING #10 - Recv Bytes above min 
        if (pnode->nSendBytes > FLOODING_MINBYTES / 2)
        {
            WARNINGS = WARNINGS + "10";
        }

        // WARNING #11 - Recv Bytes below min
        if (pnode->nSendBytes < FLOODING_MINBYTES / 2)
        {
            WARNINGS = WARNINGS + "11";
        }

        // WARNING #12 - Recv Bytes above max 
        if (pnode->nSendBytes > FLOODING_MINBYTES / 2)
        {
            WARNINGS = WARNINGS + "12";
        }

        // WARNING #13 - Recv Bytes below max
        if (pnode->nSendBytes < FLOODING_MINBYTES / 2)
        {
            WARNINGS = WARNINGS + "13";
        }

        // WARNING #14 - 
        if (pnode->nTrafficAverage > Firewall::FloodingWallet_MinTrafficAverage)
        {
            WARNINGS = WARNINGS + "14";
        }

        // WARNING #15 - 
        if (pnode->nTrafficAverage < Firewall::FloodingWallet_MinTrafficAverage)
        {
            WARNINGS = WARNINGS + "15";
        }

        // WARNING #16 - 
        if (pnode->nTrafficAverage > Firewall::FloodingWallet_MaxTrafficAverage)
        {
            WARNINGS = WARNINGS + "16";
        }

        // WARNING #17 - 
        if (pnode->nTrafficAverage < Firewall::FloodingWallet_MaxTrafficAverage)
        {
            WARNINGS = WARNINGS + "17";
        }

        // WARNING #18 - Starting Height = SyncHeight above max
        if (pnode->nStartingHeight == SyncHeight)
        {
            WARNINGS = WARNINGS + "18";
        }

        // WARNING #19 - Connected Time above min
        if (nTimeConnected > Firewall::FloodingWallet_MinCheck * 60)
        {
            WARNINGS = WARNINGS + "19";
        }

        // WARNING #20 - Connected Time below min
        if (nTimeConnected < Firewall::FloodingWallet_MinCheck * 60)
        {
            WARNINGS = WARNINGS + "20";
        }

        // WARNING #21 - Connected Time above max
        if (nTimeConnected > Firewall::FloodingWallet_MaxCheck * 60)
        {
            WARNINGS = WARNINGS + "21";
        }

        // WARNING #22 - Connected Time below max
        if (nTimeConnected < Firewall::FloodingWallet_MaxCheck * 60)
        {
            WARNINGS = WARNINGS + "22";
        }

        // WARNING #23 - Current BlockHeight
        if (SyncHeight > Firewall::AverageHeight)
        {  
            if (SyncHeight < Firewall::AverageHeight_Max)
            {  
                WARNINGS = WARNINGS + "23";
            }
        }

        // WARNING #24 - 
        if (SyncHeight < Firewall::AverageHeight_Max)
        {
            if (SyncHeight > Firewall::AverageHeight_Min)
            {
                WARNINGS = WARNINGS + "24";
            }
        }

        // WARNING #25 - 
        if (DETECTED_ATTACK == true)
        {
            WARNINGS = WARNINGS + "25";
        }      
    
        // Auto-Trigger Flooding Patterns
        // IF WARNINGS is matched to pattern DETECTED_ATTACK = TRUE
        int i;
        int TmpFloodingWallet_PatternsCount;

        TmpFloodingWallet_PatternsCount = CountStringArray(Firewall::FloodingWallet_Patterns);

        if (TmpFloodingWallet_PatternsCount > 0)
        {
            for (i = 0; i < TmpFloodingWallet_PatternsCount; i++)
            {  
                if (Firewall::FloodingWallet_Patterns[i] != "")
                {
                    if (WARNINGS == Firewall::FloodingWallet_Patterns[i])
                    {
                        DETECTED_ATTACK = true;
                        ATTACK_TYPE = ATTACK_CHECK_NAME;
                    }
                }
            }
        }

        // Ignore Flooding Patterns
        // IF WARNINGS is matched to pattern DETECTED_ATTACK = FALSE
        int TmpFloodingWallet_IgnoredCount;

        TmpFloodingWallet_IgnoredCount = CountStringArray(Firewall::FloodingWallet_Ignored);

        if (TmpFloodingWallet_IgnoredCount > 0)
        {
            for (i = 0; i < TmpFloodingWallet_IgnoredCount; i++)
            {  
                if (Firewall::FloodingWallet_Ignored[i] != "")
                {
                    if (WARNINGS == Firewall::FloodingWallet_Ignored[i])
                    {
                        DETECTED_ATTACK = false;
                        ATTACK_TYPE = "";
                    }
                }
            }
        }

        if (DETECTED_ATTACK == true)
        {
            BAN_TIME = Firewall::FloodingWallet_BanTime;
            BAN_REASON = BanReasonFloodingWallet;
        }

        // Simple DDoS using invalid P2P packets/commands
        if (nTimeConnected > Firewall::FloodingWallet_MinCheck * 60)
        {
            if (pnode->nInvalidRecvPackets > 0)
            {
                if (pnode->nRecvBytes > 0)
                {
                    double InvalidPacketRatio = (pnode->nInvalidRecvPackets / (pnode->nRecvBytes / 1000));

                    if (InvalidPacketRatio > 1)
                    {
                        DETECTED_ATTACK = true;
                        ATTACK_TYPE = ATTACK_CHECK_NAME;
                        BAN_TIME = Firewall::FloodingWallet_BanTime;
                        BAN_REASON = BanReasonDDoSWallet;
                    }
                }
            }
        }

        // ### LIVE DEBUG OUTPUT ####
        if (Firewall::LiveDebug_FloodingWallet == true)
        {
            ATTACK_CHECK_LOG = ATTACK_CHECK_LOG  + " {" +  ATTACK_CHECK_NAME + ":" + WARNINGS + ":" + BoolToString(DETECTED_ATTACK) + "}";
        }
        // #######################

        if (DETECTED_ATTACK == true)
        {
            if (Firewall::FloodingWallet_Blacklist == true)
            {
                BLACKLIST_ATTACK = true;
            }

            if (Firewall::FloodingWallet_Ban == true)
            {
                BAN_ATTACK = true;
            }

        }
    }
    //--------------------------


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


    //--------------------------
    if (Firewall::LiveDebug_Enabled == true)
    {
        cout << ModuleName << " [Checking: " << pnode->addrName << "] [Attacks:" << ATTACK_CHECK_LOG << "]\n" << endl;
    }
    //--------------------------

    // ----------------
    // ATTACK DETECTED (TRIGGER)!
    if (DETECTED_ATTACK == true)
    {
        if (Firewall::LiveDebug_Enabled == true)
        {
            cout << ModuleName <<
            " [Attack Type: " << ATTACK_TYPE <<
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
            LogPrint("firewall", "%s [Attack Type: %s] "
                                    "[Detected from: %s] "
                                    "[Node Traffic: %d] "
                                    "[Node Traffic Avrg: %d] "
                                    "[Traffic Avrg: %d] "
                                    "[Sent Bytes: %d] "
                                    "[Recv Bytes: %d] "
                                    "[Start Height: %i] "
                                    "[Sync Height: %i] "
                                    "[Protocol: %i]"
                                    "[Warnings: %s]\n",

                                    ModuleName.c_str(),
                                    ATTACK_TYPE.c_str(),
                                    pnode->addrName.c_str(),
                                    pnode->nTrafficRatio,
                                    pnode->nTrafficAverage,
                                    Firewall::AverageTraffic,
                                    pnode->nSendBytes,
                                    pnode->nRecvBytes,
                                    pnode->nStartingHeight,
                                    SyncHeight,
                                    pnode->nRecvVersion,
                                    WARNINGS);
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
    else
    {
        //NO ATTACK DETECTED...
        return false;
    }
    // ----------------
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