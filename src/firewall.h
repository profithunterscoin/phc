// ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
// 
// [Bitcoin Firewall 2.0.0
// March, 2019 - Biznatch Enterprises & Profit Hunters Coin (PHC)
// https://github.com/BiznatchEnterprises/BitcoinFirewall
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <string>
#include "net.h"

class CNode;

extern bool fDebug;


class Firewall
{
    public:

        static std::string ModuleName;

        // * Global Firewall Variables *
        static bool FirstRun;
        static int AllCheck_Timer;
        static int AllCheck_MaxTimer;  // minutes interval for some detection settings

        /** Firewall Controls (General) **/
        static bool Enabled;
        static bool Blacklist_Autoclear;
        static bool Bans_Autoclear;
        static int Bans_MinNodes;

        // * Average Blockheight among Peers */
        static int AverageHeight;
        static int AverageHeight_Min;
        static int AverageHeight_Max;
        static double AverageTraffic;
        static double AverageTraffic_Min;
        static double AverageTraffic_Max;
        static int AverageSend;
        static int AverageRecv;

        // * Firewall Settings (Exam) *
        static int Average_Tolerance;       // Reduce for minimal fluctuation 2 Blocks tolerance
        static int Average_Range;   // + or - Starting Height Range
        static double Traffic_Tolerance;  // Reduce for minimal fluctuation
        static double Traffic_Zone;  // + or - Traffic Range 

        // *** Firewall Controls (General) ***
        static bool LiveDebug_Enabled;
        static bool LiveDebug_Exam;
        static bool LiveDebug_Bans;
        static bool LiveDebug_Blacklist;
        static bool LiveDebug_Disconnect;
        static bool LiveDebug_BandwidthAbuse;
        static bool LiveDebug_Nofalsepositive;
        static bool LiveDebug_InvalidWallet;
        static bool LiveDebug_ForkedWallet;
        static bool LiveDebug_FloodingWallet;

        // *** Firewall Settings (Bandwidth Abuse) ***
        static bool BandwidthAbuse_Detect;
        static bool BandwidthAbuse_Blacklist;
        static bool BandwidthAbuse_Nofalsepositive;
        static bool BandwidthAbuse_Ban;
        static int BandwidthAbuse_BanTime;
        static int BandwidthAbuse_Maxcheck;
        static double BandwidthAbuse_MinAttack;
        static double BandwidthAbuse_MaxAttack;

        // *** Firewall Controls (Invalid Peer Wallets) ***
        static bool InvalidWallet_Detect;
        static bool InvalidWallet_Blacklist;
        static bool InvalidWallet_Ban;
        static int InvalidWallet_BanTime;
        static int InvalidWallet_MinimumProtocol;
        static int InvalidWallet_MaxCheck;

        // * Firewall Settings (Invalid Wallet)
        static bool ForkedWallet_Detect;
        static bool ForkedWallet_Blacklist;
        static bool ForkedWallet_Ban;
        static int ForkedWallet_BanTime;

        // FORKLIST
        static int ForkedWallet_NodeHeight[256]; // TODO: Upgrade to vector<int> 

        // *** Firewall Settings (Flooding Peer Wallets) ***
        static bool FloodingWallet_Detect;
        static bool FloodingWallet_Blacklist;
        static bool FloodingWallet_Ban;
        static int FloodingWallet_BanTime;
        static int FloodingWallet_MinBytes;
        static int FloodingWallet_MaxBytes;
        static double FloodingWallet_MinTrafficAverage; // Ratio Up/Down
        static double FloodingWallet_MaxTrafficAverage; // Ratio Up/Down
        static int FloodingWallet_MinCheck; // seconds
        static int FloodingWallet_MaxCheck; // seconds
        static std::string FloodingWallet_Patterns[256]; // TODO: Upgrade to vector<string> 

        // Firewall Whitelist (ignore)
        static std::string WhiteList[256]; // TODO: Upgrade to vector<string> 

        // * Firewall BlackList Settings *
        static std::string BlackList[256]; // TODO: Upgrade to vector<string> 

        // * Firewall Functions *
        static void LoadFirewallSettings();
        static bool ForceDisconnectNode(CNode *pnode, std::string FromFunction);
        static bool CheckBlackList(CNode *pnode);
        static bool CheckBanned(CNode *pnode);
        static bool AddToBlackList(CNode *pnode);
        static bool AddToBanList(CNode *pnode, CBan::BanReason BAN_REASON, int BAN_TIME);
        static bool CheckAttack(CNode *pnode, std::string FromFunction);
        static void Examination(CNode *pnode, std::string FromFunction);
        static bool Init(CNode *pnode, std::string FromFunction);

};

// |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||