// ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
// 
// [Bitcoin Firewall 2.0.1
// April, 2019 - Biznatch Enterprises & Profit Hunters Coin (PHC) & BATA Development (bata.io)
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
        static bool LiveDebug_DoubleSpend;
        static bool LiveDebug_InvalidWallet;
        static bool LiveDebug_ForkedWallet;
        static bool LiveDebug_FloodingWallet;
        static bool LiveDebug_DDoSWallet;

        // *** Firewall Settings (Bandwidth Abuse) ***
        static bool BandwidthAbuse_Detect;
        static bool BandwidthAbuse_Blacklist;
        static bool BandwidthAbuse_Ban;
        static int BandwidthAbuse_BanTime; // seconds
        static bool BandwidthAbuse_Disconnect;
        static int BandwidthAbuse_Mincheck; // seconds

        // *** Firewall Settings (Double Spend Attack) ***
        static bool DoubleSpend_Detect;
        static bool DoubleSpend_Blacklist;
        static bool DoubleSpend_DoubleSpend;
        static bool DoubleSpend_Ban;
        static int DoubleSpend_BanTime; // seconds
        static bool DoubleSpend_Disconnect;
        static int DoubleSpend_Mincheck; // seconds
        static double DoubleSpend_MinAttack;
        static double DoubleSpend_MaxAttack;

        // *** Firewall Controls (Invalid Peer Wallets) ***
        static bool InvalidWallet_Detect;
        static bool InvalidWallet_Blacklist;
        static bool InvalidWallet_Ban;
        static int InvalidWallet_BanTime; // seconds
        static bool InvalidWallet_Disconnect;
        static int InvalidWallet_MinimumProtocol;
        static int InvalidWallet_MinCheck; // seconds

        // * Firewall Settings (Invalid Wallet)
        static bool ForkedWallet_Detect;
        static bool ForkedWallet_Blacklist;
        static bool ForkedWallet_Ban;
        static int ForkedWallet_BanTime; // seconds
        static bool ForkedWallet_Disconnect;
        static int ForkedWallet_NodeHeight[256]; // TODO: Upgrade to vector<int> 

        // *** Firewall Settings (Flooding Peer Wallets) ***
        static bool FloodingWallet_Detect;
        static bool FloodingWallet_Blacklist;
        static bool FloodingWallet_Ban;
        static int FloodingWallet_BanTime;
        static bool FloodingWallet_Disconnect;
        static uint64_t FloodingWallet_MinBytes;
        static uint64_t FloodingWallet_MaxBytes;
        static double FloodingWallet_MinTrafficAverage; // Ratio Up/Down
        static double FloodingWallet_MaxTrafficAverage; // Ratio Up/Down
        static int FloodingWallet_MinCheck; // seconds
        static int FloodingWallet_MaxCheck; // seconds
        static std::string FloodingWallet_Patterns[256]; // TODO: Upgrade to vector<string>
        static std::string FloodingWallet_Ignored[256]; // TODO: Upgrade to vector<string> 

        // * Firewall Settings (DDoS Wallet)
        static bool DDoSWallet_Detect;
        static bool DDoSWallet_Blacklist;
        static bool DDoSWallet_Ban;
        static int DDoSWallet_BanTime; // seconds
        static bool DDoSWallet_Disconnect;
        static int DDoSWallet_MinCheck; // seconds

        // Firewall Whitelist (ignore)
        static std::string WhiteList[256]; // TODO: Upgrade to vector<string> 

        // * Firewall BlackList Settings *
        static std::string BlackList[256]; // TODO: Upgrade to vector<string> 

        // * Firewall Functions *
        static void LoadFirewallSettings();
        static int LegacySyncHeight(CNode *pnode);
        static bool ForceDisconnectNode(CNode *pnode, std::string FromFunction);
        static bool CheckBlackList(CNode *pnode);
        static bool CheckBanned(CNode *pnode);
        static bool AddToBlackList(CNode *pnode);
        static bool AddToBanList(CNode *pnode, CBan::BanReason BAN_REASON, int BAN_TIME);
        static std::string BandwidthAbuseCheck(std::string AddrName, int SyncHeight, double TrafficAverage, int TimeConnected);
        static std::string DoubleSpendCheck(std::string AddrName, int SyncHeight, uint64_t SendBytes, uint64_t RecvBytes, double TrafficAverage, int TimeConnected);
        static std::string InvalidWalletCheck(std::string AddrName, int StartingHeight, int RecvVersion, int TimeConnected);
        static std::string ForkedWalletCheck(std::string AddrName, int SyncHeight, int TimeConnected);
        static std::string FloodingWalletCheck(std::string AddrName, int SyncHeight, int StartingHeight, bool DetectedAttack, uint64_t SendBytes, uint64_t RecvBytes, double TrafficAverage, int TimeConnected);
        static std::string DDoSCheck(std::string AddrName, int InvalidRecvPackets, uint64_t RecvBytes, int TimeConnected);
        static bool CheckAttack(CNode *pnode, std::string FromFunction);
        static void Examination(CNode *pnode, std::string FromFunction);
        static bool Init(CNode *pnode, std::string FromFunction);

};

// |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||