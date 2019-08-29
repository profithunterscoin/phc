/*
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
   ||||                                                                                             ||||
   |||| Bitcoin Firewall 2.0.0.3  Aug, 2019                                                         ||||
   |||| Biznatch Enterprises & Profit Hunters Coin (PHC) & BATA Development (bata.io)               ||||
   |||| https://github.com/BiznatchEnterprises/BitcoinFirewall                                      ||||
   |||| Distributed under the MIT/X11 software license, see the accompanying                        ||||
   |||| file COPYING or http://www.opensource.org/licenses/mit-license.php.                         ||||
   ||||                                                                                             ||||
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
*/

#include <string>
#include "net.h"

class CNode;

extern bool fDebug;


class Firewall
{
    public:

        // Eclipse Attack protection
        vector<pair<int, std::string>> PeerPrefixMap;

        /* VARIABLES: Global Firewall Variables */
        static std::string ModuleName;                      /* String                                               */
        static bool FirstRun;                               /* True/False                                           */
        static int AllCheck_Timer;                          /* Start Time                                           */
        static int AllCheck_MaxTimer;                       /* Minutes interval for some detection settings         */

        /* VARIABLES: Firewall Controls (General) */
        static bool Enabled;                                /* True/False                                           */
        static bool Blacklist_Autoclear;                    /* True/False                                           */
        static bool Bans_Autoclear;                         /* True/False                                           */
        static int Bans_MinNodes;                           /* Minimum connected nodes to auto-clear                */

        /* VARIABLES: Average Blockheight among Peers */
        static int AverageHeight;                           /* Peers Average Block Height                           */
        static int AverageHeight_Min;                       /* Peers Average Block Height Minimum Range             */
        static int AverageHeight_Max;                       /* Peers Average Block Height Maximum Range             */
        static double AverageTraffic;                       /* Peers Average Traffic Ratio                          */
        static double AverageTraffic_Min;                   /* Peers Average Traffic Ratio Minimum                  */
        static double AverageTraffic_Max;                   /* Peers Average Traffic Ratio Maximum                  */
        static int AverageSend;                             /* Peers Average Send Bytes                             */
        static int AverageRecv;                             /* Peers Average Recv Bytes                             */

        /* VARIABLES: Firewall Settings (Exam) */
        static int Average_Tolerance;                       /* Reduce for minimal fluctuation 2 Blocks tolerance    */
        static int Average_Range;                           /* + or - Starting Height Range                         */
        static double Traffic_Tolerance;                    /* Reduce for minimal fluctuation                       */
        static double Traffic_Zone;                         /* + or - Traffic Range                                 */

        /* VARIABLES: Firewall Controls (LiveDebug Output) */
        static bool LiveDebug_Enabled;                      /* True/False                                           */
        static bool LiveDebug_Exam;                         /* True/False                                           */
        static bool LiveDebug_Bans;                         /* True/False                                           */
        static bool LiveDebug_Blacklist;                    /* True/False                                           */
        static bool LiveDebug_Disconnect;                   /* True/False                                           */
        static bool LiveDebug_BandwidthAbuse;               /* True/False                                           */
        static bool LiveDebug_DoubleSpend;                  /* True/False                                           */
        static bool LiveDebug_InvalidWallet;                /* True/False                                           */
        static bool LiveDebug_ForkedWallet;                 /* True/False                                           */
        static bool LiveDebug_FloodingWallet;               /* True/False                                           */
        static bool LiveDebug_DDoSWallet;                   /* True/False                                           */

        /* VARIABLES: Firewall Settings (Bandwidth Abuse) */
        static bool BandwidthAbuse_Detect;                  /* True/False                                           */
        static bool BandwidthAbuse_Blacklist;               /* True/False                                           */
        static bool BandwidthAbuse_Ban;                     /* True/False                                           */
        static int BandwidthAbuse_BanTime;                  /* Seconds                                              */
        static bool BandwidthAbuse_Disconnect;              /* True/False                                           */
        static int BandwidthAbuse_Mincheck;                 /* Seconds                                              */

        /* VARIABLES: Firewall Settings (Double Spend Attack) */
        static bool DoubleSpend_Detect;                     /* True/False                                           */
        static bool DoubleSpend_Blacklist;                  /* True/False                                           */
        static bool DoubleSpend_DoubleSpend;                /* True/False                                           */
        static bool DoubleSpend_Ban;                        /* True/False                                           */
        static int DoubleSpend_BanTime;                     /* Seconds                                              */
        static bool DoubleSpend_Disconnect;                 /* True/False                                           */
        static int DoubleSpend_Mincheck;                    /* Seconds                                              */
        static double DoubleSpend_MinAttack;                /* Traffic Average Ratio Mimumum                        */
        static double DoubleSpend_MaxAttack;                /* Traffic Average Ratio Maximum                        */

        /* VARIABLES: Firewall Controls (Invalid Peer Wallets) */
        static bool InvalidWallet_Detect;                   /* True/False                                           */
        static bool InvalidWallet_Blacklist;                /* True/False                                           */
        static bool InvalidWallet_Ban;                      /* True/False                                           */
        static int InvalidWallet_BanTime;                   /* Seconds                                              */
        static bool InvalidWallet_Disconnect;               /* True/False                                           */
        static int InvalidWallet_MinimumProtocol;           /* Version                                              */
        static int InvalidWallet_MinCheck;                  /* Seconds                                              */

        /* VARIABLES: Firewall Settings (Invalid Wallet) */
        static bool ForkedWallet_Detect;                    /* True/False                                           */
        static bool ForkedWallet_Blacklist;                 /* True/False                                           */
        static bool ForkedWallet_Ban;                       /* True/False                                           */
        static int ForkedWallet_BanTime;                    /* Seconds                                              */
        static bool ForkedWallet_Disconnect;                /* True/False                                           */
        static int ForkedWallet_NodeHeight[256];            /* TODO: Upgrade to vector<int>                         */

        /* VARIABLES: Firewall Settings (Flooding Peer Wallets) */
        static bool FloodingWallet_Detect;                  /* True/False                                           */
        static bool FloodingWallet_Blacklist;               /* True/False                                           */
        static bool FloodingWallet_Ban;                     /* True/False                                           */
        static int FloodingWallet_BanTime;                  /* Seconds                                              */
        static bool FloodingWallet_Disconnect;              /* True/False                                           */
        static uint64_t FloodingWallet_MinBytes;            /* Minimum Bytes                                        */
        static uint64_t FloodingWallet_MaxBytes;            /* Maximum Bytes                                        */
        static double FloodingWallet_MinTrafficAverage;     /* Ratio Up/Down Minimum                                */
        static double FloodingWallet_MaxTrafficAverage;     /* Ratio Up/Down Maximum                                */
        static int FloodingWallet_MinCheck;                 /* Seconds                                              */
        static int FloodingWallet_MaxCheck;                 /* Seconds                                              */
        static std::string FloodingWallet_Patterns[256];    /* TODO: Upgrade to vector<string>                      */
        static std::string FloodingWallet_Ignored[256];     /* TODO: Upgrade to vector<string>                      */

        /* VARIABLES: Firewall Settings (DDoS Wallet) */
        static bool DDoSWallet_Detect;                      /* True/False                                           */
        static bool DDoSWallet_Blacklist;                   /* True/False                                           */
        static bool DDoSWallet_Ban;                         /* True/False                                           */
        static int DDoSWallet_BanTime;                      /* Seconds                                              */
        static bool DDoSWallet_Disconnect;                  /* True/False                                           */
        static int DDoSWallet_MinCheck;                     /* Seconds                                              */

        /* VARIABLE (Array): Firewall Whitelist (ignore)
            TODO: Upgrade to vector<string>
        */
        static std::string WhiteList[256];

        /* VARIABLE (Array): Firewall BlackList Settings
            TODO: Upgrade to vector<string> 
        */
        static std::string BlackList[256];

        /* FUNCTION: LoadFirewallSettings */
        static void LoadFirewallSettings();

        /* FUNCTION: LegacySyncHeight */
        static int LegacySyncHeight(CNode *pnode);

        /* FUNCTION: ForceDisconnectNode */
        static bool ForceDisconnectNode(CNode *pnode, std::string FromFunction);

        /* FUNCTION: CheckBlackList */
        static bool CheckBlackList(CNode *pnode);

        /* FUNCTION: CheckBanned */
        static bool CheckBanned(CNode *pnode);

        /* FUNCTION: AddToBlackList */
        static bool AddToBlackList(CNode *pnode);

        /* FUNCTION: AddToBanList */
        static bool AddToBanList(CNode *pnode, CBan::BanReason BAN_REASON, int BAN_TIME);

        /* FUNCTION: BandwidthAbuseCheck */
        static std::string BandwidthAbuseCheck(CNode *pnode, int SyncHeight, int TimeConnected);

        /* FUNCTION: DoubleSpendCheck */
        static std::string DoubleSpendCheck(CNode *pnode, int SyncHeight, int TimeConnected, std::string BandwidthAbuse_Output);
        
        /* FUNCTION: InvalidWalletCheck */
        static std::string InvalidWalletCheck(CNode *pnode, int SyncHeight, int TimeConnected);
        
        /* FUNCTION: ForkedWalletCheck */
        static std::string ForkedWalletCheck(CNode *pnode, int SyncHeight, int TimeConnected);
        
        /* FUNCTION: FloodingWalletCheck */
        static std::string FloodingWalletCheck(CNode *pnode, int SyncHeight, bool DetectedAttack, int TimeConnected, std::string BandwidthAbuse_Output);
        
        /* FUNCTION: DDoSCheck */
        static std::string DDoSCheck(CNode *pnode, int TimeConnected, std::string BandwidthAbuse_Output);
        
        /* FUNCTION: CheckAttack */
        static bool CheckAttack(CNode *pnode, std::string FromFunction);
        
        /* FUNCTION: Examination **/
        static void Examination(CNode *pnode, std::string FromFunction);

        /* FUNCTION: Init */
        static bool Init(CNode *pnode, std::string FromFunction);

};

/*
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
**/