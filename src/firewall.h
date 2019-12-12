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


#include <string>
#include "net.h"


class CNode;

extern bool fDebug;


namespace FirewallData
{
    class PeerMap
    {
        public:

            PeerMap();
            PeerMap(std::string IP);
            PeerMap(std::string IP, std::string Version);
            PeerMap(std::string IP, std::string Version, int TimeConnected);
            PeerMap(std::string IP, std::string Version, int TimeConnected, uint64_t SendBytes);
            PeerMap(std::string IP, std::string Version, int TimeConnected, uint64_t SendBytes, uint64_t ReceiveBytes);
            PeerMap(std::string IP, std::string Version, int TimeConnected, uint64_t SendBytes, uint64_t ReceiveBytes, int AddrRecvCount);

            IMPLEMENT_SERIALIZE
            (
                READWRITE(IP);

                READWRITE(Version);

                READWRITE(TimeConnected);

                READWRITE(SendBytes);
                READWRITE(ReceiveBytes);

                READWRITE(AddrRecvCount);
            )

            std::string IP;                                                 /* Peer IP Address                      */
            std::string Version;                                            /* Peer Version                         */

            int TimeConnected;                                              /* Peer Time Connected (Seconds)        */

            int StartHeight;                                                /* Peer Block Start Height              */

            uint64_t SendBytes;                                             /* Peer SendBytes                       */
            uint64_t ReceiveBytes;                                          /* Peer ReceiveBytes                    */

            int AddrRecvCount;                                              /* Peer Addr Recv Count                 */
            std::vector<pair<std::string, int>> AddrRecvPrefixes;

            uint256 HashAskedFor;                                           /* Peer last Hash Asked For             */
            uint256 HashReceived;                                           /* Peer last Hash Received              */

            int BlocksAccepted;                                             /* Total blocks accepted from peer      */
    };
}


namespace Firewall
{
    class Settings
    {
        public:

            static std::string ModuleName;                                  /* String                               */
            
            /* VARIABLES: Global Firewall Variables */
            static int AllCheck_Timer;                                      /* Start Time                           */
            static int AllCheck_MaxTimer;                                   /* Minutes cycle for detection          */

            /* VARIABLES: Firewall Controls (General) */
            static bool Enabled;                                            /* True/False                           */
            static bool Denied_Autoclear;                                   /* True/False                           */
            static bool Banned_Autoclear;                                   /* True/False                           */
            static int Banned_MinNodes;                                     /* Min connected nodes before clearbans */

            /* VARIABLES: Firewall Settings (Exam) */
            static int Average_Tolerance;                                   /* Min fluctuation 2 Blocks tolerance   */
            static int Average_Range;                                       /* + or - Starting Height Range         */
            static double Traffic_Tolerance;                                /* Reduce for minimal fluctuation       */
            static double Traffic_Zone;                                     /* + or - Traffic Range                 */

    };


    class Stats
    {
        public:

            /* VARIABLES: Average Blockheight among Peers */
            static int AverageHeight;                                       /* Average Block Height                 */
            static int AverageHeight_Min;                                   /* Average Block Height Min Range       */
            static int AverageHeight_Max;                                   /* Average Block Height Max Range       */
            static double AverageTraffic;                                   /* Average Traffic Ratio                */
            static double AverageTraffic_Min;                               /* Average Traffic Ratio Min            */
            static double AverageTraffic_Max;                               /* Average Traffic Ratio Max            */
            static int AverageSend;                                         /* Average Send Bytes                   */
            static int AverageRecv;                                         /* Average Recv Bytes                   */
    
            // PeerMap vector of pair: Timestamp, PeerMapEntry
            static std::vector<pair<int, FirewallData::PeerMap>> PeerMap;

    };

    class Lists
    {
        public:

            /* VARIABLE (Array): Allowed List Default
                TODO: Upgrade to vector<string>
            */
            static std::string Allowed[256];

            /* VARIABLE (Array): Denied List Default
                TODO: Upgrade to vector<string> 
            */
            static std::string Denied[256];

            /* FUNCTION: Check (Allowed/Denied) */
            static bool Check(CNode *pnode, std::string ListType);

            /* FUNCTION: Add */
            static bool Add(CNode *pnode, std::string ListType);

            /* FUNCTION: Remove */
            static bool Remove(CNode *pnode, std::string ListType);

            /* FUNCTION: Count */
            static int Count(std::string ListType);

            /* FUNCTION: Clear */
            static bool Clear(std::string ListType);
    };


    class LiveDebug
    {
        public:

            /* VARIABLES: Firewall Controls (LiveDebug Output) */
            static bool Enabled;                                            /* True/False                           */
            static bool Exam;                                               /* True/False                           */
            static bool CheckAttack;                                        /* True/False                           */
            static bool Bans;                                               /* True/False                           */
            static bool Denied;                                             /* True/False                           */
            static bool Disconnect;                                         /* True/False                           */
            static bool BandwidthAbuse;                                     /* True/False                           */
            static bool DoubleSpend;                                        /* True/False                           */
            static bool InvalidWallet;                                      /* True/False                           */
            static bool ForkedWallet;                                       /* True/False                           */
            static bool FloodingWallet;                                     /* True/False                           */
            static bool DDoSWallet;                                         /* True/False                           */
            static bool EclipseWallet;                                      /* True/False                           */
            static bool ErebusWallet;                                       /* True/False                           */
            static bool BGPWallet;                                          /* True/False                           */
            static bool ResettingSyncWallet;                                /* True/False                           */              

    };

    class BandwidthAbuse
    {
        public:

            /* VARIABLES: Firewall Settings (Bandwidth Abuse) */
            static bool Detect;                                             /* True/False                           */
            static bool Denied;                                             /* True/False                           */
            static bool Ban;                                                /* True/False                           */
            static int BanTime;                                             /* Seconds                              */
            static bool Disconnect;                                         /* True/False                           */
            static int MinCheck;                                            /* Seconds                              */
            
            /* FUNCTION: BandwidthAbuseCheck */
            static std::string Check(CNode *pnode, int SyncHeight, int TimeConnected);

    };


    class DoubleSpend
    {
        public:

            /* VARIABLES: Firewall Settings (Double Spend Attack) */
            static bool Detect;                                             /* True/False                           */
            static bool Denied;                                             /* True/False                           */
            static bool Ban;                                                /* True/False                           */
            static int BanTime;                                             /* Seconds                              */
            static bool Disconnect;                                         /* True/False                           */
            static int MinCheck;                                            /* Seconds                              */
            static double MinAttack;                                        /* Traffic Average Ratio Mimumum        */
            static double MaxAttack;                                        /* Traffic Average Ratio Maximum        */
    
            /* FUNCTION: DoubleSpend::Check */
            static std::string Check(CNode *pnode, int SyncHeight, int TimeConnected, std::string BandwidthAbuse_Output);

    };



    class InvalidWallet
    {
        public:

            /* VARIABLES: Firewall Controls (Invalid Peer Wallets) */
            static bool Detect;                                             /* True/False                           */
            static bool Denied;                                             /* True/False                           */
            static bool Ban;                                                /* True/False                           */
            static int BanTime;                                             /* Seconds                              */
            static bool Disconnect;                                         /* True/False                           */
            static int MinimumProtocol;                                     /* Version                              */
            static int MinCheck;                                            /* Seconds                              */
            
            /* FUNCTION: InvalidWallet::Check */
            static std::string Check(CNode *pnode, int SyncHeight, int TimeConnected);

    };



    class ForkedWallet
    {
        public:

            /* VARIABLES: Firewall Settings (Invalid Wallet) */
            static bool Detect;                                             /* True/False                           */
            static bool Denied;                                             /* True/False                           */
            static bool Ban;                                                /* True/False                           */
            static int BanTime;                                             /* Seconds                              */
            static bool Disconnect;                                         /* True/False                           */
            static int NodeHeight[256];                                     /* TODO: Upgrade to vector<int>         */
            static int MinCheck;                                            /* Seconds                              */

            /* FUNCTION: ForkedWallet::Check */
            static std::string Check(CNode *pnode, int SyncHeight, int TimeConnected);

    };


    class FloodingWallet
    {
        public:

            /* VARIABLES: Firewall Settings (Flooding Peer Wallets) */
            static bool Detect;                                             /* True/False                           */
            static bool Denied;                                             /* True/False                           */
            static bool Ban;                                                /* True/False                           */
            static int BanTime;                                             /* Seconds                              */
            static bool Disconnect;                                         /* True/False                           */
            static uint64_t MinBytes;                                       /* Minimum Bytes                        */
            static uint64_t MaxBytes;                                       /* Maximum Bytes                        */
            static double MinTrafficAverage;                                /* Ratio Up/Down Minimum                */
            static double MaxTrafficAverage;                                /* Ratio Up/Down Maximum                */
            static int MinCheck;                                            /* Seconds                              */
            static int MaxCheck;                                            /* Seconds                              */
            static std::string Patterns[256];                               /* TODO: Upgrade to vector<string>      */
            static std::string Ignored[256];                                /* TODO: Upgrade to vector<string>      */

            /* FUNCTION: FloodingWallet::Check */
            static std::string Check(CNode *pnode, int SyncHeight, bool DetectedAttack, int TimeConnected, std::string BandwidthAbuse_Output);

    };


    class DDoSWallet
    {
        public:

            /* VARIABLES: Firewall Settings (DDoS Wallet) */
            static bool Detect;                                             /* True/False                               */
            static bool Denied;                                             /* True/False                                  */
            static bool Ban;                                                /* True/False                               */
            static int BanTime;                                             /* Seconds                                  */
            static bool Disconnect;                                         /* True/False                               */
            static int MinCheck;                                            /* Seconds                                  */
            
            /* FUNCTION: DDoSWallet::Check */
            static std::string Check(CNode *pnode, int TimeConnected, std::string BandwidthAbuse_Output);

    };


    class EclipseWallet
    {
        public:

            /* VARIABLES: Firewall Settings (Eclipse Attack) */
            static bool Detect;                                             /* True/False                               */
            static bool Denied;                                             /* True/False                                  */
            static bool Ban;                                                /* True/False                               */
            static int BanTime;                                             /* Seconds                                  */
            static bool Disconnect;                                         /* True/False                               */
            static int MinCheck;                                            /* Seconds                                  */

            /* FUNCTION: EclipseWallet::Check */
            static std::string Check(CNode *pnode, int SyncHeight, int TimeConnected);

    };


    class ErebusWallet
    {
        public:

            /* VARIABLES: Firewall Settings (Erebus Attack) */
            static bool Detect;                                             /* True/False                               */
            static bool Denied;                                             /* True/False                                  */
            static bool Ban;                                                /* True/False                               */
            static int BanTime;                                             /* Seconds                                  */
            static bool Disconnect;                                         /* True/False                               */
            static int MinCheck;                                            /* Seconds                                  */
            
            /* FUNCTION: ErebusWallet::Check */
            static std::string Check(CNode *pnode, int SyncHeight, int TimeConnected);

    };


    class BGPWallet
    {
        public:

            /* VARIABLES: Firewall Settings (BGP Attack) */
            static bool Detect;                                             /* True/False                                 */
            static bool Denied;                                             /* True/False                                    */
            static bool Ban;                                                /* True/False                                 */
            static int BanTime;                                             /* Seconds                                    */
            static bool Disconnect;                                         /* True/False                                 */
            static int MinCheck;                                            /* Seconds                                    */

            /* FUNCTION: BGP::Check */
            static std::string Check(CNode *pnode, int SyncHeight, int TimeConnected);

    };


    class ResettingSyncWallet
    {
        public:

            /* VARIABLES: Firewall Settings (ResettingSync Attack) */
            static bool Detect;                                             /* True/False                                   */
            static bool Denied;                                             /* True/False                                      */
            static bool Ban;                                                /* True/False                                   */
            static int BanTime;                                             /* Seconds                                      */
            static bool Disconnect;                                         /* True/False                                   */
            static int MinCheck;                                            /* Seconds                                      */
            
            /* FUNCTION: ResettingSync::Check */
            static std::string Check(CNode *pnode, int SyncHeight, int TimeConnected);

    };


    class Operations
    {
        public:

            /* FUNCTION: ForceDisconnectNode */
            static bool ForceDisconnectNode(CNode *pnode, std::string FromFunction);

            /* FUNCTION: AddBan */
            static bool AddBan(CNode *pnode, CBan::BanReason BAN_REASON, int BAN_TIME);

            /* FUNCTION: AddBan */
            static bool AddDenied(CNode *pnode);

            /* FUNCTION: CheckBanned */
            static bool CheckBanned(CNode *pnode);

            /* FUNCTION: CheckDenied */
            static bool CheckDenied(CNode *pnode);

    };


    class Monitoring
    {
        public:

            /* FUNCTION: LegacySyncHeight */
            static int LegacySyncHeight(CNode *pnode);

            /* FUNCTION: CheckAttack */
            static bool CheckAttack(CNode *pnode, std::string FromFunction);
            
            /* FUNCTION: Examination **/
            static void Examination(CNode *pnode, std::string FromFunction);

            /* FUNCTION: Init */
            static bool Init(CNode *pnode, std::string FromFunction);

    };


}
/*
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
**/