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


#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H

#include "compat.h"
#include "core.h"
#include "hash.h"
#include "limitedmap.h"
#include "mruset.h"
#include "netbase.h"
#include "checkpoints.h"
#include "protocol.h"
#include "sync.h"
#include "uint256.h"
#include "util.h"

#include <deque>
#include <stdint.h>

#ifndef WIN32
#include <arpa/inet.h>
#endif

#include <boost/array.hpp>
#include <boost/signals2/signal.hpp>
#include <openssl/rand.h>

class CAddrMan;
class CBlockIndex;
extern int nBestHeight;

class CNode;

namespace boost
{
    class thread_group;
}

extern int64_t TURBOSYNC_MAX;

/** Time between pings automatically sent out for latency probing and keepalive (in seconds). */
static const int PING_INTERVAL = 1 * 60;

/** Time after which to disconnect, after waiting for a ping response (or inactivity). */
static const int TIMEOUT_INTERVAL = 20 * 60;

/** Time between cycles to check for idle nodes, force disconnect (seconds) **/ 
static const int IDLE_TIMEOUT = 4 * 60;

/** Time between cycles to check for idle nodes, force disconnect (seconds) **/ 
static const int DATA_TIMEOUT = 3 * 60;

/** Maximum length of strSubVer in `version` message */
static const unsigned int MAX_SUBVERSION_LENGTH = 256;

inline unsigned int ReceiveFloodSize()
{
    return 1000 * GetArg("-maxreceivebuffer", 5*1000);
}

inline unsigned int SendBufferSize()
{
    return 1000 * GetArg("-maxsendbuffer", 1*1000);
}

void AddOneShot(std::string strDest);
bool RecvLine(SOCKET hSocket, std::string& strLine);
void AddressCurrentlyConnected(const CService& addr);

CNode* FindNode(const CNetAddr& ip);
CNode* FindNode(const CSubNet& subNet);
CNode* FindNode(std::string addrName);
CNode* FindNode(const CService& ip);
CNode* ConnectNode(CAddress addrConnect, const char *strDest = NULL, bool darkSendMaster=false);

bool CheckNode(CAddress addrConnect);
void MapPort(bool fUseUPnP);
unsigned short GetListenPort();
bool BindListenPort(const CService &bindAddr, std::string& strError=REF(std::string()));
void StartNode(boost::thread_group& threadGroup);
bool StopNode();
void SocketSendData(CNode *pnode);

typedef int NodeId;

inline int GetMaxInvBandwidth(int64_t TurboSyncMax)
{
    switch (TurboSyncMax)
    {
        case 1:
        {
            // Level 1 (up to 100% faster)
            return 100000; 
        }
        break;
            
        case 2:
        {
            // Level 2 (up to 200% faster)
            return 200000; 
        }
        break;

        case 3:
        {
            // Level 3 (up to 300% faster)
            return 300000;
        }
        break;

        case 4:
        {
            // Level 4 (up to 400% faster)
            return 400000; 
        }
        break;

        case 5:
        {
            // Level 5 (up to 500% faster)
            return 500000; 
        }
        break;
    }

    // Default
    return 50000;
}

inline int GetMaxAddrBandwidth(int64_t TurboSyncMax)
{
    switch (TurboSyncMax)
    {
        case 1:
        {
            // Level 1  (up to 100% faster)
            return 2000; 
        }
        break;

        case 2:
        {
            // Level 2  (up to 200% faster)
            return 4000; 
        }
        break;

        case 3:
        {
            // Level 3  (up to 300% faster)
            return 8000; 
        }
        break;

        case 4:
        {
            // Level 4  (up to 400% faster)
            return 16000; 
        }
        break;

        case 5:
        {
            // Level 5  (up to 500% faster)
            return 32000; 
        }
        break;
    }

    // Default
    return 1000;
}

inline int GetMaxBlocksBandwidth(int64_t TurboSyncMax)
{
    switch (TurboSyncMax)
    {
        case 1:
        {
            // Level 1  (100% faster)
            return 1000;
        }
        break;

        case 2:
        {
            // Level 2  (200% faster)
            return 2000;
        }
        break;

        case 3:
        {
            // Level 3  (300% faster)
            return 4000; 
        }
        break;

        case 4:
        {
            // Level 4  (400% faster)
            return 8000; 
        }
        break;

        case 5:
        {
            // Level 5  (500% faster)
            return 16000; 
        }
        break;
    }

    // Default
    return 500;
}

/** The maximum number of entries in an 'inv' protocol message */
static const unsigned int MAX_INV_SZ = GetMaxInvBandwidth(TURBOSYNC_MAX);

/** The maximum number of entries in mapAskFor */
static const size_t MAPASKFOR_MAX_SZ = MAX_INV_SZ;

/** The maximum number of entries in setAskFor (larger due to getdata latency)*/
//static const size_t SETASKFOR_MAX_SZ = 2 * MAX_INV_SZ;

/** The maximum number of new addresses to accumulate before announcing. */
static const unsigned int MAX_ADDR_TO_SEND = GetMaxAddrBandwidth(TURBOSYNC_MAX);

// Signals for message handling
struct CNodeSignals
{
    boost::signals2::signal<int ()> GetHeight;
    boost::signals2::signal<bool (CNode*)> ProcessMessages;
    boost::signals2::signal<bool (CNode*, bool)> SendMessages;
    boost::signals2::signal<void (NodeId, const CNode*)> InitializeNode;
    boost::signals2::signal<void (NodeId)> FinalizeNode;
};

CNodeSignals& GetNodeSignals();

typedef int NodeId;

enum
{
    LOCAL_NONE,   // unknown
    LOCAL_IF,     // address a local interface listens on
    LOCAL_BIND,   // address explicit bound to
    LOCAL_UPNP,   // address reported by UPnP
    LOCAL_MANUAL, // address explicitly specified (-externalip=)

    LOCAL_MAX
};

bool IsPeerAddrLocalGood(CNode *pnode);
void SetLimited(enum Network net, bool fLimited = true);
bool IsLimited(enum Network net);
bool IsLimited(const CNetAddr& addr);
bool AddLocal(const CService& addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);
bool SeenLocal(const CService& addr);
bool IsLocal(const CService& addr);
bool GetLocal(CService &addr, const CNetAddr *paddrPeer = NULL);
bool IsReachable(const CNetAddr &addr);
void SetReachable(enum Network net, bool fFlag = true);

CAddress GetLocalAddress(const CNetAddr *paddrPeer = NULL);

enum
{
    MSG_TX = 1,
    MSG_BLOCK,
    // Nodes may always request a MSG_FILTERED_BLOCK in a getdata, however,
    // MSG_FILTERED_BLOCK should not appear in any invs except as a part of getdata.
    MSG_FILTERED_BLOCK,
    MSG_TXLOCK_REQUEST,
    MSG_TXLOCK_VOTE,
    MSG_SPORK,
    MSG_MASTERNODE_WINNER,
    MSG_MASTERNODE_SCANNING_ERROR,
    MSG_DSTX
};

extern bool fDiscover;
extern uint64_t nLocalServices;
extern uint64_t nLocalHostNonce;
extern CAddrMan addrman;
extern int nMaxConnections;

extern std::vector<CNode*> vNodes;
extern CCriticalSection cs_vNodes;
extern std::map<CInv, CDataStream> mapRelay;
extern std::deque<std::pair<int64_t, CInv> > vRelayExpiration;
extern CCriticalSection cs_mapRelay;
extern limitedmap<CInv, int64_t> mapAlreadyAskedFor;

extern std::vector<std::string> vAddedNodes;
extern CCriticalSection cs_vAddedNodes;

extern NodeId nLastNodeId;
extern CCriticalSection cs_nLastNodeId;

extern NodeId nLastNodeId;
extern CCriticalSection cs_nLastNodeId;
struct LocalServiceInfo
{
    int nScore;
    int nPort;
};

extern CCriticalSection cs_mapLocalHost;
extern map<CNetAddr, LocalServiceInfo> mapLocalHost;

/** Subversion as sent to the P2P network in `version` messages */
extern std::string strSubVersion;


namespace CBan
{
    typedef enum BanReason
    {
        BanReasonUnknown                    = 0,
        BanReasonNodeMisbehaving            = 1,
        BanReasonManuallyAdded              = 2,
        BanReasonBandwidthAbuse             = 3,
        BanReasonInvalidWallet              = 4,
        BanReasonForkedWallet               = 5,
        BanReasonFloodingWallet             = 6,
        BanReasonDDoSWallet                 = 7,
        BanReasonDoubleSpendWallet          = 8,
        BanReasonEclipseWallet              = 9,
        BanReasonErebusWallet               = 10,
        BanReasonBGPWallet                  = 11,
        BanReasonResettingSyncWallet        = 12

    } BanReason;


    class CBanEntry
    {

        public:

            static const int CURRENT_VERSION=2;
            int nVersion;

            int64_t nCreateTime;
            int64_t nBanUntil;
            uint8_t banReason;

            CBanEntry()
            {
                SetNull();
            }

            CBanEntry(int64_t nCreateTimeIn)
            {
                SetNull();
                nCreateTime = nCreateTimeIn;
            }
        
            IMPLEMENT_SERIALIZE
            (
                READWRITE(this->nVersion);
                nVersion = this->nVersion;
                READWRITE(nCreateTime);
                READWRITE(nBanUntil);
                READWRITE(banReason);
            )

            void SetNull()
            {
                nVersion = CBanEntry::CURRENT_VERSION;
                nCreateTime = 0;
                nBanUntil = 0;
                banReason = CBan::BanReasonUnknown;
            }

            std::string banReasonToString()
            {
                switch (banReason)
                {
                    case BanReasonNodeMisbehaving:
                    {
                        return "Misbehaving";
                    }
                    break;

                    case BanReasonManuallyAdded:
                    {
                        return "Nanually added";
                    }

                    case BanReasonBandwidthAbuse:
                    {
                        return "Bandwidth abuse";
                    }

                    case BanReasonInvalidWallet:
                    {
                        return "Invalid wallet";
                    }

                    case BanReasonForkedWallet:
                    {
                        return "Forked wallet";
                    }

                    case BanReasonFloodingWallet:
                    {
                        return "Flooding wallet";
                    }

                    case BanReasonDDoSWallet:
                    {
                        return "DDoS wallet";
                    }

                    case BanReasonDoubleSpendWallet:
                    {
                        return "Double-spend wallet";
                    }

                    default:
                    {
                        return "unknown";
                    }
                }
            }
    };
    
    typedef std::map<CSubNet, CBanEntry> banmap_t;
}


class CNodeStats
{
    public:

        NodeId nodeid;
        int nVersion;
        std::string cleanSubVer;
        std::string strSubVer;
        std::string addrLocal;
        std::string addrName;

        int nStartingHeight;

        uint64_t nServices;
        int64_t nLastSend;
        int64_t nLastRecv;
        int64_t nTimeConnected;
        int64_t nTimeOffset;
        uint64_t nSendBytes;
        uint64_t nRecvBytes;
        
        bool fInbound;
        bool fSyncNode;

        double dPingTime;
        double dPingWait;

        // Turbosync (C) 2019 - Profit Hunters Coin
        int64_t nTurboSync;
        bool fTurboSyncSent;
        bool fTurboSyncRecv;

        // Firewall (C) 2017 - Biznatch Enterprises & BATA.io & Profit Hunters Coin
        double nTrafficAverage;
        double nTrafficRatio;
        int nTrafficTimestamp;
        int nInvalidRecvPackets;

        // Dynamic Checkpoints (C) 2019 - Profit Hunters Coin
        // Received
        bool Checkpoint_Recv;
        int64_t CheckpointHeight_Recv;
        int64_t CheckpointTimestamp_Recv;
        uint256 CheckpointBlock_Recv;
        // Sent
        bool Checkpoint_Sent;
        int64_t CheckpointHeight_Sent;
        int64_t CheckpointTimestamp_Sent;
        uint256 CheckpointBlock_Sent;

};

class CNetMessage
{
    public:

        // parsing header (false) or data (true)
        bool in_data;                   

        // partially received header
        CDataStream hdrbuf;

        // complete header
        CMessageHeader hdr;

        unsigned int nHdrPos;

        // received message data
        CDataStream vRecv;

        unsigned int nDataPos;

        CNetMessage(int nTypeIn, int nVersionIn) : hdrbuf(nTypeIn, nVersionIn), vRecv(nTypeIn, nVersionIn)
        {
            hdrbuf.resize(24);
            in_data = false;
            nHdrPos = 0;
            nDataPos = 0;
        }

        bool complete() const
        {
            if (!in_data)
            {
                return false;
            }

            return (hdr.nMessageSize == nDataPos);
        }

        void SetVersion(int nVersionIn)
        {
            hdrbuf.SetVersion(nVersionIn);
            vRecv.SetVersion(nVersionIn);
        }

        int readHeader(const char *pch, unsigned int nBytes);
        int readData(const char *pch, unsigned int nBytes);
};



class SecMsgNode
{
    public:

        SecMsgNode()
        {
            lastSeen        = 0;
            lastMatched     = 0;
            ignoreUntil     = 0;
            nWakeCounter    = 0;
            nPeerId         = 0;
            fEnabled        = false;
        };
        
        ~SecMsgNode() {};
        
        CCriticalSection            cs_smsg_net;
        int64_t                     lastSeen;
        int64_t                     lastMatched;
        int64_t                     ignoreUntil;
        uint32_t                    nWakeCounter;
        uint32_t                    nPeerId;
        bool                        fEnabled;
        
};


/** Information about a peer */
class CNode
{

    protected:

        // Denial-of-service detection/prevention
        // Key is IP address, value is banned-until-time
        static CBan::banmap_t setBanned;
        static CCriticalSection cs_setBanned;
        static bool setBannedIsDirty;

        std::vector<std::string> vecRequestsFulfilled; //keep track of what client has asked for
        
    public:

        // socket
        uint64_t nServices;

        SOCKET hSocket;
        CDataStream ssSend;
        
        // total size of all vSendMsg entries
        size_t nSendSize; 
        // offset inside the first vSendMsg already sent
        size_t nSendOffset;
        uint64_t nSendBytes;
        
        std::deque<CSerializeData> vSendMsg;
        CCriticalSection cs_vSend;

        std::deque<CInv> vRecvGetData;
        std::deque<CNetMessage> vRecvMsg;
        CCriticalSection cs_vRecvMsg;

        CAddress addr;
        std::string addrName;
        CService addrLocal;
        int nVersion;
        int nRecvVersion;
        int nStartingHeight;
        int64_t nLastSend;
        int64_t nLastRecv;
        int64_t nLastSendEmpty;
        int64_t nTimeConnected;
        int64_t nTimeOffset;
        uint64_t nRecvBytes;

        CSemaphoreGrant grantOutbound;
        int nRefCount;
        NodeId id;

        bool fSyncNode;

        // Turbosync (C) 2019 - Profit Hunters Coin
        int64_t nTurboSync;
        bool fTurboSyncSent;
        bool fTurboSyncRecv;

        // Firewall (C) 2017 - Biznatch Enterprises & BATA.io & Profit Hunters Coin
        double nTrafficAverage;
        double nTrafficRatio;
        int nTrafficTimestamp;
        int nInvalidRecvPackets;

        // Dynamic Checkpoints (C) 2019 - Profit Hunters Coin
        DynamicCheckpoints::Checkpoint dCheckpointSent;
        DynamicCheckpoints::Checkpoint dCheckpointRecv;
        DynamicCheckpoints::Checkpoint dOrphanRecv;

        // strSubVer is whatever byte array we read from the wire. However, this field is intended
        // to be printed out, displayed to humans in various forms and so on. So we sanitize it and
        // store the sanitized version in cleanSubVer. The original should be used when dealing with
        // the network or wire types and the cleaned string used when displayed or logged.
        std::string strSubVer, cleanSubVer;

        bool fOneShot;
        bool fClient;
        bool fInbound;
        bool fNetworkNode;
        bool fSuccessfullyConnected;
        bool fDisconnect;

        // We use fRelayTxes for two purposes -
        // a) it allows us to not relay tx invs before receiving the peer's version message
        // b) the peer may tell us in their version message that we should not relay tx invs
        //    until they have initialized their bloom filter.
        bool fRelayTxes;
        bool fDarkSendMaster;

        uint256 hashContinue;
        CBlockIndex* pindexLastGetBlocksBegin;
        uint256 hashLastGetBlocksEnd;

        // BGP Hijack protection
        uint256 hashAskedFor;
        uint256 hashReceived;
        // int BGPWarnings;

        // flood relay
        std::vector<CAddress> vAddrToSend;
        mruset<CAddress> setAddrKnown;

        bool fGetAddr;
        
        std::set<uint256> setKnown;
        uint256 hashCheckpointKnown; // ppcoin: known sent sync-checkpoint

        // inventory based relay
        mruset<CInv> setInventoryKnown;
        std::vector<CInv> vInventoryToSend;
        CCriticalSection cs_inventory;
        std::set<uint256> setAskFor;
        std::multimap<int64_t, CInv> mapAskFor;

        SecMsgNode smsgData;

        // Ping time measurement:
        // The pong reply we're expecting, or 0 if no pong expected.
        uint64_t nPingNonceSent;

        // Time (in usec) the last ping was sent, or 0 if no ping was ever sent.
        int64_t nPingUsecStart;
        
        // Last measured round-trip time.
        int64_t nPingUsecTime;
        
        // Whether a ping is requested.
        bool fPingQueued;

        int nRecvAddrs;

        CNode(SOCKET hSocketIn, CAddress addrIn, std::string addrNameIn = "", bool fInboundIn=false) : ssSend(SER_NETWORK, INIT_PROTO_VERSION), setAddrKnown(5000)
        {
            nServices = 0;
            hSocket = hSocketIn;
            nRecvVersion = INIT_PROTO_VERSION;
            nLastSend = 0;
            nLastRecv = 0;
            nSendBytes = 0;
            nRecvBytes = 0;
            nLastSendEmpty = GetTime();
            nTimeConnected = GetTime();
            nTimeOffset = 0;
            addr = addrIn;
            addrName = addrNameIn == "" ? addr.ToStringIPPort() : addrNameIn;
            nVersion = 0;
            strSubVer = "";

            fOneShot = false;
            fClient = false; // set by version message
            fInbound = fInboundIn;
            fNetworkNode = false;
            fSuccessfullyConnected = false;
            fDisconnect = false;

            nRefCount = 0;
            nSendSize = 0;
            nSendOffset = 0;
            hashContinue = 0;
            pindexLastGetBlocksBegin = 0;
            hashLastGetBlocksEnd = 0;
            nStartingHeight = -1;

            fSyncNode = false;
            fGetAddr = false;
            fRelayTxes = false;
            
            hashCheckpointKnown = 0;
            setInventoryKnown.max_size(SendBufferSize() / 1000);
            nPingNonceSent = 0;
            nPingUsecStart = 0;
            nPingUsecTime = 0;

            // BGP protection
            uint256 hashAskedFor;
            uint256 hashReceived;
            // int BGPWarnings;

            fPingQueued = false;

            // Turbosync (C) 2019 - Profit Hunters Coin
            nTurboSync = 0;
            fTurboSyncSent = false;
            fTurboSyncRecv = false;

            // Firewall (C) 2017 - Biznatch Enterprises & BATA.io & Profit Hunters Coin
            nTrafficAverage = 0;
            nTrafficRatio = 0;
            nTrafficTimestamp = 0;
            nInvalidRecvPackets = 0;

            // Dynamic Checkpoints 1.0.0
            dCheckpointSent.height = 0;
            dCheckpointSent.hash = 0;
            dCheckpointSent.timestamp = 0;
            dCheckpointSent.synced = false;

            dCheckpointRecv.height = 0;
            dCheckpointRecv.hash = 0;
            dCheckpointRecv.timestamp = 0;
            dCheckpointRecv.synced = false;

            dOrphanRecv.height = 0;
            dOrphanRecv.hash = 0;
            dOrphanRecv.timestamp = 0;
            dOrphanRecv.synced = false;

            nRecvAddrs = 0;

            // Global Namespace Start
            {
                // Node Lock
                LOCK(cs_nLastNodeId);

                id = nLastNodeId++;
            }
            // Global Namespace End

            // Be shy and don't send version until we hear
            if (hSocket != INVALID_SOCKET && !fInbound)
            {
                PushVersion();
            }

            GetNodeSignals().InitializeNode(GetId(), this);
        }

        ~CNode()
        {
            if (hSocket != INVALID_SOCKET)
            {
                closesocket(hSocket);
                hSocket = INVALID_SOCKET;
            }

            GetNodeSignals().FinalizeNode(GetId());
        }

    private:

        // Network usage totals
        static CCriticalSection cs_totalBytesRecv;
        static CCriticalSection cs_totalBytesSent;
        static uint64_t nTotalBytesRecv;
        static uint64_t nTotalBytesSent;

        CNode(const CNode&);
        void operator=(const CNode&);

    public:

        NodeId GetId() const
        {
            return id;
        }

        int GetRefCount()
        {
            if (nRefCount < 0)
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : nRefCount < 0 (assert-1\n", __FUNCTION__);
                }

                cout << __FUNCTION__ << " (assert-1)" << endl;

                return 0;
            }

            return nRefCount;
        }

        // requires LOCK(cs_vRecvMsg)
        unsigned int GetTotalRecvSize()
        {
            unsigned int total = 0;

            for(const CNetMessage &msg: vRecvMsg)
            {
                total += msg.vRecv.size() + 24;
            }

            return total;
        }

        // requires LOCK(cs_vRecvMsg)
        bool ReceiveMsgBytes(const char *pch, unsigned int nBytes);

        // requires LOCK(cs_vRecvMsg)
        void SetRecvVersion(int nVersionIn)
        {
            nRecvVersion = nVersionIn;

            for(CNetMessage &msg: vRecvMsg)
            {
                msg.SetVersion(nVersionIn);
            }
        }

        CNode* AddRef()
        {
            nRefCount++;

            return this;
        }

        void Release()
        {
            nRefCount--;
        }

        void AddAddressKnown(const CAddress& addr)
        {
            setAddrKnown.insert(addr);
        }

        void PushAddress(const CAddress& addr)
        {
            // Known checking here is only to save space from duplicates.
            // SendMessages will filter it again for knowns that were added
            // after addresses were pushed.
            if (addr.IsValid() && !setAddrKnown.count(addr))
            {
                if (vAddrToSend.size() >= MAX_ADDR_TO_SEND)
                {
                    vAddrToSend[insecure_rand() % vAddrToSend.size()] = addr;
                }
                else
                {
                    vAddrToSend.push_back(addr);
                }
            }
        }

        void AddInventoryKnown(const CInv& inv)
        {
            // Global Namespace Start
            {
                LOCK(cs_inventory);

                setInventoryKnown.insert(inv);
            }
            // Global Namespace End
        }

        int GetInventoryKnown(const CInv& inv)
        {
            // Global Namespace Start
            {
                LOCK(cs_inventory);

                return setInventoryKnown.size();
            }
            // Global Namespace End
        }

        void PushInventory(const CInv& inv)
        {
            // Global Namespace Start
            {
                LOCK(cs_inventory);

                if (!setInventoryKnown.count(inv))
                {
                    vInventoryToSend.push_back(inv);
                }
            }
            // Global Namespace End
        }

        void AskFor(const CInv& inv, bool fImmediateRetry = false)
        {
            if (mapAskFor.size() > MAPASKFOR_MAX_SZ)
            {
                return;
            }

            // a peer may not have multiple non-responded queue positions for a single inv item
            if (!setAskFor.insert(inv.hash).second)
            {
                return;
            }

            // We're using mapAskFor as a priority queue,
            // the key is the earliest time the request can be sent
            int64_t nRequestTime;
            limitedmap<CInv, int64_t>::const_iterator it = mapAlreadyAskedFor.find(inv);
            if (it != mapAlreadyAskedFor.end())
            {
                nRequestTime = it->second;
            }
            else
            {
                nRequestTime = 0;
            }

            if (fDebug)
            {
                LogPrint("net", "%s : NOTICE - askfor %s   %d (%s) \n", __FUNCTION__, inv.ToString().c_str(), nRequestTime, DateTimeStrFormat("%H:%M:%S", nRequestTime/1000000).c_str());
            }

            // Make sure not to reuse time indexes to keep things in the same order
            int64_t nNow = (GetTime() - 1) * 1000000;
            static int64_t nLastTime;

            ++nLastTime;
            nNow = std::max(nNow, nLastTime);
            nLastTime = nNow;

            // Retry immediately during initial sync otherwise retry 2 minutes after the last
            if (fImmediateRetry)
            {
                nRequestTime = nNow;
            }
            else
            {
                nRequestTime = std::max(nRequestTime + 2 * 60 * 1000000, nNow);
            }

            if (it != mapAlreadyAskedFor.end())
            {
                mapAlreadyAskedFor.update(it, nRequestTime);
            }
            else
            {
                mapAlreadyAskedFor.insert(std::make_pair(inv, nRequestTime));
            }

            mapAskFor.insert(std::make_pair(nRequestTime, inv));
        }

        // TODO: Document the postcondition of this function.  Is cs_vSend locked?
        void BeginMessage(const char* pszCommand) EXCLUSIVE_LOCK_FUNCTION(cs_vSend)
        {
            ENTER_CRITICAL_SECTION(cs_vSend);

            if (ssSend.size() != 0)
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - ssSend.size() != 0 \n", __FUNCTION__);
                }

                return;
            }

            ssSend << CMessageHeader(pszCommand, 0);
 
            if (fDebug)
            {
                LogPrint("net", "%s : OK - Sending: %s ", __FUNCTION__, pszCommand);
            }
        }

        // TODO: Document the precondition of this function.  Is cs_vSend locked?
        void AbortMessage() UNLOCK_FUNCTION(cs_vSend)
        {
            ssSend.clear();

            LEAVE_CRITICAL_SECTION(cs_vSend);

            if (fDebug)
            {
                LogPrint("net", "%s : WARNING - (aborted) \n", __FUNCTION__);
            }
        }

        // TODO: Document the precondition of this function.  Is cs_vSend locked?
        void EndMessage() UNLOCK_FUNCTION(cs_vSend)
        {
            // The -*messagestest options are intentionally not documented in the help message,
            // since they are only used during development to debug the networking code and are
            // not intended for end-users.
            if (mapArgs.count("-dropmessagestest") && GetRand(GetArg("-dropmessagestest", 2)) == 0)
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - dropmessages DROPPING SEND MESSAGE \n", __FUNCTION__);
                }

                AbortMessage();

                return;
            }

            if (ssSend.size() == 0)
            {
                return;
            }

            // Set the size
            unsigned int nSize = ssSend.size() - CMessageHeader::HEADER_SIZE;

            memcpy((char*)&ssSend[CMessageHeader::MESSAGE_SIZE_OFFSET], &nSize, sizeof(nSize));

            // Set the checksum
            uint256 hash = Hash(ssSend.begin() + CMessageHeader::HEADER_SIZE, ssSend.end());
            unsigned int nChecksum = 0;

            memcpy(&nChecksum, &hash, sizeof(nChecksum));

            if(ssSend.size () < CMessageHeader::CHECKSUM_OFFSET + sizeof(nChecksum))
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - ssSend.size() != 0 \n", __FUNCTION__);
                }

                return;
            }

            memcpy((char*)&ssSend[CMessageHeader::CHECKSUM_OFFSET], &nChecksum, sizeof(nChecksum));

            if (fDebug)
            {
                LogPrint("net", "%s : NOTICE - (%d bytes) \n", __FUNCTION__, nSize);
            }
            
            std::deque<CSerializeData>::iterator it = vSendMsg.insert(vSendMsg.end(), CSerializeData());
            ssSend.GetAndClear(*it);
            nSendSize += (*it).size();

            // If write queue empty, attempt "optimistic write"
            if (it == vSendMsg.begin())
            {
                SocketSendData(this);
            }

            LEAVE_CRITICAL_SECTION(cs_vSend);
        }

        void PushVersion();


        void PushMessage(const char* pszCommand)
        {
            try
            {
                BeginMessage(pszCommand);
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1>
        void PushMessage(const char* pszCommand, const T1& a1)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2, typename T3>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2, typename T3, typename T4>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2, typename T3, typename T4, typename T5>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4 << a5;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4 << a5 << a6;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8, const T9& a9)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8, const T9& a9, const T10& a10)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9 << a10;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }
        template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8, const T9& a9, const T10& a10, const T11& a11)
    {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9 << a10 << a11;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12>
        void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8, const T9& a9, const T10& a10, const T11& a11, const T12& a12)
        {
            try
            {
                BeginMessage(pszCommand);
                ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9 << a10 << a11 << a12;
                EndMessage();
            }
            catch (...)
            {
                AbortMessage();

                throw;
            }
        }

        bool HasFulfilledRequest(std::string strRequest)
        {
            for(std::string& type: vecRequestsFulfilled)
            {
                if(type == strRequest)
                {
                    return true;
                }
            }

            return false;
        }

        void FulfilledRequest(std::string strRequest)
        {
            if(HasFulfilledRequest(strRequest))
            {
                return;
            }

            vecRequestsFulfilled.push_back(strRequest);
        }

        void PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd);
        bool IsSubscribed(unsigned int nChannel);
        void Subscribe(unsigned int nChannel, unsigned int nHops=0);
        void CancelSubscribe(unsigned int nChannel);
        void CloseSocketDisconnect();

        // Denial-of-service detection/prevention
        // The idea is to detect peers that are behaving
        // badly and disconnect/ban them, but do it in a
        // one-coding-mistake-won't-shatter-the-entire-network
        // way.
        // IMPORTANT:  There should be nothing I can give a
        // node that it will forward on that will make that
        // node's peers drop it. If there is, an attacker
        // can isolate a node and/or try to split the network.
        // Dropping a node for sending stuff that is invalid
        // now but might be valid in a later version is also
        // dangerous, because it can cause a network split
        // between nodes running old code and nodes running
        // new code.
        static void ClearBanned(); // needed for unit testing
        static bool IsBanned(CNetAddr ip);
        static bool IsBanned(CSubNet subnet);
        static void Ban(const CNetAddr &ip, const CBan::BanReason &banReason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
        static void Ban(const CSubNet &subNet, const CBan::BanReason &banReason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
        static bool Unban(const CNetAddr &ip);
        static bool Unban(const CSubNet &ip);
        static void GetBanned(CBan::banmap_t &banmap);
        static void SetBanned(const CBan::banmap_t &banmap);

        //!check is the banlist has unwritten changes
        static bool BannedSetIsDirty();

        //!set the "dirty" flag for the banlist
        static void SetBannedSetDirty(bool dirty=true);

        //!clean unused entires (if bantime has expired)
        static void SweepBanned();

        void copyStats(CNodeStats &stats);

        // Network stats
        static void RecordBytesRecv(uint64_t bytes);
        static void RecordBytesSent(uint64_t bytes);

        static uint64_t GetTotalBytesRecv();
        static uint64_t GetTotalBytesSent();
};

inline void RelayInventory(const CInv& inv)
{
    // Global Namespace Start
    {
        // Put on lists to offer to the other nodes
        LOCK(cs_vNodes);

        for(CNode* pnode: vNodes)
        {
            pnode->PushInventory(inv);
        }
    }
    // Global Namespace End
}

class CTransaction;

void RelayTransaction(const CTransaction& tx, const uint256& hash);
void RelayTransaction(const CTransaction& tx, const uint256& hash, const CDataStream& ss);
void RelayTransactionLockReq(const CTransaction& tx, bool relayToAll=false);

/** Access to the (IP) address database (peers.dat) */
class CAddrDB
{
    private:

        boost::filesystem::path pathAddr;

    public:

        CAddrDB();

        bool Write(const CAddrMan& addr);
        bool Read(CAddrMan& addr);
};

/** Access to the banlist database (banlist.dat) */
class CBanDB
{
    private:

        boost::filesystem::path pathBanlist;

    public:
    
        CBanDB();
        
        bool Write(const CBan::banmap_t& banSet);
        bool Read(CBan::banmap_t& banSet);
};

void DumpBanlist();

#endif