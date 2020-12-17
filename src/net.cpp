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


#include "db.h"
#include "net.h"
#include "main.h"
#include "addrman.h"
#include "chainparams.h"
#include "core.h"
#include "ui_interface.h"
#include "darksend.h"
#include "wallet.h"
#include "firewall.h"

#ifdef WIN32
#include <string.h>
#else
#include <fcntl.h>
#endif

#ifdef USE_UPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <boost/lexical_cast.hpp>

// Dump addresses to peers.dat every 15 minutes (900s)
#define DUMP_ADDRESSES_INTERVAL 900

#if !defined(HAVE_MSG_NOSIGNAL) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

/* ONLY NEEDED FOR UNIT TESTING */
#include <iostream>

using namespace std;
using namespace boost;
using namespace CBan;

static const int MAX_OUTBOUND_CONNECTIONS = 25;


bool OpenNetworkConnection(const CAddress& addrConnect, CSemaphoreGrant *grantOutbound = NULL, const char *strDest = NULL, bool fOneShot = false);


//
// Global state variables
//
bool fDiscover = true;
uint64_t nLocalServices = NODE_NETWORK;

CCriticalSection cs_mapLocalHost;
map<CNetAddr, LocalServiceInfo> mapLocalHost;

static bool vfReachable[NET_MAX] = {};
static bool vfLimited[NET_MAX] = {};

static CNode* pnodeLocalHost = NULL;

uint64_t nLocalHostNonce = 0;

static std::vector<SOCKET> vhListenSocket;

CAddrMan addrman;
std::string strSubVersion;

int nMaxConnections = GetArg("-maxconnections", 125);

vector<CNode*> vNodes;
CCriticalSection cs_vNodes;
map<CInv, CDataStream> mapRelay;
deque<pair<int64_t, CInv> > vRelayExpiration;
CCriticalSection cs_mapRelay;
limitedmap<CInv, int64_t> mapAlreadyAskedFor(MAX_INV_SZ);

static deque<string> vOneShots;
CCriticalSection cs_vOneShots;

set<CNetAddr> setservAddNodeAddresses;
CCriticalSection cs_setservAddNodeAddresses;

vector<std::string> vAddedNodes;
CCriticalSection cs_vAddedNodes;

NodeId nLastNodeId = 0;
CCriticalSection cs_nLastNodeId;

static CSemaphore *semOutbound = NULL;


// Signals for message handling
static CNodeSignals g_signals;

CNodeSignals& GetNodeSignals()
{
    return g_signals;
}




void AddOneShot(string strDest)
{
    LOCK(cs_vOneShots);

    vOneShots.push_back(strDest);
}


unsigned short GetListenPort()
{
    return (unsigned short)(GetArg("-port", Params().GetDefaultPort()));
}

void CNode::PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd)
{
    // Filter out duplicate requests
    if (pindexBegin == pindexLastGetBlocksBegin
        && hashEnd == hashLastGetBlocksEnd)
    {
        return;
    }

    pindexLastGetBlocksBegin = pindexBegin;
    hashLastGetBlocksEnd = hashEnd;

    PushMessage("getblocks", CBlockLocator(pindexBegin), hashEnd);
}


// find 'best' local address for a particular peer
bool GetLocal(CService& addr, const CNetAddr *paddrPeer)
{
    if (fNoListen)
    {
        return false;
    }

    int nBestScore = -1;
    int nBestReachability = -1;

    // Global Namespace Start
    {
        LOCK(cs_mapLocalHost);

        for (map<CNetAddr, LocalServiceInfo>::iterator it = mapLocalHost.begin(); it != mapLocalHost.end(); it++)
        {
            int nScore = (*it).second.nScore;
            int nReachability = (*it).first.GetReachabilityFrom(paddrPeer);

            if (nReachability > nBestReachability
                || (nReachability == nBestReachability
                && nScore > nBestScore))
            {
                addr = CService((*it).first, (*it).second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    // Global Namespace End

    return nBestScore >= 0;
}


// get best local address for a particular peer as a CAddress
CAddress GetLocalAddress(const CNetAddr *paddrPeer)
{
    CAddress ret(CService("0.0.0.0",0),0);

    CService addr;

    if (GetLocal(addr, paddrPeer))
    {
        ret = CAddress(addr);
        ret.nServices = nLocalServices;
        ret.nTime = GetAdjustedTime();
    }

    return ret;
}


bool RecvLine(SOCKET hSocket, string& strLine)
{
    strLine = "";

    while (true)
    {
        char c;
        int nBytes = recv(hSocket, &c, 1, 0);

        if (nBytes > 0)
        {
            if (c == '\n')
            {
                continue;
            }

            if (c == '\r')
            {
                return true;
            }

            strLine += c;

            if (strLine.size() >= 9000)
            {
                return true;
            }
        }
        else if (nBytes <= 0)
        {
            boost::this_thread::interruption_point();

            if (nBytes < 0)
            {
                int nErr = WSAGetLastError();

                if (nErr == WSAEMSGSIZE)
                {
                    continue;
                }

                if (nErr == WSAEWOULDBLOCK
                    || nErr == WSAEINTR
                    || nErr == WSAEINPROGRESS)
                {
                    MilliSleep(10);

                    continue;
                }
            }

            if (!strLine.empty())
            {
                return true;
            }

            if (nBytes == 0)
            {
                // socket closed
                if (fDebug)
                {
                    LogPrint("net", "%s : WARNING - socket closed \n", __FUNCTION__);
                }

                return false;
            }
            else
            {
                // socket error
                int nErr = WSAGetLastError();

                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - recv failed: %s \n", __FUNCTION__, nErr);
                }

                return false;
            }
        }
    }
}


int GetnScore(const CService& addr)
{
    LOCK(cs_mapLocalHost);

    if (mapLocalHost.count(addr) == LOCAL_NONE)
    {
        return 0;
    }

    return mapLocalHost[addr].nScore;
}


// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(CNode *pnode)
{
    return fDiscover
            && pnode->addr.IsRoutable()
            && pnode->addrLocal.IsRoutable()
            && !IsLimited(pnode->addrLocal.GetNetwork());
}


// used when scores of local addresses may have changed
// pushes better local address to peers
void static AdvertizeLocal()
{
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        if (pnode->fSuccessfullyConnected)
        {
            CAddress addrLocal = GetLocalAddress(&pnode->addr);

            if (addrLocal.IsRoutable()
                && (CService)addrLocal != (CService)pnode->addrLocal)
            {
                pnode->PushAddress(addrLocal);
                pnode->addrLocal = addrLocal;
            }
        }
    }
}


void SetReachable(enum Network net, bool fFlag)
{
    LOCK(cs_mapLocalHost);

    vfReachable[net] = fFlag;

    if (net == NET_IPV6
        && fFlag)
    {
        vfReachable[NET_IPV4] = true;
    }
}


// learn a new local address
bool AddLocal(const CService& addr, int nScore)
{
    if (!addr.IsRoutable())
    {
        return false;
    }

    if (!fDiscover
        && nScore < LOCAL_MANUAL)
    {
        return false;
    }

    if (IsLimited(addr))
    {
        return false;
    }

    if (fDebug)
    {
        LogPrint("net", "%s : NOTICE - (%s,%i) \n", __FUNCTION__, addr.ToStringIPPort(), nScore);
    }

    // Global Namespace Start
    {
        LOCK(cs_mapLocalHost);

        bool fAlready = mapLocalHost.count(addr) > 0;

        LocalServiceInfo &info = mapLocalHost[addr];
        
        if (!fAlready
            || nScore >= info.nScore)
        {
            info.nScore = nScore + (fAlready ? 1 : 0);
            info.nPort = addr.GetPort();
        }

        SetReachable(addr.GetNetwork());
    }
    // Global Namespace End

    AdvertizeLocal();

    return true;
}


bool AddLocal(const CNetAddr &addr, int nScore)
{
    return AddLocal(CService(addr, GetListenPort()), nScore);
}


/** Make a particular network entirely off-limits (no automatic connects to it) */
void SetLimited(enum Network net, bool fLimited)
{
    if (net == NET_UNROUTABLE)
    {
        return;
    }

    LOCK(cs_mapLocalHost);

    vfLimited[net] = fLimited;
}


bool IsLimited(enum Network net)
{
    LOCK(cs_mapLocalHost);

    return vfLimited[net];
}


bool IsLimited(const CNetAddr &addr)
{
    return IsLimited(addr.GetNetwork());
}


/** vote for a local address */
bool SeenLocal(const CService& addr)
{
    // Global Namespace Start
    {
        LOCK(cs_mapLocalHost);

        if (mapLocalHost.count(addr) == 0)
        {
            return false;
        }

        mapLocalHost[addr].nScore++;
    }
    // Global Namespace End

    AdvertizeLocal();

    return true;
}


/** check whether a given address is potentially local */
bool IsLocal(const CService& addr)
{
    LOCK(cs_mapLocalHost);

    return mapLocalHost.count(addr) > 0;
}


/** check whether a given address is in a network we can probably connect to */
bool IsReachable(const CNetAddr& addr)
{
    LOCK(cs_mapLocalHost);

    enum Network net = addr.GetNetwork();

    return vfReachable[net]
            && !vfLimited[net];
}


void AddressCurrentlyConnected(const CService& addr)
{
    addrman.Connected(addr);
}


uint64_t CNode::nTotalBytesRecv = 0;
uint64_t CNode::nTotalBytesSent = 0;

CCriticalSection CNode::cs_totalBytesRecv;
CCriticalSection CNode::cs_totalBytesSent;


CNode* FindNode(const CNetAddr& ip)
{
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        if (pnode->addr.ToStringIP().c_str() == ip.ToStringIP().c_str())
        {
            return (pnode);
        }
    }

    return NULL;
}


CNode* FindNode(const CSubNet& subNet)
{
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        if (subNet.Match((CNetAddr)pnode->addr))
        {
            return (pnode);
        }
    }

    return NULL;
}


CNode* FindNode(std::string addrName)
{
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        if (pnode->addrName == addrName)
        {
            return (pnode);
        }

        if (pnode->addr.ToStringIP().c_str() == addrName)
        {
            return (pnode);
        }
    }

    return NULL;
}


CNode* FindNode(const CService& addr)
{
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        if ((CService)pnode->addr == addr)
        {
            return (pnode);
        }
    }

    return NULL;
}


bool CheckNode(CAddress addrConnect)
{
    // Look for an existing connection. If found then just add it to masternode list.
    CNode* pnode = FindNode((CService)addrConnect);

    if (pnode)
    {
        return true;
    }

    // Connect
    SOCKET hSocket;

    //bool proxyConnectionFailed = false;

    if (ConnectSocket(addrConnect, hSocket))
    {
        if (fDebug)
        {
            LogPrint("net", "%s : OK - Connected masternode %s \n", __FUNCTION__, addrConnect.ToString());
        }

        closesocket(hSocket);
        
/*        // Set to non-blocking
#ifdef WIN32
        u_long nOne = 1;
        if (ioctlsocket(hSocket, FIONBIO, &nOne) == SOCKET_ERROR)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ioctlsocket non-blocking setting failed, error %d\n", __FUNCTION__, WSAGetLastError());
            }
        }

#else
        if (fcntl(hSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : fcntl non-blocking setting failed, error %d\n", __FUNCTION__, errno);
            }
        }

#endif
        CNode* pnode = new CNode(hSocket, addrConnect, "", false);
        // Close connection
        pnode->CloseSocketDisconnect();
*/        
        return true;
    }

    if (fDebug)
    {
        LogPrint("net", "%s : ERROR - Connecting to masternode %s failed \n", __FUNCTION__, addrConnect.ToString());
    }

    return false;
}


CNode* ConnectNode(CAddress addrConnect, const char *pszDest, bool darkSendMaster)
{
    if (fImporting
        || fReindex)
    {
        return NULL;
    }

    if (pszDest == NULL)
    {
        if (IsLocal(addrConnect))
        {
            return NULL;
        }

        // Look for an existing connection
        CNode* pnode = FindNode((CService)addrConnect);

        if (pnode)
        {
            if(darkSendMaster)
            {
                pnode->fDarkSendMaster = true;
            }

            pnode->AddRef();

            return pnode;
        }
    }

    /// debug print
    if (fDebug)
    {
        LogPrint("net", "%s : NOTICE - trying connection %s lastseen=%.1fhrs \n", __FUNCTION__, pszDest ? pszDest : addrConnect.ToString(), pszDest ? 0 : (double)(GetAdjustedTime() - addrConnect.nTime)/3600.0);
    }

    // Connect
    SOCKET hSocket;

    if (pszDest ? ConnectSocketByName(addrConnect, hSocket, pszDest, Params().GetDefaultPort()) : ConnectSocket(addrConnect, hSocket))
    {
        addrman.Attempt(addrConnect);

        if (fDebug)
        {
            LogPrint("net", "%s : connected %s \n", __FUNCTION__, pszDest ? pszDest : addrConnect.ToString());
        }

        // Set to non-blocking
#ifdef WIN32
        u_long nOne = 1;
        
        if (ioctlsocket(hSocket, FIONBIO, &nOne) == SOCKET_ERROR)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - ioctlsocket non-blocking setting failed %d \n", __FUNCTION__, WSAGetLastError());
            }
        }

#else
        if (fcntl(hSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - fcntl non-blocking setting failed %d \n", __FUNCTION__, errno);
            }
        }

#endif

        // Add node
        CNode* pnode = new CNode(hSocket, addrConnect, pszDest ? pszDest : "", false);

        pnode->AddRef();

        // Global Namespace Start
        {
            LOCK(cs_vNodes);

            vNodes.push_back(pnode);
        }
        // Global Namespace End

        pnode->nTimeConnected = GetTime();

        return pnode;
    }
    else
    {
        return NULL;
    }
}


void CNode::CloseSocketDisconnect()
{
    fDisconnect = true;

    if (hSocket != INVALID_SOCKET)
    {
        if (fDebug)
        {
            LogPrint("net", "%s : OK - Disconnecting node %s \n", __FUNCTION__, addrName);
        }

        closesocket(hSocket);

        hSocket = INVALID_SOCKET;
    }

    // in case this fails, we'll empty the recv buffer when the CNode is deleted
    TRY_LOCK(cs_vRecvMsg, lockRecv);

    if (lockRecv)
    {
        vRecvMsg.clear();
    }
}


void CNode::PushVersion()
{
    /// when NTP implemented, change to just nTime = GetAdjustedTime()
    int64_t nTime = (fInbound ? GetAdjustedTime() : GetTime());
    CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService("0.0.0.0",0)));
    CAddress addrMe = GetLocalAddress(&addr);
    
    GetRandBytes((unsigned char*)&nLocalHostNonce, sizeof(nLocalHostNonce));
    
    if (fDebug)
    {
        LogPrint("net", "%s : send version message: version %d, blocks=%d, us=%s, them=%s, peer=%s \n", __FUNCTION__, PROTOCOL_VERSION, nBestHeight, addrMe.ToString(), addrYou.ToString(), addr.ToStringIPPort());
    }

    PushMessage("version", PROTOCOL_VERSION, nLocalServices, nTime, addrYou, addrMe, nLocalHostNonce, strSubVersion, nBestHeight);
}


banmap_t CNode::setBanned;
CCriticalSection CNode::cs_setBanned;

bool CNode::setBannedIsDirty;


void CNode::ClearBanned()
{
    LOCK(cs_setBanned);

    setBanned.clear();

    setBannedIsDirty = true;
}


bool CNode::IsBanned(CNetAddr ip)
{
    bool fResult = false;

    // Global Namespace Start
    {
        LOCK(cs_setBanned);

        for (banmap_t::iterator it = setBanned.begin(); it != setBanned.end(); it++)
        {
            CSubNet subNet = (*it).first;
            CBanEntry banEntry = (*it).second;

            if(subNet.Match(ip)
                && GetTime() < banEntry.nBanUntil)
            {
                fResult = true;
            }
        }
    }
    // Global Namespace End

    return fResult;
}


bool CNode::IsBanned(CSubNet subnet)
{
    bool fResult = false;

    // Global Namespace Start
    {
        LOCK(cs_setBanned);

        banmap_t::iterator i = setBanned.find(subnet);

        if (i != setBanned.end())
        {
            CBanEntry banEntry = (*i).second;

            if (GetTime() < banEntry.nBanUntil)
            {
                fResult = true;
            }
        }
    }
    // Global Namespace End

    return fResult;
}


void CNode::Ban(const CNetAddr& addr, const BanReason &banReason, int64_t bantimeoffset, bool sinceUnixEpoch)
{
    CSubNet subNet(addr.ToString()+(addr.IsIPv4() ? "/32" : "/128"));

    Ban(subNet, banReason, bantimeoffset, sinceUnixEpoch);
}


void CNode::Ban(const CSubNet& subNet, const BanReason &banReason, int64_t bantimeoffset, bool sinceUnixEpoch)
{
    CBanEntry banEntry(GetTime());

    banEntry.banReason = banReason;

    if (bantimeoffset <= 0)
    {
        // Default 24-hour ban
        bantimeoffset = GetArg("-bantime", 60*60*24);

        sinceUnixEpoch = false;
    }

    banEntry.nBanUntil = (sinceUnixEpoch ? 0 : GetTime() )+bantimeoffset;

    LOCK(cs_setBanned);

    if (setBanned[subNet].nBanUntil < banEntry.nBanUntil)
    {
        setBanned[subNet] = banEntry;
    }

    setBannedIsDirty = true;
}


bool CNode::Unban(const CNetAddr &addr)
{
    CSubNet subNet(addr.ToString()+(addr.IsIPv4() ? "/32" : "/128"));

    return Unban(subNet);
}


bool CNode::Unban(const CSubNet &subNet)
{
    LOCK(cs_setBanned);

    if (setBanned.erase(subNet))
    {
        setBannedIsDirty = true;

        return true;
    }

    return false;
}


void CNode::GetBanned(banmap_t &banMap)
{
    LOCK(cs_setBanned);

    //create a thread safe copy
    banMap = setBanned; 
}


void CNode::SetBanned(const banmap_t &banMap)
{
    LOCK(cs_setBanned);

    setBanned = banMap;
    setBannedIsDirty = true;
}


void CNode::SweepBanned()
{
    int64_t now = GetTime();

    LOCK(cs_setBanned);

    banmap_t::iterator it = setBanned.begin();

    while(it != setBanned.end())
    {
        CBanEntry banEntry = (*it).second;

        if(now > banEntry.nBanUntil)
        {
            setBanned.erase(it++);

            setBannedIsDirty = true;
        }
        else
        {
            ++it;
        }
    }
}


bool CNode::BannedSetIsDirty()
{
    LOCK(cs_setBanned);

    return setBannedIsDirty;
}


void CNode::SetBannedSetDirty(bool dirty)
{
    //reuse setBanned lock for the isDirty flag
    LOCK(cs_setBanned);

    setBannedIsDirty = dirty;
}


#undef X
#define X(name) stats.name = name
void CNode::copyStats(CNodeStats &stats)
{
    stats.nodeid = this->GetId();
    X(nServices);
    X(nLastSend);
    X(nLastRecv);
    X(nTimeConnected);
    X(nTimeOffset);
    X(addrName);
    X(nVersion);
    X(cleanSubVer);
    X(strSubVer);
    X(fInbound);
    X(nTurboSync);
    X(fTurboSyncSent);
    X(fTurboSyncRecv);
    X(nTrafficAverage);
    X(nTrafficRatio);
    X(nTrafficTimestamp);
    X(nStartingHeight);
    X(nInvalidRecvPackets);
    X(nSendBytes);
    X(nRecvBytes);
    X(fSyncNode);

    // It is common for nodes with good ping times to suddenly become lagged,
    // due to a new block arriving or other large transfer.
    // Merely reporting pingtime might fool the caller into thinking the node was still responsive,
    // since pingtime does not update until the ping is complete, which might take a while.
    // So, if a ping is taking an unusually long time in flight,
    // the caller can immediately detect that this is happening.
    int64_t nPingUsecWait = 0;

    if ((0 != nPingNonceSent)
        && (0 != nPingUsecStart))
    {
        nPingUsecWait = GetTimeMicros() - nPingUsecStart;
    }

    // Raw ping time is in microseconds, but show it to user as whole seconds (Bitcoin users should be well used to small numbers with many decimal places by now :)
    stats.dPingTime = (((double)nPingUsecTime) / 1e6);
    stats.dPingWait = (((double)nPingUsecWait) / 1e6);

    // Leave string empty if addrLocal invalid (not filled in yet)
    stats.addrLocal = addrLocal.IsValid() ? addrLocal.ToString() : "";

    // Dynamic Checkpoints (C) 2019 - Profit Hunters Coin
    // Received
    stats.Checkpoint_Recv = dCheckpointRecv.synced;
    stats.CheckpointHeight_Recv= dCheckpointRecv.height;
    stats.CheckpointTimestamp_Recv = (int64_t)dCheckpointRecv.timestamp;
    stats.CheckpointBlock_Recv = dCheckpointRecv.hash;
    // Sent
    stats.Checkpoint_Sent = dCheckpointSent.synced;;
    stats.CheckpointHeight_Sent = dCheckpointSent.height;
    stats.CheckpointTimestamp_Sent = (int64_t)dCheckpointSent.timestamp;
    stats.CheckpointBlock_Sent = dCheckpointSent.hash;

}
#undef X


// requires LOCK(cs_vRecvMsg)
bool CNode::ReceiveMsgBytes(const char *pch, unsigned int nBytes)
{
    while (nBytes > 0)
    {
        // get current incomplete message, or create a new one
        if (vRecvMsg.empty()
            || vRecvMsg.back().complete())
        {
            vRecvMsg.push_back(CNetMessage(SER_NETWORK, nRecvVersion));
        }

        CNetMessage& msg = vRecvMsg.back();

        // absorb network data
        int handled;

        if (!msg.in_data)
        {
            handled = msg.readHeader(pch, nBytes);
        }
        else
        {
            handled = msg.readData(pch, nBytes);
        }

        if (handled < 0)
        {
            return false;
        }

        pch += handled;
        nBytes -= handled;
    }

    return true;
}


int CNetMessage::readHeader(const char *pch, unsigned int nBytes)
{
    // copy data to temporary parsing buffer
    unsigned int nRemaining = 24 - nHdrPos;
    unsigned int nCopy = std::min(nRemaining, nBytes);

    memcpy(&hdrbuf[nHdrPos], pch, nCopy);

    nHdrPos += nCopy;

    // if header incomplete, exit
    if (nHdrPos < 24)
    {
        return nCopy;
    }

    // deserialize to CMessageHeader
    try
    {
        hdrbuf >> hdr;
    }
    catch (std::exception &e)
    {
        return -1;
    }

    // reject messages larger than MAX_SIZE
    if (hdr.nMessageSize > MAX_SIZE)
    {
        return -1;
    }

    // switch state to reading message data
    in_data = true;

    return nCopy;
}


int CNetMessage::readData(const char *pch, unsigned int nBytes)
{
    unsigned int nRemaining = hdr.nMessageSize - nDataPos;
    unsigned int nCopy = std::min(nRemaining, nBytes);

    if (vRecv.size() < nDataPos + nCopy)
    {
        // Allocate up to 256 KiB ahead, but never more than the total message size.
        vRecv.resize(std::min(hdr.nMessageSize, nDataPos + nCopy + 256 * 1024));
    }

    memcpy(&vRecv[nDataPos], pch, nCopy);

    nDataPos += nCopy;

    return nCopy;
}


int LastRefreshstamp = 0;
int RefreshesDone = 0;
bool FirstCycle = true;


void RefreshRecentConnections(int RefreshMinutes)
{

    if (vNodes.size() >= 8)
    {
        return;
    }

    time_t timer;

    int SecondsPassed = 0;
    int MinutesPassed = 0;
    int CurrentTimestamp = time(&timer);

    if (LastRefreshstamp > 0)
    {
        SecondsPassed = CurrentTimestamp - LastRefreshstamp;
        MinutesPassed = SecondsPassed / 60;

        if (MinutesPassed > RefreshMinutes - 2) 
        {
            FirstCycle = false;
        }
    }
    else
    {
        LastRefreshstamp = CurrentTimestamp;

        return;
    }

    if (FirstCycle == false)
    {
        if (MinutesPassed < RefreshMinutes) 
        {
            return;
        }
        else
        {
            RefreshesDone = RefreshesDone + 1;

            //cout<<"         Last refresh: "<<LastRefreshstamp<<endl;
            //cout<<"         Minutes ago: "<<MinutesPassed<<endl;
            //cout<<"         Peer/node refresh cycles: "<<RefreshesDone<<endl;

            LastRefreshstamp = CurrentTimestamp;

            // Load addresses for peers.dat
            int64_t nStart = GetTimeMillis();

            // Global Namespace Start
            {
                CAddrDB adb;

                if (!adb.Read(addrman))
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : WARNING - Invalid or missing peers.dat; recreating \n", __FUNCTION__);
                    }
                }
            }
            // Global Namespace End

            if (fDebug)
            {
                LogPrint("net", "%s : NOTICE - Loaded %i addresses from peers.dat  %dms \n", __FUNCTION__, addrman.size(), GetTimeMillis() - nStart);
            }

            const vector<CDNSSeedData> &vSeeds = Params().DNSSeeds();

            int found = 0;

            if (fDebug)
            {
                LogPrint("net", "%s : NOTICE - Loading addresses from DNS seeds (could take a while) \n", __FUNCTION__);
            }

            for(const CDNSSeedData &seed: vSeeds)
            {
                if (HaveNameProxy())
                {
                    AddOneShot(seed.host);
                }
                else
                {
                    vector<CNetAddr> vIPs;
                    vector<CAddress> vAdd;

                    if (LookupHost(seed.host.c_str(), vIPs))
                    {
                        for(CNetAddr& ip: vIPs)
                        {
                            if (found < 16)
                            {
                                int nOneDay = 24*3600;

                                CAddress addr = CAddress(CService(ip, Params().GetDefaultPort()));
                                
                                // use a random age between 3 and 7 days old
                                addr.nTime = GetTime() - 3*nOneDay - GetRand(4*nOneDay);
                                
                                vAdd.push_back(addr);
                                
                                found++;
                            }
                        }
                    }

                    addrman.Add(vAdd, CNetAddr(seed.name, true));
                }
            }

            if (fDebug)
            {
                LogPrint("net", "%s : OK - %d addresses found from DNS seeds \n", __FUNCTION__, found);
            }

            //DumpAddresses();

            CSemaphoreGrant grant(*semOutbound);

            boost::this_thread::interruption_point();

            // Choose an address to connect to based on most recently seen
            //
            CAddress addrConnect;

            // Only connect out to one peer per network group (/16 for IPv4).
            // Do this here so we don't have to critsect vNodes inside mapAddresses critsect.
            int nOutbound = 0;

            set<vector<unsigned char> > setConnected;
            
            // Global Namespace Start
            {
                LOCK(cs_vNodes);

                for(CNode* pnode: vNodes)
                {
                    if (!pnode->fInbound)
                    {
                        setConnected.insert(pnode->addr.GetGroup());

                        nOutbound++;
                    }

                }
            }
            // Global Namespace End

            int64_t nANow = GetAdjustedTime();

            int nTries = 0;

            while (true)
            {
                CAddress addr = addrman.Select();

                // if we selected an invalid address, restart
                if (!addr.IsValid()
                    || setConnected.count(addr.GetGroup())
                    || IsLocal(addr))
                {
                    break;
                }

                // If we didn't find an appropriate destination after trying 100 addresses fetched from addrman,
                // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
                // already-connected network ranges, ...) before trying new addrman addresses.
                nTries++;

                if (nTries > 100)
                {
                    break;
                }

                if (IsLimited(addr))
                {
                    continue;
                }

                // only consider very recently tried nodes after 30 failed attempts
                if (nANow - addr.nLastTry < 600
                    && nTries < 30)
                {
                    continue;
                }

                // do not allow non-default ports, unless after 50 invalid addresses selected already
                if (addr.GetPort() != Params().GetDefaultPort()
                    && nTries < 50)
                {
                    continue;
                }

                addrConnect = addr;

                break;
            }

            if (addrConnect.IsValid())
            {
                OpenNetworkConnection(addrConnect, &grant);
            }
        }
    }
}


void IdleNodeCheck(CNode *pnode)
{
    // Disconnect node/peer if send/recv data becomes idle
    if (GetTime() - pnode->nTimeConnected > IDLE_TIMEOUT)
    {
        if (GetTime() - pnode->nLastRecv > IDLE_TIMEOUT)
        {
            if (GetTime() - pnode->nLastSend < IDLE_TIMEOUT)
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - Unexpected idle interruption %s \n", __FUNCTION__, pnode->addrName);
                }

                pnode->CloseSocketDisconnect();
            }
        }
    }
}


// requires LOCK(cs_vSend)
void SocketSendData(CNode *pnode)
{
    std::deque<CSerializeData>::iterator it = pnode->vSendMsg.begin();

    while (it != pnode->vSendMsg.end())
    {
        // Detect if Firewall has found an attack node (true)
        if (Firewall::Monitoring::Init(pnode, "SendData") == true)
        {
            // Abort SendData
            return;
        }

        const CSerializeData &data = *it;

        if (data.size() <= pnode->nSendOffset)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - data.size() <= pnode->nSendOffset \n", __FUNCTION__);
            }

            return;
        }
        
        int nBytes = send(pnode->hSocket, &data[pnode->nSendOffset], data.size() - pnode->nSendOffset, MSG_NOSIGNAL | MSG_DONTWAIT);
        
        if (nBytes > 0)
        {
            pnode->nLastSend = GetTime();
            pnode->nSendBytes += nBytes;
            pnode->nSendOffset += nBytes;

            pnode->RecordBytesSent(nBytes);

            if (pnode->nSendOffset == data.size())
            {
                pnode->nSendOffset = 0;
                pnode->nSendSize -= data.size();

                it++;
            }
            else
            {
                if (fDebug)
                {
                    // could not send full message; stop sending more
                    LogPrint("net", "%s : ERROR - Socket send interruption \n", __FUNCTION__);
                }

                IdleNodeCheck(pnode);

                break;
            }
        }
        else
        {
            if (nBytes < 0)
            {
                // error
                int nErr = WSAGetLastError();
                
                if (nErr != WSAEWOULDBLOCK
                    && nErr != WSAEMSGSIZE
                    && nErr != WSAEINTR
                    && nErr != WSAEINPROGRESS)
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : ERROR - Socket send error %d \n", __FUNCTION__, nErr);
                    }

                    IdleNodeCheck(pnode);
                }
            }

            if (fDebug)
            {
                // couldn't send anything at all
                LogPrint("net", "%s : ERROR - Socket send data failure \n", __FUNCTION__);
            }

            IdleNodeCheck(pnode);

            break;
        }
    }

    if (it == pnode->vSendMsg.end())
    {
        if (pnode->nSendOffset != 0)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - pnode->nSendOffset != 0 \n", __FUNCTION__);
            }

            return;
        }

        if (pnode->nSendSize != 0)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - pnode->nSendOffset != 0 \n", __FUNCTION__);
            }

            return;
        }
    }

    pnode->vSendMsg.erase(pnode->vSendMsg.begin(), it);
}


static list<CNode*> vNodesDisconnected;


void ThreadSocketHandler()
{
    if (fImporting
        || fReindex)
    {
        return;
    }

    unsigned int nPrevNodeCount = 0;

    while (true)
    {
        //
        // Disconnect nodes
        //

        // Global Namespace Start
        {
            LOCK(cs_vNodes);

            // Disconnect unused nodes
            vector<CNode*> vNodesCopy = vNodes;

            for(CNode* pnode: vNodesCopy)
            {
                if (pnode->fDisconnect
                    || (pnode->GetRefCount() <= 0
                    && pnode->vRecvMsg.empty()
                    && pnode->nSendSize == 0
                    && pnode->ssSend.empty()))
                {
                    // remove from vNodes
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

                    // release outbound grant (if any)
                    pnode->grantOutbound.Release();

                    // close socket and cleanup
                    pnode->CloseSocketDisconnect();

                    // hold in disconnected pool until all refs are released
                    if (pnode->fNetworkNode
                        || pnode->fInbound)
                    {
                        pnode->Release();
                    }

                    vNodesDisconnected.push_back(pnode);
                }
            }
        }
        // Global Namespace End

        // Global Namespace Start
        {
            // Delete disconnected nodes
            list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;

            for(CNode* pnode: vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    {
                        TRY_LOCK(pnode->cs_vSend, lockSend);

                        if (lockSend)
                        {
                            TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);

                            if (lockRecv)
                            {
                                TRY_LOCK(pnode->cs_inventory, lockInv);

                                if (lockInv)
                                {
                                    fDelete = true;
                                }
                            }
                        }
                    }

                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);

                        delete pnode;
                    }
                }
            }
        }
        // Global Namespace End

        if(vNodes.size() != nPrevNodeCount)
        {
            nPrevNodeCount = vNodes.size();

            uiInterface.NotifyNumConnectionsChanged(nPrevNodeCount);
        }

        //
        // Find which sockets have data to receive
        //

        struct timeval timeout;

        timeout.tv_sec  = 0;

        // frequency to poll pnode->vSend
        timeout.tv_usec = 50000;

        fd_set fdsetRecv;
        fd_set fdsetSend;
        fd_set fdsetError;

        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);

        SOCKET hSocketMax = 0;

        bool have_fds = false;

        for(SOCKET hListenSocket: vhListenSocket)
        {
            FD_SET(hListenSocket, &fdsetRecv);

            hSocketMax = max(hSocketMax, hListenSocket);
            have_fds = true;
        }

        // Global Namespace Start
        {
            LOCK(cs_vNodes);

            for(CNode* pnode: vNodes)
            {
                if (pnode->hSocket == INVALID_SOCKET)
                {
                    continue;
                }

                FD_SET(pnode->hSocket, &fdsetError);

                hSocketMax = max(hSocketMax, pnode->hSocket);
                have_fds = true;

                // Implement the following logic:
                // * If there is data to send, select() for sending data. As this only
                //   happens when optimistic write failed, we choose to first drain the
                //   write buffer in this case before receiving more. This avoids
                //   needlessly queueing received data, if the remote peer is not themselves
                //   receiving data. This means properly utilizing TCP flow control signalling.
                // * Otherwise, if there is no (complete) message in the receive buffer,
                //   or there is space left in the buffer, select() for receiving data.
                // * (if neither of the above applies, there is certainly one message
                //   in the receiver buffer ready to be processed).
                // Together, that means that at least one of the following is always possible,
                // so we don't deadlock:
                // * We send some data.
                // * We wait for data to be received (and disconnect after timeout).
                // * We process a message in the buffer (message handler thread).

                // Global Namespace Start
                {
                    TRY_LOCK(pnode->cs_vSend, lockSend);

                    if (lockSend
                        && !pnode->vSendMsg.empty())
                    {
                        FD_SET(pnode->hSocket, &fdsetSend);

                        continue;
                    }
                }
                // Global Namespace End

                // Global Namespace Start
                {
                    TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);

                    if (lockRecv
                        && (pnode->vRecvMsg.empty()
                        || !pnode->vRecvMsg.front().complete()
                        || pnode->GetTotalRecvSize() <= ReceiveFloodSize()))
                    {
                        FD_SET(pnode->hSocket, &fdsetRecv);
                    }
                }
                // Global Namespace End
            }
            
        }
        // Global Namespace End

        int nSelect = select(have_fds ? hSocketMax + 1 : 0, &fdsetRecv, &fdsetSend, &fdsetError, &timeout);

        boost::this_thread::interruption_point();

        if (nSelect == SOCKET_ERROR)
        {
            if (have_fds)
            {
                int nErr = WSAGetLastError();

                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - Socket select %d \n", __FUNCTION__, nErr);
                }

                for (unsigned int i = 0; i <= hSocketMax; i++)
                {
                    FD_SET(i, &fdsetRecv);
                }

            }

            FD_ZERO(&fdsetSend);
            FD_ZERO(&fdsetError);

            MilliSleep(timeout.tv_usec/1000);
        }

        //
        // Accept new connections
        //

        for(SOCKET hListenSocket: vhListenSocket)
        {
            if (hListenSocket != INVALID_SOCKET && FD_ISSET(hListenSocket, &fdsetRecv))
            {
                struct sockaddr_storage sockaddr;

                socklen_t len = sizeof(sockaddr);

                SOCKET hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);
                CAddress addr;

                int nInbound = 0;

                if (hSocket != INVALID_SOCKET)
                {
                    if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr))
                    {
                        if (fDebug)
                        {
                            LogPrint("net", "%s : WARNING - Unknown socket family \n", __FUNCTION__);
                        }
                    }
                }

                // Global Namespace Start
                {
                    LOCK(cs_vNodes);

                    for(CNode* pnode: vNodes)
                    {
                        if (pnode->fInbound)
                        {
                            nInbound++;
                        }
                    }

                }
                // Global Namespace End

                if (hSocket == INVALID_SOCKET)
                {
                    int nErr = WSAGetLastError();

                    if (nErr != WSAEWOULDBLOCK)
                    {
                        if (fDebug)
                        {
                            LogPrint("net", "%s : ERROR - Socket accept failed: %d \n", __FUNCTION__, nErr);
                        }
                    }
                }
                else if (nInbound >= nMaxConnections - MAX_OUTBOUND_CONNECTIONS)
                {
                    closesocket(hSocket);
                }
                else if (CNode::IsBanned(addr))
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : WARNING - Connection from %s dropped (banned) \n", __FUNCTION__, addr.ToStringIPPort());
                    }

                    closesocket(hSocket);
                }
                else
                {
                    // According to the internet TCP_NODELAY is not carried into accepted sockets
                    // on all platforms.  Set it again here just to be sure.
                    int set = 1;
#ifdef WIN32
                    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
                    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif

                    if (FindNode(addr.ToStringIP().c_str()))
                    {
                        if (fDebug)
                        {
                            LogPrint("net", "%s : WARNING - Connection from %s dropped (duplicate connection) \n", __FUNCTION__, addr.ToStringIPPort());
                        }

                        closesocket(hSocket);

                        continue;
                    }

                    CNode* pnode = new CNode(hSocket, addr, "", true);

                    pnode->AddRef();

                    // Global Namespace Start
                    {
                        LOCK(cs_vNodes);

                        vNodes.push_back(pnode);
                    }
                    // Global Namespace End

                    if (fDebug)
                    {
                        LogPrint("net", "%s : OK - Accepted connection %s \n", __FUNCTION__, addr.ToStringIPPort());
                    }
                }
            }
        }
        

        //
        // Service each socket
        //
        vector<CNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);

            vNodesCopy = vNodes;

            for(CNode* pnode: vNodesCopy)
            {
                pnode->AddRef();
            }
        }

        //
        // Receive
        //
        for(CNode* pnode: vNodesCopy)
        {
            boost::this_thread::interruption_point();

            if (pnode->hSocket == INVALID_SOCKET)
            {
                continue;
            }

            if (FD_ISSET(pnode->hSocket, &fdsetRecv)
                || FD_ISSET(pnode->hSocket, &fdsetError))
            {
                TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);

                if (lockRecv)
                {
                    if (pnode->GetTotalRecvSize() > ReceiveFloodSize())
                    {
                        if (!pnode->fDisconnect)
                        {
                            if (fDebug)
                            {
                                LogPrint("net", "%s : WARNING - socket recv flood control disconnect (%u bytes) \n", __FUNCTION__, pnode->GetTotalRecvSize());
                            }
                        }

                        pnode->CloseSocketDisconnect();
                    }
                    else
                    {
                        // typical socket buffer is 8K-64K
                        char pchBuf[0x10000];

                        int nBytes = recv(pnode->hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);

                        if (nBytes > 0)
                        {
                            if (!pnode->ReceiveMsgBytes(pchBuf, nBytes))
                            {
                                pnode->CloseSocketDisconnect();
                            }

                            pnode->nLastRecv = GetTime();
                            pnode->nRecvBytes += nBytes;
                            pnode->RecordBytesRecv(nBytes);
                        }
                        else if (nBytes == 0)
                        {
                            // socket closed gracefully
                            if (!pnode->fDisconnect)
                            {
                                if (fDebug)
                                {
                                    LogPrint("net", "%s : OK - Socket closed \n", __FUNCTION__);
                                }
                            }

                            pnode->CloseSocketDisconnect();
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();

                            if (nErr != WSAEWOULDBLOCK
                                && nErr != WSAEMSGSIZE
                                && nErr != WSAEINTR
                                && nErr != WSAEINPROGRESS)
                            {
                                if (!pnode->fDisconnect)
                                {
                                    if (fDebug)
                                    {
                                        LogPrint("net", "%s : ERROR - Socket recv error %d \n", __FUNCTION__, nErr);
                                    }
                                }

                                pnode->CloseSocketDisconnect();
                            }
                        }
                    }
                }
            }

            //
            // Send
            //
            if (pnode->hSocket == INVALID_SOCKET)
            {
                continue;
            }

            if (FD_ISSET(pnode->hSocket, &fdsetSend))
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);

                if (lockSend)
                {
                    SocketSendData(pnode);
                }
            }

            //
            // Inactivity checking
            //
            if (pnode->vSendMsg.empty())
            {
                pnode->nLastSendEmpty = GetTime();
            }

            if (GetTime() - pnode->nTimeConnected > IDLE_TIMEOUT)
            {
                if (pnode->nLastRecv == 0
                    || pnode->nLastSend == 0)
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : ERROR - Socket no message in timeout, %d %d \n", __FUNCTION__, pnode->nLastRecv != 0, pnode->nLastSend != 0);
                    }

                    pnode->fDisconnect = true;

                    pnode->CloseSocketDisconnect();
                }
                else if (GetTime() - pnode->nLastSend > DATA_TIMEOUT)
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : ERROR - Socket not sending \n", __FUNCTION__);
                    }

                    pnode->fDisconnect = true;

                    pnode->CloseSocketDisconnect();
                }
                else if (GetTime() - pnode->nLastRecv > DATA_TIMEOUT)
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : ERROR - Socket inactivity timeout \n", __FUNCTION__);
                    }

                    pnode->fDisconnect = true;

                    pnode->CloseSocketDisconnect();
                }
            }
        }

        // Global Namespace Start
        {
            LOCK(cs_vNodes);

            for(CNode* pnode: vNodesCopy)
            {
                pnode->Release();
            }

        }
        // Global Namespace End
    }

    // Refresh nodes/peers every X minutes
    RefreshRecentConnections(2);
}


#ifdef USE_UPNP
void ThreadMapPort()
{
    std::string port = strprintf("%u", GetListenPort());
    const char * multicastif = 0;
    const char * minissdpdpath = 0;
    struct UPNPDev * devlist = 0;
    char lanaddr[64];

#ifndef UPNPDISCOVER_SUCCESS
    /* miniupnpc 1.5 */
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0);
#elif MINIUPNPC_API_VERSION < 14
    /* miniupnpc 1.6 */
    int error = 0;

    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, &error);
#else
    /* miniupnpc 1.9.20150730 */
    int error = 0;

    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, 2, &error);
#endif

    struct UPNPUrls urls;
    struct IGDdatas data;
    int r;

    r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if (r == 1)
    {
        if (fDiscover)
        {
            char externalIPAddress[40];

            r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);

            if(r != UPNPCOMMAND_SUCCESS)
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - UPnP GetExternalIPAddress() returned %d \n", __FUNCTION__, r);
                }
            }
            else
            {
                if(externalIPAddress[0])
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : OK - UPnP ExternalIPAddress = %s \n", __FUNCTION__, externalIPAddress);
                    }

                    AddLocal(CNetAddr(externalIPAddress), LOCAL_UPNP);
                }
                else
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : ERROR - UPnP GetExternalIPAddress failed. \n", __FUNCTION__);
                    }
                }
            }
        }

        string strDesc = "PHC " + FormatFullVersion();

        try
        {
            while (!ShutdownRequested())
            {
                boost::this_thread::interruption_point();

#ifndef UPNPDISCOVER_SUCCESS
                /* miniupnpc 1.5 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0);
#else
                /* miniupnpc 1.6 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0, "0");
#endif

                if(r!=UPNPCOMMAND_SUCCESS)
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : ERROR - (%s, %s, %s) Failed with code %d (%s) \n", __FUNCTION__, port, port, lanaddr, r, strupnperror(r));
                    }
                }
                else
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : OK - UPnP Port Mapping successful. \n", __FUNCTION__);;
                    }
                }

                // Refresh every 20 minutes 
                MilliSleep(20*60*1000);  
            }
        }
        catch (boost::thread_interrupted)
        {
            r = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port.c_str(), "TCP", 0);

            if (fDebug)
            {
                LogPrint("net", "%s : OK - UPNP_DeletePortMapping() returned : %d \n", __FUNCTION__, r);
            }

            freeUPNPDevlist(devlist); devlist = 0;

            FreeUPNPUrls(&urls);

            throw;
        }
    }
    else
    {
        if (fDebug)
        {
            LogPrint("net", "%s : WARNING - No valid UPnP IGDs found \n", __FUNCTION__);
        }

        freeUPNPDevlist(devlist); devlist = 0;

        if (r != 0)
        {
            FreeUPNPUrls(&urls);
        }
    }
}


void MapPort(bool fUseUPnP)
{
    static boost::thread* upnp_thread = NULL;

    if (fUseUPnP)
    {
        if (upnp_thread)
        {
            // Check if the thread is still running or not
            bool fThreadStopped = upnp_thread->timed_join(boost::posix_time::seconds(0));

            if (fThreadStopped)
            {
                delete upnp_thread;

                upnp_thread = NULL;
            }
        }

        if (!upnp_thread)
        {
            // Start the UPnP thread if not running
            upnp_thread = new boost::thread(boost::bind(&TraceThread<void (*)()>, "upnp", &ThreadMapPort));
        }
    }
    else if (upnp_thread)
    {
        upnp_thread->interrupt();

        if (ShutdownRequested())
        {
            // Only wait for the thread to finish if a shutdown is requested
            upnp_thread->join();

            delete upnp_thread;
            
            upnp_thread = NULL;
        }
    }
}


#else
void MapPort(bool)
{
    // Intentionally left blank.
}
#endif


void ThreadDNSAddressSeed()
{
    // goal: only query DNS seeds if address need is acute
    if ((addrman.size() > 0)
        && (!GetBoolArg("-forcednsseed", true)))
    {
        MilliSleep(11 * 1000);

        LOCK(cs_vNodes);

        if (vNodes.size() >= 8)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : WARNING - P2P peers available. Skipped DNS seeding. \n", __FUNCTION__);
            }

            return;
        }
    }

    const vector<CDNSSeedData> &vSeeds = Params().DNSSeeds();
    
    int found = 0;

    if (fDebug)
    {
        LogPrint("net", "%s : NOTICE - Loading addresses from DNS seeds (could take a while) \n", __FUNCTION__);
    }

    for(const CDNSSeedData &seed: vSeeds)
    {
        if (HaveNameProxy())
        {
            AddOneShot(seed.host);
        }
        else
        {
            vector<CNetAddr> vIPs;
            vector<CAddress> vAdd;

            if (LookupHost(seed.host.c_str(), vIPs))
            {
                for(CNetAddr& ip: vIPs)
                {
                    int nOneDay = 24*3600;

                    CAddress addr = CAddress(CService(ip, Params().GetDefaultPort()));
                    
                    // use a random age between 3 and 7 days old
                    addr.nTime = GetTime() - 3*nOneDay - GetRand(4*nOneDay);
                    
                    vAdd.push_back(addr);
                    
                    found++;
                }
            }

            addrman.Add(vAdd, CNetAddr(seed.name, true));
        }
    }

    if (fDebug)
    {
        LogPrint("net", "%s : OK - %d addresses found from DNS seeds \n", __FUNCTION__, found);
    }
}

void DumpAddresses()
{
    int64_t nStart = GetTimeMillis();

    CAddrDB adb;

    adb.Write(addrman);

    if (fDebug)
    {
        LogPrint("net", "%s : OK - Flushed %d addresses to peers.dat  %dms \n", __FUNCTION__, addrman.size(), GetTimeMillis() - nStart);
    }
}

void DumpData()
{
    DumpAddresses();

    if (CNode::BannedSetIsDirty())
    {
        DumpBanlist();

        CNode::SetBannedSetDirty(false);
    }
}

void static ProcessOneShot()
{
    string strDest;
    {
        LOCK(cs_vOneShots);

        if (vOneShots.empty())
        {
            return;
        }

        strDest = vOneShots.front();

        vOneShots.pop_front();
    }

    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, true);

    if (grant)
    {
        if (!OpenNetworkConnection(addr, &grant, strDest.c_str(), true))
        {
            AddOneShot(strDest);
        }
    }
}


void ThreadOpenConnections()
{
    if (fImporting
        || fReindex)
    {
        return;
    }

    // Connect to specific addresses
    if (mapArgs.count("-connect")
        && mapMultiArgs["-connect"].size() > 0)
    {
        for (int64_t nLoop = 0;; nLoop++)
        {
            ProcessOneShot();

            for(string strAddr: mapMultiArgs["-connect"])
            {
                CAddress addr;

                OpenNetworkConnection(addr, NULL, strAddr.c_str());

                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    MilliSleep(500);
                }
            }

            MilliSleep(500);
        }
    }

    // Initiate network connections
    int64_t nStart = GetTime();

    while (true)
    {
        ProcessOneShot();

        MilliSleep(500);

        CSemaphoreGrant grant(*semOutbound);

        boost::this_thread::interruption_point();

        // Add seed nodes if DNS seeds are all down (an infrastructure attack?).
        if (addrman.size() == 0
            && (GetTime() - nStart > 60))
        {
            static bool done = false;

            if (!done)
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : WARNING - Adding fixed seed nodes as DNS doesn't seem to be available. \n", __FUNCTION__);
                }

                addrman.Add(Params().FixedSeeds(), CNetAddr("127.0.0.1"));
                done = true;
            }
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per network group (/16 for IPv4).
        // Do this here so we don't have to critsect vNodes inside mapAddresses critsect.
        int nOutbound = 0;

        set<vector<unsigned char> > setConnected;
        {
            LOCK(cs_vNodes);

            for(CNode* pnode: vNodes)
            {
                if (!pnode->fInbound)
                {
                    setConnected.insert(pnode->addr.GetGroup());

                    nOutbound++;
                }
            }
        }

        int64_t nANow = GetAdjustedTime();

        int nTries = 0;

        while (true)
        {
            // use an nUnkBias between 10 (no outgoing connections) and 90 (8 outgoing connections)
            CAddress addr = addrman.Select();

            // if we selected an invalid address, restart
            if (!addr.IsValid()
                || setConnected.count(addr.GetGroup())
                || IsLocal(addr))
            {
                break;
            }

            // If we didn't find an appropriate destination after trying 100 addresses fetched from addrman,
            // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new addrman addresses.
            nTries++;

            if (nTries > 100)
            {
                break;
            }

            if (IsLimited(addr))
            {
                continue;
            }

            // only consider very recently tried nodes after 30 failed attempts
            if (nANow - addr.nLastTry < 600
                && nTries < 30)
            {
                continue;
            }

            // do not allow non-default ports, unless after 50 invalid addresses selected already
            /*if (addr.GetPort() != Params().GetDefaultPort() && nTries < 50)
                continue;*/

            addrConnect = addr;

            break;
        }

        if (addrConnect.IsValid())
        {
            OpenNetworkConnection(addrConnect, &grant);
        }

    }
}


void ThreadOpenAddedConnections()
{
    // Global Namespace Start
    {
        LOCK(cs_vAddedNodes);

        vAddedNodes = mapMultiArgs["-addnode"];
    }
    // Global Namespace End

    if (HaveNameProxy())
    {
        while(true)
        {
            list<string> lAddresses(0);
            {
                LOCK(cs_vAddedNodes);

                for(string& strAddNode: vAddedNodes)
                {
                    lAddresses.push_back(strAddNode);
                }
            }

            for(string& strAddNode: lAddresses)
            {
                CAddress addr;
                CSemaphoreGrant grant(*semOutbound);

                OpenNetworkConnection(addr, &grant, strAddNode.c_str());

                MilliSleep(500);
            }

            // Retry every 2 minutes
            MilliSleep(120000);
        }
    }

    for (unsigned int i = 0; true; i++)
    {
        list<string> lAddresses(0);
        {
            LOCK(cs_vAddedNodes);

            for(string& strAddNode: vAddedNodes)
            {
                lAddresses.push_back(strAddNode);
            }
        }

        list<vector<CService> > lservAddressesToAdd(0);

        for(string& strAddNode: lAddresses)
        {
            vector<CService> vservNode(0);

            if(Lookup(strAddNode.c_str(), vservNode, Params().GetDefaultPort(), fNameLookup, 0))
            {
                lservAddressesToAdd.push_back(vservNode);

                // Global Namespace Start
                {
                    LOCK(cs_setservAddNodeAddresses);

                    for(CService& serv: vservNode)
                    {
                        setservAddNodeAddresses.insert(serv);
                    }
                }
                // Global Namespace End
            }
        }

        // Global Namespace Start
        {
            // Attempt to connect to each IP for each addnode entry until at least one is successful per addnode entry
            // (keeping in mind that addnode entries can have many IPs if fNameLookup)

            LOCK(cs_vNodes);

            for(CNode* pnode: vNodes)
            {
                for (list<vector<CService> >::iterator it = lservAddressesToAdd.begin(); it != lservAddressesToAdd.end(); it++)
                {
                    for(CService& addrNode: *(it))
                    {
                        if (pnode->addr == addrNode)
                        {
                            it = lservAddressesToAdd.erase(it);

                            it--;

                            break;
                        }
                    }
                }
            }
        }
        // Global Namespace End

        for(vector<CService>& vserv: lservAddressesToAdd)
        {
            CSemaphoreGrant grant(*semOutbound);

            OpenNetworkConnection(CAddress(vserv[i % vserv.size()]), &grant);

            MilliSleep(500);
        }

        // Retry every 2 minutes
        MilliSleep(120000); 
    }
}


// if successful, this moves the passed grant to the constructed node
bool OpenNetworkConnection(const CAddress& addrConnect, CSemaphoreGrant *grantOutbound, const char *strDest, bool fOneShot)
{
    if (fImporting
        || fReindex)
    {
        return false;
    }

    //
    // Initiate outbound network connection
    //

    boost::this_thread::interruption_point();

    if (!strDest)
    {
        if (IsLocal(addrConnect) == true
            || FindNode((CNetAddr)addrConnect) != NULL
            || CNode::IsBanned(addrConnect) == true
            || FindNode(addrConnect.ToStringIP().c_str()) != NULL
            )
        {
            return false;
        }
    }

    if (strDest && FindNode(strDest))
    {
        return false;
    }

    CNode* pnode = ConnectNode(addrConnect, strDest);
    
    boost::this_thread::interruption_point();

    if (!pnode)
    {
        return false;
    }

    // Detect if Firewall has found an attack node (true)
    if (Firewall::Monitoring::Init(pnode, "OpenNetConnection") == false)
    {
        // Abort
        return false;
    }

    if (grantOutbound)
    {
        grantOutbound->MoveTo(pnode->grantOutbound);
    }

    pnode->fNetworkNode = true;

    if (fOneShot)
    {
        pnode->fOneShot = true;
    }

    // Connection Accepted/Open
    return true;
}

int nLastSyncCycle;

void static NodeSync(const vector<CNode*> &vNodes)
{
    // fImporting and fReindex are accessed out of cs_main here, but only
    // as an optimization - they are checked again in SendMessages.
    if (fImporting
        || fReindex)
    {
        return;
    }

    if (nLastSyncCycle > 0
        && nLastSyncCycle > GetTime() - 60)
    {
        return;
    }

    nLastSyncCycle = GetTime();

    // Iterate over all nodes
    for(CNode* pnode: vNodes)
    {
        LOCK(cs_vNodes);

        // check preconditions for allowing a sync
        if (!pnode->fClient
            && !pnode->fSyncNode
            && pnode->nRefCount > 0
            && pnode->nLastRecv > 0
            && !pnode->fOneShot
            && !pnode->fDisconnect
            && pnode->fSuccessfullyConnected
            && (pnode->nStartingHeight > (nBestHeight - 144))
            && (pnode->nVersion < NOBLKS_VERSION_START || pnode->nVersion >= NOBLKS_VERSION_END))
        {
            // if a new sync candidate was found, start sync!
            pnode->fSyncNode = true;
            
            // Force a new GetBlocks request to each node if Hypersync mode is enabled
            if (GetBoolArg("-hypersync", false) == true)
            {
                pnode->PushGetBlocks(pindexBest->pprev, uint256(0));
            }
        }
    }
}


void ThreadMessageHandler()
{
    Set_ThreadPriority(THREAD_PRIORITY_BELOW_NORMAL);

    while (true)
    {
        vector<CNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);

            vNodesCopy = vNodes;

            for(CNode* pnode: vNodesCopy)
            {
                pnode->AddRef();
            }
        }

        NodeSync(vNodesCopy);

        CNode* pnodeTrickle = NULL;

        if (!vNodesCopy.empty())
        {
            // Poll the connected nodes for messages
            pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
        }

        bool fSleep = true;

        for(CNode* pnode: vNodesCopy)
        {
            if (pnode->fDisconnect)
            {
                continue;
            }

            // Global Namespace Start
            {
                // Receive messages
                TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);

                if (lockRecv)
                {
                    if (!g_signals.ProcessMessages(pnode))
                    {
                        pnode->CloseSocketDisconnect();
                    }

                    IdleNodeCheck(pnode);

                    if (pnode->nSendSize < SendBufferSize())
                    {
                        if (!pnode->vRecvGetData.empty()
                            || (!pnode->vRecvMsg.empty()
                            && pnode->vRecvMsg[0].complete()))
                        {
                            fSleep = false;
                        }
                    }
                }
            }
            // Global Namespace End

            boost::this_thread::interruption_point();

            // Global Namespace Start
            {
                // Send messages

                TRY_LOCK(pnode->cs_vSend, lockSend);

                if (lockSend)
                {
                    g_signals.SendMessages(pnode, pnode == pnodeTrickle);
                }

            }
            // Global Namespace End

            boost::this_thread::interruption_point();
        }

        // Global Namespace Start
        {
            LOCK(cs_vNodes);

            for(CNode* pnode: vNodesCopy)
            {
                pnode->Release();
            }
        }
        // Global Namespace End

        if (fSleep)
        {
            MilliSleep(100);
        }

    }
}


bool BindListenPort(const CService &addrBind, string& strError)
{
    strError = "";

    int nOne = 1;

#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    
    if (ret != NO_ERROR)
    {
        if (fDebug)
        {
            strError = strprintf("TCP/IP socket library failed to start (WSAStartup returned error %d)", ret);
            LogPrint("net", "%s : ERROR - %s \n", __FUNCTION__, strError);
        }

        return false;
    }
#endif

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);

    if (!addrBind.GetSockAddr((struct sockaddr*)&sockaddr, &len))
    {
        if (fDebug)
        {
            strError = strprintf("Bind address family for %s not supported", addrBind.ToString());

            LogPrint("net", "%s : ERROR - %s \n", __FUNCTION__, strError);
        }

        return false;
    }

    SOCKET hListenSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    
    if (hListenSocket == INVALID_SOCKET)
    {
        if (fDebug)
        {
            strError = strprintf("Couldn't open socket for incoming connections (socket returned error %d)", WSAGetLastError());
            
            LogPrint("net", "%s : ERROR - %s \n", __FUNCTION__, strError);
        }

        return false;
    }


#ifndef WIN32
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hListenSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&nOne, sizeof(int));
#endif
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.  Not an issue on windows.
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
    // Disable Nagle's algorithm
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&nOne, sizeof(int));
#else
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&nOne, sizeof(int));
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&nOne, sizeof(int));
#endif


#ifdef WIN32
    // Set to non-blocking, incoming connections will also inherit this
    if (ioctlsocket(hListenSocket, FIONBIO, (u_long*)&nOne) == SOCKET_ERROR)
#else
    if (fcntl(hListenSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
#endif
    {
        if (fDebug)
        {
            strError = strprintf("Couldn't set properties on socket for incoming connections (error %d)", WSAGetLastError());
            
            LogPrint("net", "%s : ERROR - %s \n", __FUNCTION__, strError);
        }

        return false;
    }

    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (addrBind.IsIPv6())
    {
#ifdef IPV6_V6ONLY
#ifdef WIN32
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&nOne, sizeof(int));
#else
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&nOne, sizeof(int));
#endif
#endif

#ifdef WIN32
        int nProtLevel = 10 /* PROTECTION_LEVEL_UNRESTRICTED */;
        int nParameterId = 23 /* IPV6_PROTECTION_LEVEl */;

        // this call is allowed to fail
        setsockopt(hListenSocket, IPPROTO_IPV6, nParameterId, (const char*)&nProtLevel, sizeof(int));
#endif
    }

    if (::bind(hListenSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();

        if (fDebug)
        {
            if (nErr == WSAEADDRINUSE)
            {
                strError = strprintf(_("Unable to bind to %s on this computer. PHC is probably already running."), addrBind.ToString());
            }
            else
            {
                strError = strprintf(_("Unable to bind to %s on this computer (bind returned error %d, %s)"), addrBind.ToString(), nErr, strerror(nErr));
            }

            LogPrint("net", "%s : ERROR - %s \n", __FUNCTION__, strError);
        }

        return false;
    }

    if (fDebug)
    {
        LogPrint("net", "%s : NOTICE - Bound to %s \n", __FUNCTION__, addrBind.ToString());
    }

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        if (fDebug)
        {
            strError = strprintf("Listening for incoming connections failed (listen returned error %d)", WSAGetLastError());
            
            LogPrint("net", "%s : ERROR - %s \n", __FUNCTION__, strError);
        }

        return false;
    }

    vhListenSocket.push_back(hListenSocket);

    if (addrBind.IsRoutable()
        && fDiscover)
    {
        AddLocal(addrBind, LOCAL_BIND);
    }

    return true;
}


void static Discover(boost::thread_group& threadGroup)
{
    if (!fDiscover)
    {
        return;
    }

#ifdef WIN32
    // Get local host IP
    char pszHostName[1000] = "";

    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        vector<CNetAddr> vaddr;
        if (LookupHost(pszHostName, vaddr))
        {
            for(const CNetAddr &addr: vaddr)
            {
                AddLocal(addr, LOCAL_IF);
            }
        }
    }
#else
    // Get local host ip
    struct ifaddrs* myaddrs;

    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL)
            {
                continue;
            }

            if ((ifa->ifa_flags
                & IFF_UP) == 0)
            {
                continue;
            }

            if (strcmp(ifa->ifa_name, "lo") == 0)
            {
                continue;
            }

            if (strcmp(ifa->ifa_name, "lo0") == 0)
            {
                continue;
            }

            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                
                CNetAddr addr(s4->sin_addr);

                if (AddLocal(addr, LOCAL_IF))
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : OK - IPv4 %s: %s \n", __FUNCTION__, ifa->ifa_name, addr.ToString());
                    }
                }
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                
                CNetAddr addr(s6->sin6_addr);

                if (AddLocal(addr, LOCAL_IF))
                {
                    if (fDebug)
                    {
                        LogPrint("net", "%s : OK - IPv6 %s: %s \n", __FUNCTION__, ifa->ifa_name, addr.ToString());
                    }
                }

            }
        }

        freeifaddrs(myaddrs);
    }
#endif

}


void StartNode(boost::thread_group& threadGroup)
{

    //try to read stored banlist
    CBanDB bandb;
    
    banmap_t banmap;

    if (!bandb.Read(banmap))
    {
        if (fDebug)
        {
            LogPrint("net", "%s : WARNING - Invalid or missing banlist.dat; recreating \n", __FUNCTION__);
        }
    }

    //thread save setter
    CNode::SetBanned(banmap);

    //no need to write down just read or nonexistent data
    CNode::SetBannedSetDirty(false);

    //sweap out unused entries
    CNode::SweepBanned();

    if (semOutbound == NULL)
    {
        // initialize semaphore
        int nMaxOutbound = min(MAX_OUTBOUND_CONNECTIONS, nMaxConnections);
        
        semOutbound = new CSemaphore(nMaxOutbound);
    }

    if (pnodeLocalHost == NULL)
    {
        pnodeLocalHost = new CNode(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0), nLocalServices));
    }

    Discover(threadGroup);

    //
    // Start threads
    //

    if (!GetBoolArg("-dnsseed", true))
    {
        if (fDebug)
        {
            LogPrint("net", "%s : WARNING - DNS seeding disabled \n", __FUNCTION__);
        }
    }
    else
    {
        threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "dnsseed", &ThreadDNSAddressSeed));
    }

#ifdef USE_UPNP
    // Map ports with UPnP
    MapPort(GetBoolArg("-upnp", USE_UPNP));
#endif
    
    // Send and receive from sockets, accept connections
    threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "net", &ThreadSocketHandler));

    // Initiate outbound connections from -addnode
    threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "addcon", &ThreadOpenAddedConnections));

    // Initiate outbound connections
    threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "opencon", &ThreadOpenConnections));

    // Process messages
    threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "msghand", &ThreadMessageHandler));

    // Dump network addresses
    threadGroup.create_thread(boost::bind(&LoopForever<void (*)()>, "dumpaddr", &DumpData, DUMP_ADDRESSES_INTERVAL * 1000));
}


bool StopNode()
{
    if (fDebug)
    {
        LogPrint("net", "%s : NOTICE - StopNode() \n", __FUNCTION__);
    }

    MapPort(false);

    mempool.AddTransactionsUpdated(1);

    if (semOutbound)
    {
        for (int i=0; i<MAX_OUTBOUND_CONNECTIONS; i++)
        {
            semOutbound->post();
        }
    }

    DumpData();

    MilliSleep(50);

    DumpAddresses();

    return true;
}


class CNetCleanup
{
    public:

        CNetCleanup()
        {
        }
        ~CNetCleanup()
        {
            // Close sockets
            for(CNode* pnode: vNodes)
            {
                if (pnode->hSocket != INVALID_SOCKET)
                {
                    closesocket(pnode->hSocket);
                }
            }

            for(SOCKET hListenSocket: vhListenSocket)
            {
                if (hListenSocket != INVALID_SOCKET)
                {
                    if (closesocket(hListenSocket) == SOCKET_ERROR)
                    {
                        if (fDebug)
                        {
                            LogPrint("net", "%s : ERROR - Closesocket(hListenSocket) failed with error %d \n", __FUNCTION__, WSAGetLastError());
                        }
                    }
                }
            }

            // clean up some globals (to help leak detection)
            for(CNode *pnode: vNodes)
            {
                delete pnode;
            }

            for(CNode *pnode: vNodesDisconnected)
            {
                delete pnode;
            }

            vNodes.clear();
            vNodesDisconnected.clear();

            delete semOutbound;
            
            semOutbound = NULL;
            
            delete pnodeLocalHost;
            
            pnodeLocalHost = NULL;

#ifdef WIN32
            // Shutdown Windows Sockets
            WSACleanup();
#endif
        }
}
instance_of_cnetcleanup;


void RelayTransaction(const CTransaction& tx, const uint256& hash)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss.reserve(10000);
    ss << tx;

    RelayTransaction(tx, hash, ss);
}


void RelayTransaction(const CTransaction& tx, const uint256& hash, const CDataStream& ss)
{
    CInv inv(MSG_TX, hash);
    {
        LOCK(cs_mapRelay);

        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelay.erase(vRelayExpiration.front().second);

            vRelayExpiration.pop_front();
        }

        // Save original serialized message so newer versions are preserved
        mapRelay.insert(std::make_pair(inv, ss));

        vRelayExpiration.push_back(std::make_pair(GetTime() + 15 * 60, inv));
    }

    RelayInventory(inv);
}


void RelayTransactionLockReq(const CTransaction& tx, bool relayToAll)
{
    CInv inv(MSG_TXLOCK_REQUEST, tx.GetHash());

    //broadcast the new lock
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        if(!relayToAll
            && !pnode->fRelayTxes)
        {
            continue;
        }

        pnode->PushMessage("txlreq", tx);
    }
}


void CNode::RecordBytesRecv(uint64_t bytes)
{
    LOCK(cs_totalBytesRecv);

    nTotalBytesRecv += bytes;
}

void CNode::RecordBytesSent(uint64_t bytes)
{
    LOCK(cs_totalBytesSent);

    nTotalBytesSent += bytes;
}

uint64_t CNode::GetTotalBytesRecv()
{
    LOCK(cs_totalBytesRecv);

    return nTotalBytesRecv;
}

uint64_t CNode::GetTotalBytesSent()
{
    LOCK(cs_totalBytesSent);

    return nTotalBytesSent;
}

//
// CAddrDB
//

CAddrDB::CAddrDB()
{
    pathAddr = GetDataDir(true) / "peers.dat";
}

bool CAddrDB::Write(const CAddrMan& addr)
{
    // Generate random temporary filename
    unsigned short randv = 0;

    GetRandBytes((unsigned char *)&randv, sizeof(randv));

    std::string tmpfn = strprintf("peers.dat.%04x", randv);

    // serialize addresses, checksum data up to that point, then append csum
    CDataStream ssPeers(SER_DISK, CLIENT_VERSION);
    ssPeers << FLATDATA(Params().MessageStart());
    ssPeers << addr;
    uint256 hash = Hash(ssPeers.begin(), ssPeers.end());
    ssPeers << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = GetDataDir(true) / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout = CAutoFile(file, SER_DISK, CLIENT_VERSION);

    if (fileout.IsNull())
    {
        return error("%s : ERROR - Open failed", __FUNCTION__);
    }

    // Write and commit header, data
    try
    {
        fileout << ssPeers;
    }
    catch (std::exception &e)
    {
        return error("%s : ERROR - I/O error", __FUNCTION__);
    }

    FileCommit(fileout.Get());

    fileout.fclose();

    // replace existing peers.dat, if any, with new peers.dat.XXXX
    if (!RenameOver(pathTmp, pathAddr))
    {
        return error("%s : ERROR - Rename-into-place failed", __FUNCTION__);
    }

    return true;
}


bool CAddrDB::Read(CAddrMan& addr)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathAddr.string().c_str(), "rb");
    CAutoFile filein = CAutoFile(file, SER_DISK, CLIENT_VERSION);
    
    if (filein.IsNull())
    {
        return error("%s : ERROR - Open failed", __FUNCTION__);
    }

    // use file size to size memory buffer
    std::size_t fileSize = boost::filesystem::file_size(pathAddr);
    int64_t dataSize = fileSize - sizeof(uint256);

    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
    {
        dataSize = fileSize - sizeof(uint256);
    }

    if ( dataSize < 0 )
    {
        dataSize = 0;
    }

    vector<unsigned char> vchData;

    vchData.resize(dataSize);
    
    uint256 hashIn;

    // read data and checksum from file
    try
    {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (std::exception &e)
    {
        return error("%s : 2 : ERROR - I/O error or stream data corrupted", __FUNCTION__);
    }

    filein.fclose();

    CDataStream ssPeers(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssPeers.begin(), ssPeers.end());
    
    if (hashIn != hashTmp)
    {
        return error("%s : ERROR - Checksum mismatch; data corrupted", __FUNCTION__);
    }

    unsigned char pchMsgTmp[4];

    try
    {
        // de-serialize file header (network specific magic number) and ..
        ssPeers >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
        {
            return error("%s : ERROR - Invalid network magic number", __FUNCTION__);
        }

        // de-serialize address data into one CAddrMan object
        ssPeers >> addr;
    }
    catch (std::exception &e)
    {
        return error("%s : ERROR - I/O error or stream data corrupted", __FUNCTION__);
    }

    return true;
}


//
// CBanDB
//

CBanDB::CBanDB()
{
    pathBanlist = GetDataDir(true) / "banlist.dat";
}


bool CBanDB::Write(const banmap_t& banSet)
{
    // Generate random temporary filename
    unsigned short randv = 0;

    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    
    std::string tmpfn = strprintf("banlist.dat.%04x", randv);

    // serialize banlist, checksum data up to that point, then append csum
    CDataStream ssBanlist(SER_DISK, CLIENT_VERSION);
    
    ssBanlist << FLATDATA(Params().MessageStart());
    ssBanlist << banSet;
    
    uint256 hash = Hash(ssBanlist.begin(), ssBanlist.end());

    ssBanlist << hash;


    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = GetDataDir(true) / tmpfn;
    
    FILE *file = fopen(pathTmp.string().c_str(), "wb");

    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);

    if (fileout.IsNull())
    {
        return error("%s: ERROR - Failed to open file %s", __FUNCTION__, pathTmp.string());
    }

    // Write and commit header, data
    try
    {
        fileout << ssBanlist;
    }
    catch (const std::exception& e)
    {
        return error("%s: ERROR - Serialize or I/O error - %s", __FUNCTION__, e.what());
    }

    FileCommit(fileout.Get());
    
    fileout.fclose();

    // replace existing banlist.dat, if any, with new banlist.dat.XXXX
    if (!RenameOver(pathTmp, pathBanlist))
    {
        return error("%s: ERROR - Rename-into-place failed", __FUNCTION__);
    }

    return true;
}


bool CBanDB::Read(banmap_t& banSet)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathBanlist.string().c_str(), "rb");

    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);

    if (filein.IsNull())
    {
        return error("%s: ERROR - Failed to open file %s", __FUNCTION__, pathBanlist.string());
    }

    // use file size to size memory buffer
    uint64_t fileSize = boost::filesystem::file_size(pathBanlist);
    uint64_t dataSize = 0;

    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
    {
        dataSize = fileSize - sizeof(uint256);
    }

    vector<unsigned char> vchData;

    vchData.resize(dataSize);

    uint256 hashIn;

    // read data and checksum from file
    try
    {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (const std::exception& e)
    {
        return error("%s: ERROR - Deserialize or I/O error - %s", __FUNCTION__, e.what());
    }

    filein.fclose();

    CDataStream ssBanlist(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssBanlist.begin(), ssBanlist.end());
    
    if (hashIn != hashTmp)
    {
        return error("%s: ERROR - Checksum mismatch, data corrupted", __FUNCTION__);
    }

    unsigned char pchMsgTmp[4];
    try
    {
        // de-serialize file header (network specific magic number) and ..
        ssBanlist >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
        {
            return error("%s: ERROR - Invalid network magic number", __FUNCTION__);
        }

        // de-serialize address data into one CAddrMan object
        ssBanlist >> banSet;
    }
    catch (const std::exception& e)
    {
        return error("%s: ERROR - Deserialize or I/O error - %s", __FUNCTION__, e.what());
    }

    return true;
}

void DumpBanlist()
{
    int64_t nStart = GetTimeMillis();

    //clean unused entires (if bantime has expired)
    CNode::SweepBanned();

    CBanDB bandb;

    banmap_t banmap;

    CNode::GetBanned(banmap);

    bandb.Write(banmap);

    if (fDebug)
    {
        LogPrint("net", "%s : OK - Flushed %d banned node ips/subnets to banlist.dat  %dms \n", __FUNCTION__, banmap.size(), GetTimeMillis() - nStart);
    }
}


