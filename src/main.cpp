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


#include "main.h"
#include "addrman.h"
#include "alert.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "db.h"
#include "init.h"
#include "kernel.h"
#include "net.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "instantx.h"
#include "darksend.h"
#include "masternodeman.h"
#include "masternode-payments.h"
#include "spork.h"
#include "smessage.h"
#include "util.h"
#include "rpcserver.h"
#include "consensus.h"

#include <iostream>
#include <string>
#include <sstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/range/adaptor/reversed.hpp>


using namespace std;
using namespace boost;
using namespace CBan;

//
// Global state
//

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;

map<uint256, CBlockIndex*> mapBlockIndex;
set<pair<COutPoint, unsigned int> > setStakeSeen;
map<uint256, int> mapProofOfStake;

CBigNum bnProofOfStakeLimit(~uint256(0) >> 20);

// 1 hours
unsigned int nStakeMinAge = 60 * 60;

// time to elapse before new modifier is computed (8 hours)
unsigned int nModifierInterval = 8 * 60;

// TargetTimespan increased to prevent stalled blocks during development testing (2 Minutes)
static int64_t nTargetTimespan = 120;

// Target Spacing (1 Minute)
static const int64_t nTargetSpacing = 60; 

//static const int64_t nInterval = nTargetTimespan / nTargetSpacing;

// Block Shield
CAmount StakeRewardAverage;
int BlockShieldCounter;
std::string BlockShieldLogCache;

int nCoinbaseMaturity = 100;

CBlockIndex* pindexGenesisBlock = NULL;

int nBestHeight = -1;

uint256 nBestChainTrust = uint256();
uint256 nBestInvalidTrust = uint256();

uint256 hashBestChain = uint256();
CBlockIndex* pindexBest = NULL;

int64_t nTimeBestReceived = 0;

bool fImporting = false;
bool fReindex = false;
bool fAddrIndex = false;
bool fHaveGUI = false;

struct COrphanBlock
 {
    uint256 hashBlock;
    uint256 hashPrev;
    std::pair<COutPoint, unsigned int> stake;
    vector<unsigned char> vchBlock;
};

map<uint256, COrphanBlock*> mapOrphanBlocks;
multimap<uint256, COrphanBlock*> mapOrphanBlocksByPrev;
set<pair<COutPoint, unsigned int> > setStakeSeenOrphan;

map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "PHC Signed Message:\n";

double dHashesPerSec;
int64_t nHPSTimerStart;

std::set<uint256> setValidatedTx;

// Keep track of reorganization cycles when OrphanBlock is received, Reset when Block is accepted.
int fReorganizeCount;

// Keep track of ForceSync cyles when OrphanBlock is received, Reset when Block is accepted.
unsigned fForceSyncAfterOrphan;

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

namespace
{
    struct CMainSignals
    {
        // Notifies listeners of updated transaction data (passing hash, transaction, and optionally the block it is found in.
        boost::signals2::signal<void (const CTransaction &, const CBlock *, bool, bool)> SyncTransaction;
        // Notifies listeners of an erased transaction (currently disabled, requires transaction replacement).
        boost::signals2::signal<void (const uint256 &)> EraseTransaction;
        // Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible).
        boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
        // Notifies listeners of a new active block chain.
        boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
        // Notifies listeners about an inventory item being seen on the network.
        boost::signals2::signal<void (const uint256 &)> Inventory;
        // Tells listeners to broadcast their data.
        boost::signals2::signal<void (bool)> Broadcast;

    } g_signals;
}

void RegisterWallet(CWalletInterface* pwalletIn)
{
    g_signals.SyncTransaction.connect(boost::bind(&CWalletInterface::SyncTransaction, pwalletIn, _1, _2, _3, _4));
    g_signals.EraseTransaction.connect(boost::bind(&CWalletInterface::EraseFromWallet, pwalletIn, _1));
    g_signals.UpdatedTransaction.connect(boost::bind(&CWalletInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.SetBestChain.connect(boost::bind(&CWalletInterface::SetBestChain, pwalletIn, _1));
    g_signals.Inventory.connect(boost::bind(&CWalletInterface::Inventory, pwalletIn, _1));
    g_signals.Broadcast.connect(boost::bind(&CWalletInterface::ResendWalletTransactions, pwalletIn, _1));
}

void UnregisterWallet(CWalletInterface* pwalletIn)
{
    g_signals.Broadcast.disconnect(boost::bind(&CWalletInterface::ResendWalletTransactions, pwalletIn, _1));
    g_signals.Inventory.disconnect(boost::bind(&CWalletInterface::Inventory, pwalletIn, _1));
    g_signals.SetBestChain.disconnect(boost::bind(&CWalletInterface::SetBestChain, pwalletIn, _1));
    g_signals.UpdatedTransaction.disconnect(boost::bind(&CWalletInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.EraseTransaction.disconnect(boost::bind(&CWalletInterface::EraseFromWallet, pwalletIn, _1));
    g_signals.SyncTransaction.disconnect(boost::bind(&CWalletInterface::SyncTransaction, pwalletIn, _1, _2, _3, _4));
}

void UnregisterAllWallets()
{
    g_signals.Broadcast.disconnect_all_slots();
    g_signals.Inventory.disconnect_all_slots();
    g_signals.SetBestChain.disconnect_all_slots();
    g_signals.UpdatedTransaction.disconnect_all_slots();
    g_signals.EraseTransaction.disconnect_all_slots();
    g_signals.SyncTransaction.disconnect_all_slots();
}

void SyncWithWallets(const CTransaction &tx, const CBlock *pblock, bool fConnect, bool fFixSpentCoins)
{
	g_signals.SyncTransaction(tx, pblock, fConnect, fFixSpentCoins);
}

void ResendWalletTransactions(bool fForce)
{
    g_signals.Broadcast(fForce);
}

//////////////////////////////////////////////////////////////////////////////
//
// Block/Peer Management
//

// Internal stuff
namespace
{
    /** Number of nodes with fSyncStarted. */
    //int nSyncStarted = 0;

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    //CCriticalSection cs_nBlockSequenceId;

    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    //uint32_t nBlockSequenceId = 1;

    /**
     * Sources of received blocks, saved to be able to send them reject
     * messages or ban them when processing happens afterwards. Protected by
     * cs_main.
     */
    //map<uint256, NodeId> mapBlockSource;

    /**
     * Filter for transactions that were recently rejected by
     * AcceptToMemoryPool. These are not rerequested until the chain tip
     * changes, at which point the entire filter is reset. Protected by
     * cs_main.
     *
     * Without this filter we'd be re-requesting txs from each of our peers,
     * increasing bandwidth consumption considerably. For instance, with 100
     * peers, half of which relay a tx we don't accept, that might be a 50x
     * bandwidth increase. A flooding attacker attempting to roll-over the
     * filter using minimum-sized, 60byte, transactions might manage to send
     * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
     * two minute window to send invs to us.
     *
     * Decreasing the false positive rate is fairly cheap, so we pick one in a
     * million to make it highly unlikely for users to have issues with this
     * filter.
     *
     * Memory used: 1.7MB
     */
    //boost::scoped_ptr<CRollingBloomFilter> recentRejects;
    //uint256 hashRecentRejectsBlock;

    /** Blocks that are in flight, and that are in the queue to be downloaded. Protected by cs_main. */
    //struct QueuedBlock
    //{
    //    uint256 hash;
    //    CBlockIndex *pindex;  //! Optional.
    //    int64_t nTime;  //! Time of "getdata" request in microseconds.
    //    bool fValidatedHeaders;  //! Whether this block has validated headers at the time of request.
    //    int64_t nTimeDisconnect; //! The timeout for this block request (for disconnecting a slow peer)
    //};

    //map<uint256, pair<NodeId, list<QueuedBlock>::iterator> > mapBlocksInFlight;

    /** Number of blocks in flight with validated headers. */
    //int nQueuedValidatedHeaders = 0;

    /** Number of preferable block download peers. */
    //int nPreferredDownload = 0;

    /** Dirty block index entries. */
    //set<CBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    //set<int> setDirtyFileInfo;

} // anon namespace


//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

namespace
{
    // Maintain validation-specific state about nodes, protected by cs_main, instead
    // by CNode's own locks. This simplifies asynchronous operation, where
    // processing of incoming data is done after the ProcessMessage call returns,
    // and we're no longer holding the node's locks.
    struct CNodeState
    {
        // Accumulated misbehaviour score for this peer.
        int nMisbehavior;
        
        // Whether this peer should be disconnected and banned.
        bool fShouldBan;
        
        std::string name;

        CNodeState()
        {
            nMisbehavior = 0;
            fShouldBan = false;
        }
    };

    map<NodeId, CNodeState> mapNodeState;

    // Requires cs_main.
    CNodeState *State(NodeId pnode)
    {
        map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);

        if (it == mapNodeState.end())
        {
            return NULL;
        }

        return &it->second;
    }

    int GetHeight()
    {
        while(true)
        {
            TRY_LOCK(cs_main, lockMain);

            if(!lockMain)
            {
                MilliSleep(50);

                continue;
            }

            return pindexBest->nHeight;
        }
    }

    void InitializeNode(NodeId nodeid, const CNode *pnode)
    {
        LOCK(cs_main);

        CNodeState &state = mapNodeState.insert(std::make_pair(nodeid, CNodeState())).first->second;

        state.name = pnode->addrName;
    }

    void FinalizeNode(NodeId nodeid)
    {
        LOCK(cs_main);

        mapNodeState.erase(nodeid);
    }

}


bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats)
{
    LOCK(cs_main);

    CNodeState *state = State(nodeid);

    if (state == NULL)
    {
        return false;
    }

    stats.nMisbehavior = state->nMisbehavior;

    return true;
}


void RegisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.GetHeight.connect(&GetHeight);
    nodeSignals.ProcessMessages.connect(&ProcessMessages);
    nodeSignals.SendMessages.connect(&SendMessages);
    nodeSignals.InitializeNode.connect(&InitializeNode);
    nodeSignals.FinalizeNode.connect(&FinalizeNode);
}


void UnregisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.GetHeight.disconnect(&GetHeight);
    nodeSignals.ProcessMessages.disconnect(&ProcessMessages);
    nodeSignals.SendMessages.disconnect(&SendMessages);
    nodeSignals.InitializeNode.disconnect(&InitializeNode);
    nodeSignals.FinalizeNode.disconnect(&FinalizeNode);
}



bool AbortNode(const std::string &strMessage, const std::string &userMessage)
{
    strMiscWarning = strMessage;

    if (fDebug)
    {
        LogPrint("net", "%s : ERROR - *** %s \n", __FUNCTION__, strMessage);
    }

    uiInterface.ThreadSafeMessageBox(userMessage.empty() ? _("ERROR - A fatal internal error occured, see debug.log for details") : userMessage, "", CClientUIInterface::MSG_ERROR);
    
    StartShutdown();

    return false;
}

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();

    if (mapOrphanTransactions.count(hash))
    {
        return false;
    }

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);

    if (nSize > 5000)
    {
        if (fDebug)
        {
            LogPrint("mempool", "%s : ERROR - Ignoring large orphan tx (size: %u, hash: %s) \n", __FUNCTION__, nSize, hash.ToString());
        }

        return false;
    }

    mapOrphanTransactions[hash] = tx;

    for(const CTxIn& txin: tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);
    }

    if (fDebug)
    {
        LogPrint("mempool", "%s : ERROR - Stored orphan tx %s (mapsz %u) \n", __FUNCTION__, hash.ToString(), mapOrphanTransactions.size());
    }

    return true;
}


void static EraseOrphanTx(uint256 hash)
{
    map<uint256, CTransaction>::iterator it = mapOrphanTransactions.find(hash);

    if (it == mapOrphanTransactions.end())
    {
        return;
    }

    for(const CTxIn& txin: it->second.vin)
    {
        map<uint256, set<uint256> >::iterator itPrev = mapOrphanTransactionsByPrev.find(txin.prevout.hash);

        if (itPrev == mapOrphanTransactionsByPrev.end())
        {
            continue;
        }

        itPrev->second.erase(hash);

        if (itPrev->second.empty())
        {
            mapOrphanTransactionsByPrev.erase(itPrev);
        }
            
    }

    mapOrphanTransactions.erase(it);
}


unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;

    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();

        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);

        if (it == mapOrphanTransactions.end())
        {
            it = mapOrphanTransactions.begin();
        }

        EraseOrphanTx(it->first);

        ++nEvicted;
    }

    return nEvicted;
}


//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

bool CTransaction::ReadFromDisk(CTxDB& txdb, const uint256& hash, CTxIndex& txindexRet)
{
    SetNull();
    
    if (!txdb.ReadTxIndex(hash, txindexRet))
    {
        return false;
    }

    if (!ReadFromDisk(txindexRet.pos))
    {
        return false;
    }
        
    return true;
}


bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    if (!ReadFromDisk(txdb, prevout.hash, txindexRet))
    {
        return false;
    }
        
    if (prevout.n >= vout.size())
    {
        SetNull();

        return false;
    }

    return true;
}


bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout)
{
    CTxIndex txindex;

    return ReadFromDisk(txdb, prevout, txindex);
}


bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB txdb("r");

    CTxIndex txindex;

    return ReadFromDisk(txdb, prevout, txindex);
}


bool IsStandardTx(const CTransaction& tx, string& reason)
{
    if (tx.nVersion > CTransaction::CURRENT_VERSION
        || tx.nVersion < 1)
    {
        reason = "version";

        return false;
    }

    // Treat non-final transactions as non-standard to prevent a specific type
    // of double-spend attack, as well as DoS attacks. (if the transaction
    // can't be mined, the attacker isn't expending resources broadcasting it)
    // Basically we don't want to propagate transactions that can't be included in
    // the next block.
    //
    // However, IsFinalTx() is confusing... Without arguments, it uses
    // ChainBuddy.Height() to evaluate nLockTime; when a block is accepted, ChainBuddy.Height()
    // is set to the value of nHeight in the block. However, when IsFinalTx()
    // is called within CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a transaction can
    // be part of the *next* block, we need to call IsFinalTx() with one more
    // than ChainBuddy.Height().
    //
    // Timestamps on the other hand don't get any special treatment, because we
    // can't know what timestamp the next block will have, and there aren't
    // timestamp applications where it matters.
    if (!IsFinalTx(tx, nBestHeight + 1))
    {
        reason = "non-final";

        return false;
    }

    // nTime has different purpose from nLockTime but can be used in similar attacks
    if (tx.nTime > FutureDrift(GetAdjustedTime()))
    {
        reason = "time-too-new";

        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);

    if (sz >= MAX_STANDARD_TX_SIZE)
    {
        reason = "tx-size";

        return false;
    }

    for(const CTxIn& txin: tx.vin)
    {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
        if (txin.scriptSig.size() > 1650)
        {
            reason = "scriptsig-size";

            return false;
        }

        if (!txin.scriptSig.IsPushOnly())
        {
            reason = "scriptsig-not-pushonly";

            return false;
        }

        if (!txin.scriptSig.HasCanonicalPushes())
        {
            reason = "scriptsig-non-canonical-push";

            return false;
        }
    }

    unsigned int nDataOut = 0;

    txnouttype whichType;

    for(const CTxOut& txout: tx.vout)
    {
        if (!::IsStandard(txout.scriptPubKey, whichType))
        {
            reason = "scriptpubkey";

            return false;
        }

        if (whichType == TX_NULL_DATA)
        {
            nDataOut++;
        }
        else if (txout.nValue == 0)
        {
            reason = "dust";

            return false;
        }

        if (!txout.scriptPubKey.HasCanonicalPushes())
        {
            reason = "scriptpubkey-non-canonical-push";

            return false;
        }
    }

    // not more than one data txout per non-data txout is permitted
    // only one data txout is permitted too
    if (nDataOut > 1
        && nDataOut > tx.vout.size()/2)
    {
        reason = "multi-op-return";

        return false;
    }

    return true;
}


bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    AssertLockHeld(cs_main);

    // Time based nLockTime implemented in 0.1.6
    if (tx.nLockTime == 0)
    {
        return true;
    }

    if (nBlockHeight == 0)
    {
        nBlockHeight = nBestHeight;
    }
        
    if (nBlockTime == 0)
    {
        nBlockTime = GetAdjustedTime();
    }
        
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
    {
        return true;
    }
        
    for(const CTxIn& txin: tx.vin)
    {
        if (!txin.IsFinal())
        {
            return false;
        }
    }

    return true;
}


//
// Check transaction inputs to mitigate two
// potential denial-of-service attacks:
//
// 1. scriptSigs with extra data stuffed into them,
//    not consumed by scriptPubKey (or P2SH script)
// 2. P2SH scripts with a crazy number of expensive
//    CHECKSIG/CHECKMULTISIG operations
//
bool AreInputsStandard(const CTransaction& tx, const MapPrevTx& mapInputs)
{
    if (tx.IsCoinBase())
    {
        return true; // Coinbases don't use vin normally
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut& prev = tx.GetOutputFor(tx.vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;

        txnouttype whichType;

        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;

        if (!Solver(prevScript, whichType, vSolutions))
        {
            return false;
        }

        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);

        if (nArgsExpected < 0)
        {
            return false;
        }

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig
        // IsStandard() will have already returned false
        // and this method isn't called.
        vector<vector<unsigned char> > stack;

        if (!EvalScript(stack, tx.vin[i].scriptSig, tx, i, SCRIPT_VERIFY_NONE, 0))
        {
            return false;
        }

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
            {
                return false;
            }

            CScript subscript(stack.back().begin(), stack.back().end());

            vector<vector<unsigned char> > vSolutions2;

            txnouttype whichType2;

            if (Solver(subscript, whichType2, vSolutions2))
            {
                int tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);

                if (whichType2 == TX_SCRIPTHASH)
                {
                    return false;
                }

                if (tmpExpected < 0)
                {
                    return false;
                }

                nArgsExpected += tmpExpected;
            }
            else
            {
                // Any other Script with less than 15 sigops OK:
                unsigned int sigops = subscript.GetSigOpCount(true);

                // ... extra data left on the stack after execution is OK, too:
                return (sigops <= MAX_P2SH_SIGOPS);
            }
        }

        if (stack.size() != (unsigned int)nArgsExpected)
        {
            return false;
        }
            
    }

    return true;
}


unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;

    for(const CTxIn& txin: tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }

    for(const CTxOut& txout: tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }

    return nSigOps;
}


unsigned int GetP2SHSigOpCount(const CTransaction& tx, const MapPrevTx& inputs)
{
    if (tx.IsCoinBase())
    {
        return 0;
    }

    unsigned int nSigOps = 0;

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut& prevout = tx.GetOutputFor(tx.vin[i], inputs);

        if (prevout.scriptPubKey.IsPayToScriptHash())
        {
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
        }

    }

    return nSigOps;
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    AssertLockHeld(cs_main);

    CBlock blockTmp;

    if (pblock == NULL)
    {
        // Load the block this tx is in
        CTxIndex txindex;

        if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
        {
            return 0;
        }

        if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos))
        {
            return 0;
            pblock = &blockTmp;
        }
    }

    if (pblock)
    {
        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
        {
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
            {
                break;
            }
        }

        if (nIndex == (int)pblock->vtx.size())
        {
            vMerkleBranch.clear();

            nIndex = -1;

            if (fDebug)
            {
                LogPrint("core", "%s : ERROR: couldn't find tx in block \n", __FUNCTION__);
            }

            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);

    if (mi == mapBlockIndex.end())
    {
        return 0;
    }

    CBlockIndex* pindex = (*mi).second;

    if (!pindex
        || !pindex->IsInMainChain())
    {
        return 0;
    }

    return pindexBest->nHeight - pindex->nHeight + 1;
}


double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
    {
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    }

    for(const CTxIn& txin: vin)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)txin.scriptSig.size());

        if (nTxSize > offset)
        {
            nTxSize -= offset;
        }
    }

    if (nTxSize == 0)
    {
        return 0.0;
    }

    return dPriorityInputs / nTxSize;
}


bool CTransaction::CheckTransaction() const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
    {
        return DoS(10, error("%s : ERROR - Vin empty", __FUNCTION__));
    }

    if (vout.empty())
    {
        return DoS(10, error("%s : ERROR - vout empty", __FUNCTION__));
    }

    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
    {
        return DoS(100, error("%s : ERROR - size limits failed", __FUNCTION__));
    }

    // Check for negative or overflow output values
    int64_t nValueOut = 0;

    for (unsigned int i = 0; i < vout.size(); i++)
    {
        const CTxOut& txout = vout[i];

        if (txout.IsEmpty()
            && !IsCoinBase()
            && !IsCoinStake())
        {
            return DoS(100, error("%s : ERROR - Txout empty for user transaction", __FUNCTION__));
        }

        if (txout.nValue < 0)
        {
            return DoS(100, error("%s : ERROR - Txout.nValue negative", __FUNCTION__));
        }

        if (txout.nValue > MAX_MONEY)
        {
            return DoS(100, error("%s : ERROR - Txout.nValue too high", __FUNCTION__));
        }

        nValueOut += txout.nValue;

        if (!MoneyRange(nValueOut))
        {
            return DoS(100, error("%s : ERROR - Txout total out of range", __FUNCTION__));
        }
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;

    for(const CTxIn& txin: vin)
    {
        if (vInOutPoints.count(txin.prevout))
        {
            return false;
        }

        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2
            || vin[0].scriptSig.size() > 100)
        {
            return DoS(100, error("%s : ERROR - Coinbase script size is invalid", __FUNCTION__));
        }
    }
    else
    {
        for(const CTxIn& txin: vin)
        {
            if (txin.prevout.IsNull())
            {
                return DoS(10, error("%s : ERROR - Prevout is null", __FUNCTION__));
            }
        }
    }

    return true;
}


int64_t GetMinFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree, enum GetMinFee_mode mode)
{
    // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
    int64_t nBaseFee = (mode == GMF_RELAY) ? MIN_RELAY_TX_FEE : MIN_TX_FEE;
    int64_t nMinFee = (1 + (int64_t)nBytes / 1000) * nBaseFee;

    /*if (fAllowFree)
    {
        // There is a free transaction area in blocks created by most miners,
        // * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
        //   to be considered to fall into this category. We don't want to encourage sending
        //   multiple transactions instead of one big transaction to avoid fees.
        // * If we are creating a transaction we allow transactions up to 1,000 bytes
        //   to be considered safe and assume they can likely make it into this section.
        if (nBytes < (mode == GMF_SEND ? 1000 : (DEFAULT_BLOCK_PRIORITY_SIZE - 1000)))
            nMinFee = 0;
    }*/

    // Be safe when sending and require a fee if any output
    // is less than CENT:
    if (nMinFee < nBaseFee && mode == GMF_SEND)
    {
        for(const CTxOut& txout: tx.vout)
        {
            if (txout.nValue < CENT)
            {
                nMinFee = nBaseFee;
            }
        }
    }

    if (!MoneyRange(nMinFee))
    {
        nMinFee = MAX_MONEY;
    }

    return nMinFee;
}


bool AcceptToMemoryPool(CTxMemPool& pool, CTransaction &tx, bool fLimitFree, bool* pfMissingInputs, bool fRejectInsaneFee, bool ignoreFees, bool fFixSpentCoins)
{
    AssertLockHeld(cs_main);

    if (pfMissingInputs)
    {
        *pfMissingInputs = false;
    }

    if (!tx.CheckTransaction())
    {
        return error("%s : ERROR - CheckTransaction failed", __FUNCTION__);
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
    {
        return tx.DoS(100, error("%s : ERROR - Coinbase as individual tx", __FUNCTION__));
    }

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
    {
        return tx.DoS(100, error("%s : ERROR - Coinstake as individual tx", __FUNCTION__));
    }

    // Rather not work on nonstandard transactions (unless -testnet)
    string reason;

    if (!TestNet()
        && !IsStandardTx(tx, reason))
    {
        return error("%s : ERROR - Nonstandard transaction: %s", __FUNCTION__, reason);
    }

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();

    if (pool.exists(hash))
    {
        return false;
    }

    // ----------- instantX transaction scanning -----------

    for(const CTxIn& in: tx.vin)
    {
        if(mapLockedInputs.count(in.prevout))
        {
            if(mapLockedInputs[in.prevout] != tx.GetHash())
            {
                return tx.DoS(0, error("%s : ERROR - Conflicts with existing transaction lock: %s", __FUNCTION__, reason));
            }
        }
    }

    // Global Namespace Start
    {
        // Check for conflicts with in-memory transactions
        LOCK(pool.cs); // protect pool.mapNextTx
        
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            COutPoint outpoint = tx.vin[i].prevout;

            if (pool.mapNextTx.count(outpoint))
            {
                // Disable replacement feature for now
                return false;
            }
        }
    }
    // Global Namespace End

    // Global Namespace Start
    {
        CTxDB txdb("r");

        // do we already have it?
        if (txdb.ContainsTx(hash))
        {
            return false;
        }

        // do all inputs exist?
        // Note that this does not check for the presence of actual outputs (see the next check for that),
        // only helps filling in pfMissingInputs (to determine missing vs spent).
        for(const CTxIn txin: tx.vin)
        {
            if (!txdb.ContainsTx(txin.prevout.hash))
            {
                if (pfMissingInputs)
                {
                    *pfMissingInputs = true;
                }

                return false;
            }
        }

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;

        if (!tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
            {
                return error("%s : ERROR - FetchInputs found invalid tx %s", __FUNCTION__, hash.ToString());
            }

            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!TestNet()
            && !AreInputsStandard(tx, mapInputs))
        {
            return error("%s : ERROR - Nonstandard transaction input", __FUNCTION__);
        }

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        unsigned int nSigOps = GetLegacySigOpCount(tx);

        nSigOps += GetP2SHSigOpCount(tx, mapInputs);

        if (nSigOps > MAX_TX_SIGOPS)
        {
            return tx.DoS(0, error("%s : ERROR - Too many sigops %s, %d > %d", __FUNCTION__, hash.ToString(), nSigOps, MAX_TX_SIGOPS));
        }

        int64_t nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();

        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        // but prioritise dstx and don't check fees for it
        if(mapDarksendBroadcastTxes.count(hash))
        {
            // Normally we would PrioritiseTransaction But currently it is unimplemented
            // mempool.PrioritiseTransaction(hash, hash.ToString(), 1000, 0.1*COIN);
        }
        else if(!ignoreFees)
        {
            int64_t txMinFee = GetMinFee(tx, nSize, true, GMF_RELAY);

            if (fLimitFree && nFees < txMinFee)
            {
                return error("%s : ERROR - Not enough fees %s, %d < %d", __FUNCTION__, hash.ToString(), nFees, txMinFee);
            }

            // Continuously rate-limit free transactions
            // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
            // be annoying or make others' transactions take longer to confirm.
            if (fLimitFree && nFees < MIN_RELAY_TX_FEE)
            {
                static CCriticalSection csFreeLimiter;
                static double dFreeCount;
                static int64_t nLastTime;
                int64_t nNow = GetTime();

                LOCK(csFreeLimiter);

                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;

                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000)
                {
                    return error("%s : ERROR - Free transaction rejected by rate limiter", __FUNCTION__);
                }

                if (fDebug)
                {
                    LogPrint("mempool", "%s : WARNING - Rate limit dFreeCount: %g => %g \n", __FUNCTION__, dFreeCount, dFreeCount+nSize);
                }

                dFreeCount += nSize;
            }
        }

        if (fRejectInsaneFee
            && nFees > MIN_RELAY_TX_FEE * 10000)
        {
            return error("%s : ERROR - Insane fees %s, %d > %d", __FUNCTION__, hash.ToString(), nFees, MIN_RELAY_TX_FEE * 10000);
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!tx.ConnectInputs(txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, false, false, STANDARD_SCRIPT_VERIFY_FLAGS))
        {
            return error("%s : ERROR - ConnectInputs failed %s", __FUNCTION__, hash.ToString());
        }

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.
        if (!tx.ConnectInputs(txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, false, false, MANDATORY_SCRIPT_VERIFY_FLAGS))
        {
            return error("%s : BUG - PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s", __FUNCTION__, hash.ToString());
        }
    }
    // Global Namespace End

    // Store transaction in memory
    pool.addUnchecked(hash, tx);
    setValidatedTx.insert(hash);

    SyncWithWallets(tx, NULL, true, fFixSpentCoins);

    if (fDebug)
    {
        LogPrint("mempool", "%s : NOTICE - Accepted %s (poolsz %u) \n", __FUNCTION__, hash.ToString(), pool.mapTx.size());
    }

    return true;
}


bool AcceptableInputs(CTxMemPool& pool, const CTransaction &txo, bool fLimitFree, bool* pfMissingInputs, bool fRejectInsaneFee, bool isDSTX)
{
    AssertLockHeld(cs_main);

    if (pfMissingInputs)
    {
        *pfMissingInputs = false;
    }

    CTransaction tx(txo);
    string reason;

    if (!tx.CheckTransaction())
    {
        return error("%s : ERROR - CheckTransaction failed", __FUNCTION__);
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
    {
        return tx.DoS(100, error("%s : ERROR - Coinbase as individual tx", __FUNCTION__));
    }

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
    {
        return tx.DoS(100, error("%s : ERROR - Coinstake as individual tx", __FUNCTION__));
    }

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();

    if (pool.exists(hash))
    {
        return tx.DoS(100, error("%s : ERROR - Transaction already in mempool", __FUNCTION__));
    }

    // ----------- instantX transaction scanning -----------

    for(const CTxIn& in: tx.vin)
    {
        if(mapLockedInputs.count(in.prevout))
        {
            if(mapLockedInputs[in.prevout] != tx.GetHash())
            {
                return tx.DoS(0, error("%s : ERROR - Conflicts with existing transaction lock: %s", __FUNCTION__, reason));
            }
        }
    }

    // Global Namespace Start
    {
        // Check for conflicts with in-memory transactions
        LOCK(pool.cs); // protect pool.mapNextTx

        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            COutPoint outpoint = tx.vin[i].prevout;

            if (pool.mapNextTx.count(outpoint))
            {
                // Disable replacement feature for now
                return false;
            }
        }
    }
    // Global Namespace End

    // Global Namespace Start
    {
        CTxDB txdb("r");

        // do we already have it?
        if (txdb.ContainsTx(hash))
        {
            return false;
        }

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;

        if (!tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
            {
                return error("%s : ERROR - FetchInputs found invalid tx %s", __FUNCTION__, hash.ToString());
            }
        }

        // Check for non-standard pay-to-script-hash in inputs
        //if (!TestNet() && !AreInputsStandard(tx, mapInputs))
          //  return error("AcceptToMemoryPool : nonstandard transaction input");

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        unsigned int nSigOps = GetLegacySigOpCount(tx);
        nSigOps += GetP2SHSigOpCount(tx, mapInputs);

        if (nSigOps > MAX_TX_SIGOPS)
        {
            return tx.DoS(0, error("%s : ERROR - Too many sigops %s, %d > %d", __FUNCTION__, hash.ToString(), nSigOps, MAX_TX_SIGOPS));
        }

        int64_t nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
        int64_t txMinFee = GetMinFee(tx, nSize, true, GMF_RELAY);

        // Don't accept it if it can't get into a block
        if(isDSTX)
        {
            // Normally we would PrioritiseTransaction But currently it is unimplemented
            // mempool.PrioritiseTransaction(hash, hash.ToString(), 1000, 0.1*COIN);
        }
        else
        {
            // same as !ignoreFees for AcceptToMemoryPool
            if (fLimitFree
                && nFees < txMinFee)
            {
                return error("%s : ERROR - Not enough fees %s, %d < %d", __FUNCTION__, hash.ToString(), nFees, txMinFee);
            }

            // Continuously rate-limit free transactions
            // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
            // be annoying or make others' transactions take longer to confirm.
            if (fLimitFree && nFees < MIN_RELAY_TX_FEE)
            {
                static CCriticalSection csFreeLimiter;
                static double dFreeCount;
                static int64_t nLastTime;
                int64_t nNow = GetTime();

                LOCK(csFreeLimiter);

                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;

                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000)
                {
                    return error("%s : ERROR - Free transaction rejected by rate limiter", __FUNCTION__);
                }

                if (fDebug)
                {
                    LogPrint("mempool", "%s : NOTICE - Rate limit dFreeCount: %g => %g \n", __FUNCTION__, dFreeCount, dFreeCount+nSize);
                }

                dFreeCount += nSize;
            }
        }

        if (fRejectInsaneFee
            && nFees > txMinFee * 10000)
        {
            return error("%s : ERROR - Insane fees %s, %d > %d", __FUNCTION__, hash.ToString(), nFees, MIN_RELAY_TX_FEE * 10000);
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!tx.ConnectInputs(txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, true, false, STANDARD_SCRIPT_VERIFY_FLAGS, false))
        {
            return error("%s : ERROR - ConnectInputs to mempool failed %s", __FUNCTION__, hash.ToString());
        }
    }
    // Global Namespace end


    if (fDebug)
    {
        LogPrint("mempool", "%s : NOTICE - ACCEPTED to mempool %s (poolsz %u) \n", __FUNCTION__, hash.ToString(), pool.mapTx.size());
    }
    
    return true;
}


int CMerkleTx::GetDepthInMainChainINTERNAL(CBlockIndex* &pindexRet) const
{
    if (hashBlock.IsNull()
        || nIndex == -1)
    {
        return 0;
    }

    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);

    if (mi == mapBlockIndex.end())
    {
        return 0;
    }

    CBlockIndex* pindex = (*mi).second;

    if (!pindex
        || !pindex->IsInMainChain())
    {
        return 0;
    }


    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
        {
            return 0;
        }

        fMerkleVerified = true;
    }

    pindexRet = pindex;

    return pindexBest->nHeight - pindex->nHeight + 1;
}


int CMerkleTx::GetTransactionLockSignatures() const
{
    if(!IsSporkActive(SPORK_2_INSTANTX))
    {
        return -3;
    }

    if(!fEnableInstantX)
    {
        return -1;
    }

    //compile consessus vote
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(GetHash());

    if (i != mapTxLocks.end())
    {
        return (*i).second.CountSignatures();
    }

    return -1;
}


bool CMerkleTx::IsTransactionLockTimedOut() const
{
    if(!fEnableInstantX)
    {
        return -1;
    }

    //compile consessus vote
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(GetHash());

    if (i != mapTxLocks.end())
    {
        return GetTime() > (*i).second.nTimeout;
    }

    return false;
}


int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet, bool enableIX) const
{
    AssertLockHeld(cs_main);

    int nResult = GetDepthInMainChainINTERNAL(pindexRet);

    if (nResult == 0 && !mempool.exists(GetHash()))
    {
        return -1; // Not in chain, not in mempool
    }

    if(enableIX)
    {
        if (nResult < 10)
        {
            int signatures = GetTransactionLockSignatures();

            if(signatures >= INSTANTX_SIGNATURES_REQUIRED)
            {
                return nInstantXDepth+nResult;
            }
        }
    }

    return nResult;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase()
        || IsCoinStake()))
    {
        return 0;
    }

    return max(0, nCoinbaseMaturity - GetDepthInMainChain() + 1);
}


bool CMerkleTx::AcceptToMemoryPool(bool fLimitFree, bool fRejectInsaneFee, bool ignoreFees)
{
    return ::AcceptToMemoryPool(mempool, *this, fLimitFree, NULL, fRejectInsaneFee, ignoreFees);
}


bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb)
{   
    // Global Namespace Start
    {
        // Add previous supporting transactions first
        for(CMerkleTx& tx: vtxPrev)
        {
            if (!(tx.IsCoinBase()
                || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();

                if (!mempool.exists(hash)
                    && !txdb.ContainsTx(hash))
                {
                    tx.AcceptToMemoryPool(false);
                }
            }
        }

        return AcceptToMemoryPool(false);
    }
    // Global Namespace End

    return false;
}


bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");

    return AcceptWalletTransaction(txdb);
}


int GetInputAge(CTxIn& vin)
{
    const uint256& prevHash = vin.prevout.hash;
    CTransaction tx;
    uint256 hashBlock;
    bool fFound = GetTransaction(prevHash, tx, hashBlock);

    if(fFound)
    {
        if(mapBlockIndex.find(hashBlock) != mapBlockIndex.end())
        {
            return pindexBest->nHeight - mapBlockIndex[hashBlock]->nHeight;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }
}


int GetInputAgeIX(uint256 nTXHash, CTxIn& vin)
{
    int sigs = 0;
    int nResult = GetInputAge(vin);

    if(nResult < 0)
    {
        nResult = 0;
    }

    if (nResult < 6)
    {
        std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(nTXHash);

        if (i != mapTxLocks.end())
        {
            sigs = (*i).second.CountSignatures();
        }

        if(sigs >= INSTANTX_SIGNATURES_REQUIRED)
        {
            return nInstantXDepth+nResult;
        }
    }

    return -1;
}


int GetIXConfirmations(uint256 nTXHash)
{
    int sigs = 0;
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(nTXHash);

    if (i != mapTxLocks.end())
    {
        sigs = (*i).second.CountSignatures();
    }

    if(sigs >= INSTANTX_SIGNATURES_REQUIRED)
    {
        return nInstantXDepth;
    }

    return 0;
}


int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;

    if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, false))
    {
        return 0;
    }

    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());

    if (mi == mapBlockIndex.end())
    {
        return 0;
    }

    CBlockIndex* pindex = (*mi).second;

    if (!pindex
        || !pindex->IsInMainChain())
    {
        return 0;
    }

    return 1 + nBestHeight - pindex->nHeight;
}


// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    // Global Namespace Start
    {
        LOCK(cs_main);
        {
            if (mempool.lookup(hash, tx))
            {
                return true;
            }
        }

        CTxDB txdb("r");
        CTxIndex txindex;

        if (tx.ReadFromDisk(txdb, hash, txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            {
                hashBlock = block.GetHash();
            }

            return true;
        }

        // look for transaction in disconnected blocks to find orphaned CoinBase and CoinStake transactions
        for(PAIRTYPE(const uint256, CBlockIndex*)& item: mapBlockIndex)
        {
            CBlockIndex* pindex = item.second;

            if (pindex == pindexBest
                || pindex->pnext != 0)
            {
                continue;
            }

            CBlock block;

            if (!block.ReadFromDisk(pindex))
            {
                continue;
            }

            for(const CTransaction& txOrphan: block.vtx)
            {
                if (txOrphan.GetHash() == hash)
                {
                    tx = txOrphan;

                    return true;
                }
            }
        }
    }
    // Global Namespace End

    return false;
}

//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;

CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;

    if (nHeight < nBestHeight / 2)
    {
        pblockindex = pindexGenesisBlock;
    }
    else
    {
        pblockindex = pindexBest;
    }

    if (pblockindexFBBHLast
        && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
    {
        pblockindex = pblockindexFBBHLast;
    }

    while (pblockindex->nHeight > nHeight)
    {
        pblockindex = pblockindex->pprev;
    }

    while (pblockindex->nHeight < nHeight)
    {
        pblockindex = pblockindex->pnext;
    }
        
    pblockindexFBBHLast = pblockindex;

    return pblockindex;
}


bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();

        return true;
    }

    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions))
    {
        return false;
    }

    if (GetHash() != pindex->GetBlockHash())
    {
        return error("%s : ERROR - GetHash() doesn't match index", __FUNCTION__);
    }

    return true;
}


uint256 static GetOrphanRoot(const uint256& hash)
{
    map<uint256, COrphanBlock*>::iterator it = mapOrphanBlocks.find(hash);

    if (it == mapOrphanBlocks.end())
    {
        return hash;
    }

    // Work back to the first block in the orphan chain
    do
    {
        map<uint256, COrphanBlock*>::iterator it2 = mapOrphanBlocks.find(it->second->hashPrev);

        if (it2 == mapOrphanBlocks.end())
        {
            return it->first;
        }

        it = it2;
    }
    while(true);
}


// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const COrphanBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrev))
    {
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrev];
    }

    return pblockOrphan->hashPrev;
}


static CBigNum GetProofOfStakeLimit(int nHeight)
{
    return bnProofOfStakeLimit;
}


string getDevRewardAddress(int nHeight)
{
    return Params().DevRewardAddress();
}


double GetDynamicBlockReward3(int nHeight)
{
    /* 
    Dynamic Block Reward 3.0 - (C) 2017 Crypostle & Profit Hunters Coin
        https://github.com/JustinPercy/crypostle
        https://github.com/ProfitHuntersCoin/phc
    */

    double nDifficulty = GetDifficulty();
    double nNetworkHashPS = GetPoWMHashPS();
    int nSubsidyMin = 1;
    int nSubsidyMax = 1;
    double nSubsidyBase = nSubsidyMin;
    int nSubsidyMod = 0;
    int TightForkHeight = 0;

    TightForkHeight = Params().PIP1_Height();;

    /* ------ Pre-Mining Phase: Block #0 (Start) ------ */
    if (nHeight == 0)
    {
        nSubsidyMax = 1;
    }
    /* ------ Initial Mining Phase: Blocks Bigger than 0 ------ */
    if (nHeight > 0)
    {
        nSubsidyMax = 100;
    }
    /* ------ Initial Mining Phase: Blocks Bigger than 50000 ------ */
    if (nHeight > 50000)
    {
        nSubsidyMax = 50;
    }
    /* ------ Tight-Fork Mining Phase: Blocks Bigger than 120000 ------ */
    if (nHeight > TightForkHeight)
    {
        nSubsidyMax = 25;
    }
    /* ------ Regular Mining Phase: Blocks Bigger than 200000 ------ */
    if (nHeight > 150000)
    {
        nSubsidyMax = 12;
    }
    /* ------ Regular Mining Phase: Blocks Bigger than 200000 ------ */
    if (nHeight > 200000)
    {
        nSubsidyMax = 6;
    }
    /* ------ Regular Mining Phase: Blocks Bigger than 250000 ------ */
    if (nHeight > 250000)
    {
        nSubsidyMax = 3;
    }

    nSubsidyMod = nNetworkHashPS / nDifficulty;
    nSubsidyBase = nSubsidyMax - nSubsidyMod;

    /* Default Range Control for initial mining phases (Mitigates mining-centralization with 100% reward loss) */
    /* ------ Max (Loose) ------ */
    if (nSubsidyMod > nSubsidyMax)
    {
        nSubsidyBase = nSubsidyMax;
    }
    /* ------ Min (Loose) ------ */
    if (nSubsidyMod < nSubsidyMin)
    {
        nSubsidyBase = nSubsidyMin;
    }

    //* Activate strict Range controls after fork height (Mitigates mining-centralization without 100% reward loss) */
    if (nHeight > TightForkHeight)
    {
        /* ------ Max (Tight) ------ */
        if (nSubsidyBase > nSubsidyMax)
        {
            nSubsidyBase = nSubsidyMax;
        }
        /* ------ Min  (Tight) ------ */
        if (nSubsidyBase < nSubsidyMin)
        {
            nSubsidyBase = nSubsidyMin;
        }
    }

    return nSubsidyBase;
}


// miner's coin base reward
int64_t GetProofOfWorkReward(int nHeight, int64_t nFees)
{
    /*
    Dynamic Block Reward - (C) 2017 Crypostle
    
    Reward adjustments based on network hasrate, previous block difficulty
    Simulating real bullion mining: If the difficulty rate is low; using excessive
    work to produce low value blocks does not yield large return rates. When the
    ratio of difficulty adjusts and the network hashrate remains constant or declines:
    The reward per block will reach the maximum level, thus mining becomes very profitable.
    This algorithm is intended to discourage >51% attacks, or malicous miners.
    It will also act as an automatic inflation adjustment based on network conditions.
    */

    double nSubsidyBase;

    if (nHeight > 0)
    {
        // Version 3.0 after Block 0
        nSubsidyBase = GetDynamicBlockReward3(nHeight);
    }
    else
    {
        // Genesis (Unspendable)
        nSubsidyBase = 1;
    }

    int64_t nSubsidy = nSubsidyBase * COIN;

    if (fDebug)
    {
        LogPrint("mining", "%s : NOTICE - Create=%s nSubsidyBase=%d Hashrate=%d Diff=%d \n", __FUNCTION__, FormatMoney(nSubsidy), nSubsidyBase, GetPoWMHashPS(), GetDifficulty());
    }

    return nSubsidy + nFees;

}


// miner's coin stake reward
int64_t GetProofOfStakeReward(const CBlockIndex* pindexPrev, int64_t nCoinAge, int64_t nFees)
{
    int64_t nSubsidy = nCoinAge * COIN_YEAR_REWARD * 33 / (365 * 33 + 8);
    int64_t nSubsidyBase = nCoinAge * COIN_YEAR_REWARD / (365 + 8 / 33);

    /* ------ Pre-Mining Phase: Block #0 (Start) ------ */
    if (pindexPrev->nHeight == 0)
    {
        // 0000%
        nSubsidy = 0;
    }
    /* ------ Initial Mining Phase: Block #1 Up to 500000 ------ */
    else
    {
        // 1000%
        nSubsidy = nSubsidy * 1;
    }
    /* ------ Initial Mining Phase: Block #50001 Up to 100000 ------ */
    if (pindexPrev->nHeight > 50000)
    {
        // 500%
        nSubsidy = nSubsidy * 0.5;
    }
    /* ------ Initial Mining Phase: Block #100001 Up to 150000 ------ */
    if (pindexPrev->nHeight > 120000)
    {
        // 250%
        nSubsidy = nSubsidy * 0.25;
    }
    /* ------ Regular Mining Phase: Block #150001 Up to 200000 ------ */
    if (pindexPrev->nHeight > 150000)
    {
        // 125%
        nSubsidy = nSubsidy * 0.125;
    }
    /* ------ Regular Mining Phase: Block #200001+ ------ */
    if (pindexPrev->nHeight > 200000)
    {
        // 250%
        nSubsidy = nSubsidyBase * 0.25;
    }

    if (fDebug)
    {
        LogPrint("mining", "%s : NOTICE - Create=%s nCoinAge=%d \n", __FUNCTION__, FormatMoney(nSubsidy), nCoinAge);
    }

    return nSubsidy + nFees;

}


// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
    {
        pindex = pindex->pprev;
    }

    return pindex;
}

//
// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime)
{
    const CBigNum &bnLimit = Params().ProofOfWorkLimit();

    // Testnet has min-difficulty blocks
    // after nTargetSpacing*2 time between blocks:
    if (TestNet()
        && nTime > nTargetSpacing*2)
    {
        return bnLimit.GetCompact();
    } 

    CBigNum bnResult;

    bnResult.SetCompact(nBase);

    while (nTime > 0 && bnResult < bnLimit)
    {
        // Maximum 400% adjustment...
        bnResult *= 4;
        // ... in best-case exactly 4-times-normal target time
        nTime -= nTargetTimespan*4;
    }

    if (bnResult > bnLimit)
    {
        bnResult = bnLimit;
    }

    return bnResult.GetCompact();
}


unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    // PIP2 - TargetTimespan correction after development testing
    if (nBestHeight >= Params().PIP2_Height())
    {
        nTargetTimespan = 60; // 1 Minute
    }

    CBigNum bnTargetLimit = fProofOfStake ? GetProofOfStakeLimit(pindexLast->nHeight) : Params().ProofOfWorkLimit();

    if (pindexLast == NULL)
    {
        return bnTargetLimit.GetCompact(); // genesis block
    }

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);

    if (pindexPrev->pprev == NULL)
    {
        return bnTargetLimit.GetCompact(); // first block
    }

    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);

    if (pindexPrevPrev->pprev == NULL)
    {
        return bnTargetLimit.GetCompact(); // second block
    }

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    if (nActualSpacing < 0)
    {
        nActualSpacing = TARGET_SPACING;
    }

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nInterval = nTargetTimespan / TARGET_SPACING;
    bnNew *= ((nInterval - 1) * TARGET_SPACING + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * TARGET_SPACING);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
    {
        bnNew = bnTargetLimit;
    }

    return bnNew.GetCompact();

}


bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0
        || bnTarget > Params().ProofOfWorkLimit())
    {
        return error("%s : ERROR - nBits below minimum work", __FUNCTION__);
    }

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
    {
        return error("%s : ERROR - Hash doesn't match nBits", __FUNCTION__);
    }

    return true;

}


bool IsInitialBlockDownload()
{
    LOCK(cs_main);

    if (pindexBest == NULL
        || nBestHeight < Checkpoints::GetTotalBlocksEstimate())
    {
        return true;
    }

    static int64_t nLastUpdate;
    static CBlockIndex* pindexLastBest;

    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;

        nLastUpdate = GetTime();
    }

    return (GetTime() - nLastUpdate < 15
            && pindexBest->GetBlockTime() < GetTime() - 5 * 60);
}


void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->nChainTrust > nBestInvalidTrust)
    {
        nBestInvalidTrust = pindexNew->nChainTrust;

        CTxDB().WriteBestInvalidTrust(CBigNum(nBestInvalidTrust));
    }

    uint256 nBestInvalidBlockTrust = pindexNew->nChainTrust - pindexNew->pprev->nChainTrust;
    uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    if (fDebug)
    {
        LogPrint("core", "%s : ERROR - Invalid block=%s  height=%d  trust=%s  blocktrust=%d  date=%s \n", __FUNCTION__,
            pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, CBigNum(pindexNew->nChainTrust).ToString(), nBestInvalidBlockTrust.Get64(), DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()));

        LogPrint("core", "%s : ERROR - Current best=%s  height=%d  trust=%s  blocktrust=%d  date=%s \n", __FUNCTION__,
            hashBestChain.ToString(), nBestHeight, CBigNum(pindexBest->nChainTrust).ToString(), nBestBlockTrust.Get64(), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()));
    }

    if (!fReindex
        || !fImporting
        || !IsInitialBlockDownload()
        || Consensus::ChainShield::ChainShieldCache < pindexBest->nHeight)
    {
        if (Consensus::ChainShield::Enabled == true
            && Consensus::ChainBuddy::Enabled == true)
        {
            // Double check to make sure local blockchain remains in sync with new blocks from nodes & new blocks mines or staked
            Consensus::ChainBuddy::WalletHasConsensus();

            Consensus::ChainShield::Protect();
        }
    }
}


void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}


void UpdateTime(CBlock& block, const CBlockIndex* pindexPrev)
{
    block.nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    block.nBits = GetNextTargetRequired(pindexPrev, false);
}


bool IsConfirmedInNPrevBlocks(const CTxIndex& txindex, const CBlockIndex* pindexFrom, int nMaxDepth, int& nActualDepth)
{
    for (const CBlockIndex* pindex = pindexFrom; pindex && pindexFrom->nHeight - pindex->nHeight < nMaxDepth; pindex = pindex->pprev)
    {
        if (pindex->nBlockPos == txindex.pos.nBlockPos
            && pindex->nFile == txindex.pos.nFile)
        {
            nActualDepth = pindexFrom->nHeight - pindex->nHeight;
            
            return true;
        }
    }

    return false;
}


bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        for(const CTxIn& txin: vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;

            if (!txdb.ReadTxIndex(prevout.hash, txindex))
            {
                return error("%s : ERROR - ReadTxIndex failed", __FUNCTION__);
            }

            if (prevout.n >= txindex.vSpent.size())
            {
                return error("%s : ERROR - prevout.n out of range", __FUNCTION__);
            }

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.hash, txindex))
            {
                return error("%s : ERROR - UpdateTxIndex failed", __FUNCTION__);
            }

        }
    }

    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely
    // spent, so erasing it would be a no-op anyway.
    txdb.EraseTxIndex(*this);

    return true;
}


bool CTransaction::FetchInputs(CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool, bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
    // FetchInputs can return false either because we just haven't seen some inputs
    // (in which case the transaction should be stored as an orphan)
    // or because the transaction is malformed (in which case the transaction should
    // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
    fInvalid = false;

    if (IsCoinBase())
    {
        return true; // Coinbase transactions have no inputs to fetch.
    }

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        COutPoint prevout = vin[i].prevout;

        if (inputsRet.count(prevout.hash))
        {
            continue; // Got it already
        }

        // Read txindex
        CTxIndex& txindex = inputsRet[prevout.hash].first;
        bool fFound = true;

        if ((fBlock || fMiner)
            && mapTestPool.count(prevout.hash))
        {
            // Get txindex from current proposed changes
            txindex = mapTestPool.find(prevout.hash)->second;
        }
        else
        {
            // Read txindex from txdb
            fFound = txdb.ReadTxIndex(prevout.hash, txindex);
        }

        if (!fFound
            && (fBlock || fMiner))
        {
            return fMiner ? false : error("%s : ERROR - %s prev tx %s index entry not found", __FUNCTION__, GetHash().ToString(),  prevout.hash.ToString());
        }

        // Read txPrev
        CTransaction& txPrev = inputsRet[prevout.hash].second;

        if (pindexBest->nHeight > 0)
        {
            if (!fFound
                || txindex.pos == CDiskTxPos(1,1,1))
            {
                // Get prev tx from single transactions in memory
                if (!mempool.lookup(prevout.hash, txPrev))
                {
                    return error("%s : ERROR - Mempool Tx %s prev not found %s", __FUNCTION__, GetHash().ToString(),  prevout.hash.ToString());
                }

                if (!fFound)
                {
                    txindex.vSpent.resize(txPrev.vout.size());
                }
            }
            else
            {
                // Get prev tx from disk
                if (!txPrev.ReadFromDisk(txindex.pos))
                {
                    return error("%s : ERROR - ReadFromDisk hash: %s prev tx %s failed", __FUNCTION__, GetHash().ToString(),  prevout.hash.ToString());
                }
            }
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const COutPoint prevout = vin[i].prevout;

        if (inputsRet.count(prevout.hash) == 0)
        {
            return error("%s : ERROR - InputsRet.count(prevout.hash) == 0", __FUNCTION__);
        }

        const CTxIndex& txindex = inputsRet[prevout.hash].first;
        const CTransaction& txPrev = inputsRet[prevout.hash].second;

        if (prevout.n >= txPrev.vout.size()
            || prevout.n >= txindex.vSpent.size())
        {
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            fInvalid = true;

            return DoS(100, error("%s : ERROR - Prevout.n %s out of range %d %u %u prev tx %s data: %s", __FUNCTION__, GetHash().ToString(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString(), txPrev.ToString()));
        }
    }

    return true;
}


const CTxOut& CTransaction::GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.hash);

    if (mi == inputs.end())
    {
        throw std::runtime_error(strprintf("%s : ERROR - Prevout.hash not found: %s", __FUNCTION__, input.prevout.hash.ToString()));
    }

    const CTransaction& txPrev = (mi->second).second;

    if (input.prevout.n >= txPrev.vout.size())
    {
        throw std::runtime_error(strprintf("%s : ERROR - Prevout.n out of range: %d", __FUNCTION__, input.prevout.n));
    }

    return txPrev.vout[input.prevout.n];
}


int64_t CTransaction::GetValueIn(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
    {
        return 0;
    }

    int64_t nResult = 0;

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        nResult += GetOutputFor(vin[i], inputs).nValue;
    }

    return nResult;
}


bool CTransaction::ConnectInputs(CTxDB& txdb, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, unsigned int flags, bool fValidateSig)
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction::AcceptToMemoryPool
    if (!IsCoinBase())
    {
        int64_t nValueIn = 0;
        int64_t nFees = 0;

        for (unsigned int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;

            if (inputs.count(prevout.hash) == 0) 
            {
                return DoS(100, error("%s : ERROR - Inputs.count(prevout.hash) = 0", __FUNCTION__));
            }

            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            if (prevout.n >= txPrev.vout.size()
                || prevout.n >= txindex.vSpent.size())
            {
                return DoS(100, error("%s : ERROR - Prevout.n out of range for hash: %s with %d %u %u prev tx %s \n%s", __FUNCTION__, GetHash().ToString(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString(), txPrev.ToString()));
            }

            // If prev is coinbase or coinstake, check that it's matured
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake())
            {
                int nSpendDepth;

                if (IsConfirmedInNPrevBlocks(txindex, pindexBlock, nCoinbaseMaturity, nSpendDepth))
                {
                    return error("%s : ERROR - Tried to spend %s at depth %d", __FUNCTION__, txPrev.IsCoinBase() ? "coinbase" : "coinstake", nSpendDepth);
                }
            }

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime)
            {
                return DoS(100, error("%s : ERROR - Transaction timestamp earlier than input transaction", __FUNCTION__));
            }

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;

            if (!MoneyRange(txPrev.vout[prevout.n].nValue)
                || !MoneyRange(nValueIn))
            {
                return DoS(100, error("%s : ERROR - Txin values out of range", __FUNCTION__));
            }
        }

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;

            if (inputs.count(prevout.hash) == 0)
            {
                return DoS(100, error("%s : ERROR - Inputs.count(prevout.hash) == 0", __FUNCTION__));
            }

            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            if (!txindex.vSpent[prevout.n].IsNull())
            {
                return fMiner ? false : error("%s : ERROR - Prev tx for %s already used for block: %s", __FUNCTION__, GetHash().ToString(), txindex.vSpent[prevout.n].ToString());
            }

            if(fValidateSig)
            {
                // Skip ECDSA signature verification when connecting blocks (fBlock=true)
                // before the last blockchain checkpoint. This is safe because block merkle hashes are
                // still computed and checked, and any change will be caught at the next checkpoint.
                if (!(fBlock
                    && !IsInitialBlockDownload()))
                {
                    // Verify signature
                    if (!VerifySignature(txPrev, *this, i, flags, 0))
                    {
                        if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS)
                        {
                            // Check whether the failure was caused by a
                            // non-mandatory script verification check, such as
                            // non-null dummy arguments;
                            // if so, don't trigger DoS protection to
                            // avoid splitting the network between upgraded and
                            // non-upgraded nodes.
                            if (VerifySignature(txPrev, *this, i, flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, 0))
                            {
                                return error("%s : ERROR - Non-mandatory VerifySignature failed for block: %s", __FUNCTION__, GetHash().ToString());
                            }
                        }

                        // Failures of other flags indicate a transaction that is
                        // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                        // such nodes as they are not following the protocol. That
                        // said during an upgrade careful thought should be taken
                        // as to the correct behavior - we may want to continue
                        // peering with non-upgraded nodes even after a soft-fork
                        // super-majority vote has passed.
                        return DoS(100,error("%s : ERROR - VerifySignature failed for block: %s", __FUNCTION__, GetHash().ToString()));
                    }
                }
            }

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock
                || fMiner)
            {
                mapTestPool[prevout.hash] = txindex;
            }
        }

        if (!IsCoinStake())
        {
            if (nValueIn < GetValueOut())
            {
                return DoS(100, error("%s : ERROR - Value in < value out for block: %s", __FUNCTION__, GetHash().ToString()));
            }

            // Tally transaction fees
            int64_t nTxFee = nValueIn - GetValueOut();

            if (nTxFee < 0)
            {
                return DoS(100, error("%s : ERROR - nTxFee < 0 for block: %s", __FUNCTION__, GetHash().ToString()));
            }

            nFees += nTxFee;

            if (!MoneyRange(nFees))
            {
                return DoS(100, error("%s : ERROR - nFees out of range for block: %s", __FUNCTION__, GetHash().ToString()));
            }
        }
    }

    return true;
}

bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
    {
        if (!vtx[i].DisconnectInputs(txdb))
        {
            return false;
        }
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);

        blockindexPrev.hashNext = 0;

        if (!txdb.WriteBlockIndex(blockindexPrev))
        {
            return error("%s : ERROR - WriteBlockIndex failed", __FUNCTION__);
        }
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    for(CTransaction& tx: vtx)
    {
        SyncWithWallets(tx, this, false);
    }

    return true;
}


bool static BuildAddrIndex(const CScript &script, std::vector<uint160>& addrIds)
{
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    std::vector<unsigned char> data;
    opcodetype opcode;

    bool fHaveData = false;

    while (pc < pend)
    {
        script.GetOp(pc, opcode, data);

        if (0 <= opcode
            && opcode <= OP_PUSHDATA4
            && data.size() >= 8)
        {
            // data element
            uint160 addrid = 0;

            if (data.size() <= 20)
            {
                memcpy(&addrid, &data[0], data.size());
            }
            else
            {
                addrid = Hash160(data);
            }

            addrIds.push_back(addrid);

            fHaveData = true;
        }
    }
    if (!fHaveData)
    {
        uint160 addrid = Hash160(script);

        addrIds.push_back(addrid);
        
        return true;
    }
    else
    {
        if(addrIds.size() > 0)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}


bool FindTransactionsByDestination(const CTxDestination &dest, std::vector<uint256> &vtxhash)
{
    uint160 addrid = 0;
    const CKeyID *pkeyid = boost::get<CKeyID>(&dest);

    if (pkeyid)
    {
        addrid = static_cast<uint160>(*pkeyid);
    }

    if (!addrid)
    {
        const CScriptID *pscriptid = boost::get<CScriptID>(&dest);

        if (pscriptid)
        {
            addrid = static_cast<uint160>(*pscriptid);
        }
    }

    if (!addrid)
    {
        if (fDebug)
        {
            LogPrint("core", "%s : ERROR - Couldn't parse dest into addrid \n", __FUNCTION__);
        }

        return false;
    }

    LOCK(cs_main);

    CTxDB txdb("r");

    if(!txdb.ReadAddrIndex(addrid, vtxhash))
    {
        if (fDebug)
        {
            LogPrint("core", "%s : ERROR - txdb.ReadAddrIndex failed \n", __FUNCTION__);
        }

        return false;
    }

    return true;
}


void CBlock::RebuildAddressIndex(CTxDB& txdb)
{
    for(CTransaction& tx: vtx)
    {
        uint256 hashTx = tx.GetHash();

        // inputs
        if(!tx.IsCoinBase())
        {
            MapPrevTx mapInputs;
            map<uint256, CTxIndex> mapQueuedChangesT;

            bool fInvalid;

            if (!tx.FetchInputs(txdb, mapQueuedChangesT, true, false, mapInputs, fInvalid))
            {
                return;
            }

            MapPrevTx::const_iterator mi;

            for(MapPrevTx::const_iterator mi = mapInputs.begin(); mi != mapInputs.end(); ++mi)
            {
                for(const CTxOut &atxout: (*mi).second.second.vout)
                {
                    std::vector<uint160> addrIds;

                    if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
                    {
                        for(uint160 addrId: addrIds)
                        {
                            if(!txdb.WriteAddrIndex(addrId, hashTx))
                            {
                                if (fDebug)
                                {
                                    LogPrint("core", "%s : ERROR - Txins WriteAddrIndex failed addrId: %s txhash: %s \n", __FUNCTION__, addrId.ToString().c_str(), hashTx.ToString().c_str());
                                }
                            }   
                        }
                    }
                }
            }
        }

        // outputs
        for(const CTxOut &atxout: tx.vout)
        {
            std::vector<uint160> addrIds;

            if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
            {
                for(uint160 addrId: addrIds)
                {
                    if(!txdb.WriteAddrIndex(addrId, hashTx))
                    {
                        if (fDebug)
                        {
                            LogPrint("core", "%s : ERROR - Txouts WriteAddrIndex failed addrId: %s txhash: %s \n", __FUNCTION__, addrId.ToString().c_str(), hashTx.ToString().c_str());
                        }
                    }
                }
            }
        }
    }
}


bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck)
{
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock(!fJustCheck, !fJustCheck, false))
    {
        return false;
    }

    unsigned int flags = SCRIPT_VERIFY_NOCACHE;

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck)
    {
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    }
    else
    {
        nTxPos = pindex->nBlockPos
                + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0))
                + GetSizeOfCompactSize(vtx.size());
    }

    map<uint256, CTxIndex> mapQueuedChanges;
    int64_t nFees = 0;
    int64_t nValueIn = 0;
    int64_t nValueOut = 0;
    int64_t nStakeReward = 0;

    unsigned int nSigOps = 0;
    int nInputs = 0;

    for(CTransaction& tx: vtx)
    {
        uint256 hashTx = tx.GetHash();
        nInputs += tx.vin.size();
        nSigOps += GetLegacySigOpCount(tx);

        if (nSigOps > MAX_BLOCK_SIGOPS)
        {
            return DoS(100, error("%s : ERROR - Too many sigops", __FUNCTION__));
        }

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);

        if (!fJustCheck)
        {
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
        }

        MapPrevTx mapInputs;

        if (tx.IsCoinBase())
        {
            nValueOut += tx.GetValueOut();
        }
        else
        {
            bool fInvalid;

            if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
            {
                return false;
            }

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += GetP2SHSigOpCount(tx, mapInputs);

            if (nSigOps > MAX_BLOCK_SIGOPS)
            {
                return DoS(100, error("%s : ERROR - Too many sigops", __FUNCTION__));
            }

            int64_t nTxValueIn = tx.GetValueIn(mapInputs);
            int64_t nTxValueOut = tx.GetValueOut();

            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            
            if (!tx.IsCoinStake())
            {
                nFees += nTxValueIn - nTxValueOut;
            }

            if (tx.IsCoinStake())
            {
                nStakeReward = nTxValueOut - nTxValueIn;
            }

            if (!tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, flags))
            {
                return false;
            }

        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }

    if (IsProofOfWork())
    {
        int64_t nReward = GetProofOfWorkReward(pindex->nHeight, nFees);

        // Check coinbase reward
        if (vtx[0].GetValueOut() > nReward)
        {
            return DoS(50, error("%s : ERROR - Coinbase reward exceeded (actual=%d vs calculated=%d)", __FUNCTION__, vtx[0].GetValueOut(), nReward));
        }

#ifndef LOWMEM
        //  PHC money supply info (last PoW reward)
        pindex->nPOWMint = nReward;
#endif 
    }

    if (IsProofOfStake())
    {
        // ppcoin: coin stake tx earns reward instead of paying fee
        uint64_t nCoinAge;

        if (!vtx[1].GetCoinAge(txdb, pindex->pprev, nCoinAge))
        {
            return error("%s : ERROR - Unable to get coin age for coinstake: %s", __FUNCTION__, vtx[1].GetHash().ToString());
        }

        int64_t nCalculatedStakeReward = GetProofOfStakeReward(pindex->pprev, nCoinAge, nFees);

#ifndef LOWMEM
        // PHC: track mint amount info (PoW)
        pindex->nPOSMint = nCalculatedStakeReward;
#endif 

        if (nStakeReward > nCalculatedStakeReward)
        {
            return DoS(100, error("%s : ERROR - Coinstake pays too much(actual=%d vs calculated=%d)", __FUNCTION__, nStakeReward, nCalculatedStakeReward));
        }
    }
/*
    // PHC: track mint amount info (PoW)
#ifndef LOWMEM
    pindex->nPOWMint = nValueOut - nValueIn + nFees;
#endif
*/
    // PHC: track money supply
#ifndef LOWMEM
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + pindex->nPOSMint + pindex->nPOWMint;
#endif

    if (!txdb.WriteBlockIndex(CDiskBlockIndex(pindex)))
    {
        return error("%s : ERROR - WriteBlockIndex for pindex failed", __FUNCTION__);
    }

    if (fJustCheck)
    {
        return true;
    }

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
        {
            return error("%s : ERROR - UpdateTxIndex failed", __FUNCTION__);
        }
    }

    if(GetBoolArg("-addrindex", false))
    {
        // Write Address Index
        for(CTransaction& tx: vtx)
        {
            uint256 hashTx = tx.GetHash();

            // inputs
            if(!tx.IsCoinBase())
            {
                MapPrevTx mapInputs;
                map<uint256, CTxIndex> mapQueuedChangesT;

                bool fInvalid;

                if (!tx.FetchInputs(txdb, mapQueuedChangesT, true, false, mapInputs, fInvalid))
                {
                    return false;
                }

                MapPrevTx::const_iterator mi;

                for(MapPrevTx::const_iterator mi = mapInputs.begin(); mi != mapInputs.end(); ++mi)
                {
                    for(const CTxOut &atxout: (*mi).second.second.vout)
                    {
                        std::vector<uint160> addrIds;

                        if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
                        {
                            for(uint160 addrId: addrIds)
                            {
                                if(!txdb.WriteAddrIndex(addrId, hashTx))
                                {
                                    if (fDebug)
                                    {
                                        LogPrint("core", "%s : ERROR - Txins WriteAddrIndex failed addrId: %s txhash: %s \n", __FUNCTION__, addrId.ToString().c_str(), hashTx.ToString().c_str());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // outputs
            for(const CTxOut &atxout: tx.vout)
            {
                std::vector<uint160> addrIds;

                if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
                {
                    for(uint160 addrId: addrIds)
                    {
                        if(!txdb.WriteAddrIndex(addrId, hashTx))
                        {
                            if (fDebug)
                            {
                                LogPrint("core", "%s : ERROR - Txouts WriteAddrIndex failed addrId: %s txhash: %s \n", __FUNCTION__, addrId.ToString().c_str(), hashTx.ToString().c_str());
                            }
                        }
                    }
                }
            }
        }
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);

        blockindexPrev.hashNext = pindex->GetBlockHash();

        if (!txdb.WriteBlockIndex(blockindexPrev))
        {
            return error("%s : ERROR - WriteBlockIndex failed", __FUNCTION__);
        }
    }

    // Watch for transactions paying to me
    for(CTransaction& tx: vtx)
    {
        SyncWithWallets(tx, this);
    }



    return true;
}


// Called from inside SetBestChain: attaches a block to the new best chain being built
bool CBlock::SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew)
{
    uint256 hash = GetHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew)
        || !txdb.WriteHashBestChain(hash))
    {
        txdb.TxnAbort();

        InvalidChainFound(pindexNew);

        return false;
    }

    if (!txdb.TxnCommit())
    {
        return error("%s : ERROR - TxnCommit failed", __FUNCTION__);
    }

    // Add to current best branch
    pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    for(CTransaction& tx: vtx)
    {
        mempool.remove(tx);
    }

    return true;
}

bool CBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
    uint256 hash = GetHash();

    if (!txdb.TxnBegin())
    {
        return error("%s : ERROR - TxnBegin failed", __FUNCTION__);
    }

    if (pindexGenesisBlock == NULL && hash == Params().HashGenesisBlock())
    {
        txdb.WriteHashBestChain(hash);

        if (!txdb.TxnCommit())
        {
            return error("%s : ERROR - TxnCommit failed", __FUNCTION__);
        }

        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain)
    {
        if (!SetBestChainInner(txdb, pindexNew))
        {
            return error("%s : ERROR - SetBestChainInner failed", __FUNCTION__);
        }
    }
    else
    {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex*> vpindexSecondary;

        // Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->pprev && pindexIntermediate->pprev->nChainTrust > pindexBest->nChainTrust)
        {
            vpindexSecondary.push_back(pindexIntermediate);

            pindexIntermediate = pindexIntermediate->pprev;
        }

        if (!vpindexSecondary.empty())
        {
            if (fDebug)
            {
                LogPrint("core", "%s : ERROR - Postponing %u reconnects \n", __FUNCTION__, vpindexSecondary.size());
            }
        }

        // Switch to new best branch
        if (!CChain::Reorganize(txdb, pindexIntermediate))
        {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);

            return error("%s : ERROR - Reorganize failed", __FUNCTION__);
        }

        // Connect further blocks
        for(CBlockIndex *pindex: boost::adaptors::reverse(vpindexSecondary))
        {
            CBlock block;

            if (!block.ReadFromDisk(pindex))
            {
                if (fDebug)
                {
                    LogPrint("core", "%s : ERROR - ReadFromDisk failed \n", __FUNCTION__);
                }

                break;
            }

            if (!txdb.TxnBegin())
            {
                if (fDebug)
                {
                    LogPrint("core", "%s : ERROR - TxnBegin 2 failed \n", __FUNCTION__);
                }

                break;
            }

            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (!block.SetBestChainInner(txdb, pindex))
            {
                break;
            }
        }


    }

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = IsInitialBlockDownload();

    if (fImporting == true)
    {
        fIsInitialDownload = true;
    }

    if (fReindex == true)
    {
        fIsInitialDownload = true;
    }

    if ((pindexNew->nHeight % 20160) == 0
        || (!fIsInitialDownload && (pindexNew->nHeight % 144) == 0))
    {
        const CBlockLocator locator(pindexNew);
        g_signals.SetBestChain(locator);
    }

    // New best block
    hashBestChain = hash;
    pindexBest = pindexNew;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexBest->nHeight;
    nBestChainTrust = pindexNew->nChainTrust;
    nTimeBestReceived = GetTime();
    mempool.AddTransactionsUpdated(1);

    //uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    if (fDebug)
    {
        LogPrint("core", "%s : NOTICE - new best=%s  height=%d  trust=%s \n", __FUNCTION__, hashBestChain.ToString(), nBestHeight, CBigNum(nBestChainTrust).ToString());
    }

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexBest;

        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
            {
                ++nUpgraded;
            }

            pindex = pindex->pprev;
        }

        if (nUpgraded > 0)
        {
            if (fDebug)
            {
                LogPrint("core", "%s : ERROR - %d of last 100 blocks above version %d \n", __FUNCTION__, nUpgraded, (int)CBlock::CURRENT_VERSION);
            }
        }

        if (nUpgraded > 100/2)
        {
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
        }

    }

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CTxDB& txdb, const CBlockIndex* pindexPrev, uint64_t& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
    {
        return true;
    }

    for(const CTxIn& txin: vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;

        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
        {
            continue;  // previous transaction not in main chain
        }

        if (nTime < txPrev.nTime)
        {
            return false;  // Transaction timestamp violation
        }

        // Read block header
        CBlock block;

        if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
        {
            return false; // unable to read block of previous transaction
        }

        if (block.GetBlockTime() + nStakeMinAge > nTime)
        {
            continue; // only count coins meeting min age requirement
        }

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;

        if (fDebug)
        {
            LogPrint("coinage", "%s : NOTICE - Coin age nValueIn=%d nTimeDiff=%d bnCentSecond=%s \n", __FUNCTION__, nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString());
        }
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);

    if (fDebug)
    {
        LogPrint("coinage", "%s : NOTICE - Coin age bnCoinDay=%s \n", __FUNCTION__, bnCoinDay.ToString());
    }

    nCoinAge = bnCoinDay.getuint64();

    return true;
}


bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, const uint256& hashProof)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
    {
        return error("%s : %s NOTICE - Already exists", __FUNCTION__, hash.ToString());
    }

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);

    if (!pindexNew)
    {
        return error("%s : NOTICE - New CBlockIndex failed", __FUNCTION__);
    }

    pindexNew->phashBlock = &hash;
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);

    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    // ppcoin: compute chain trust score
    pindexNew->nChainTrust = (pindexNew->pprev ? pindexNew->pprev->nChainTrust : 0) + pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit()))
    {
        return error("%s : NOTICE - SetStakeEntropyBit() failed", __FUNCTION__);
    }

    /* TO-FIX
    // peercoin: record proof-of-stake hash value
    if (pindexNew->IsProofOfStake())
    {
        if (!mapProofOfStake.count(hash))
        {
            return error("AddToBlockIndex() : hashProofOfStake not found in map");
        }

        pindexNew->hashProof = mapProofOfStake[hash];
    }
    else
    {
        // Record proof hash value
        pindexNew->hashProof = hashProof;
    }
    */

    // Record proof hash value
    pindexNew->hashProof = hashProof;

    // ppcoin: compute stake modifier
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;

    if (!ComputeNextStakeModifier(pindexNew->pprev, nStakeModifier, fGeneratedStakeModifier))
    {
        return error("%s : NOTICE - ComputeNextStakeModifier() failed", __FUNCTION__);
    }

    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    
    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;

    if (pindexNew->IsProofOfStake())
    {
        setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
    }

    pindexNew->phashBlock = &((*mi).first);

    // Write to disk block index
    CTxDB txdb;

    if (!txdb.TxnBegin())
    {
        return false;
    }

    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));

    if (!txdb.TxnCommit())
    {
        return false;
    }

    // New best
    if (pindexNew->nChainTrust > nBestChainTrust)
    {
        if (!SetBestChain(txdb, pindexNew))
        {
            return false;
        }
    }
    
    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;

        g_signals.UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    return true;
}


bool CBlock::CheckBlock(bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (vtx.empty()
        || vtx.size() > MAX_BLOCK_SIZE
        || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
    {
        return DoS(100, error("%s : ERROR - Size limits failed", __FUNCTION__));
    }

    // Check proof of work matches claimed amount
    if (fCheckPOW && IsProofOfWork() && !CheckProofOfWork(GetPoWHash(), nBits))
    {
        return DoS(50, error("%s : ERROR - Proof of work failed", __FUNCTION__));
    }

    // Check timestamp
    if (GetBlockTime() > FutureDrift(GetAdjustedTime()))
    {
        return error("%s : ERROR - Block timestamp too far in the future", __FUNCTION__);
    }

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty()
        || !vtx[0].IsCoinBase())
    {
        return DoS(100, error("%s : ERROR - First tx is not coinbase", __FUNCTION__));
    }

    for (unsigned int i = 1; i < vtx.size(); i++)
    {
        if (vtx[i].IsCoinBase())
        {
            return DoS(100, error("%s : ERROR - More than one coinbase", __FUNCTION__));
        }
    }

    if (IsProofOfStake())
    {
        // Coinbase output should be empty if proof-of-stake block
        if (vtx[0].vout.size() != 1
            || !vtx[0].vout[0].IsEmpty())
        {
            return DoS(100, error("%s : ERROR - Coinbase output not empty for proof-of-stake block", __FUNCTION__));
        }

        // Second transaction must be coinstake, the rest must not be
        if (vtx.empty()
            || !vtx[1].IsCoinStake())
        {
            return DoS(100, error("%s : ERROR - Second tx is not coinstake", __FUNCTION__));
        }

        for (unsigned int i = 2; i < vtx.size(); i++)
        {
            if (vtx[i].IsCoinStake())
            {
                return DoS(100, error("%s : ERROR - More than one coinstake", __FUNCTION__));
            }
        }
    }

    // Check proof-of-stake block signature
    if (fCheckSig
        && !CheckBlockSignature())
    {
        return DoS(100, error("%s : ERROR - Bad proof-of-stake block signature", __FUNCTION__));
    }

    // ----------- instantX transaction scanning -----------
    if(IsSporkActive(SPORK_3_INSTANTX_BLOCK_FILTERING))
    {
        for(const CTransaction& tx: vtx)
        {
            if (!tx.IsCoinBase())
            {
                //only reject blocks when it's based on complete consensus
                for(const CTxIn& in: tx.vin)
                {
                    if(mapLockedInputs.count(in.prevout))
                    {
                        if(mapLockedInputs[in.prevout] != tx.GetHash())
                        {
                            if(fDebug)
                            {
                                LogPrint("core", "%s : ERROR - Found conflicting transaction with transaction lock %s %s \n", __FUNCTION__, mapLockedInputs[in.prevout].ToString().c_str(), tx.GetHash().ToString().c_str());
                            }
                            
                            return DoS(0, error("%s : ERROR - Found conflicting transaction with transaction lock %s %s \n", __FUNCTION__, mapLockedInputs[in.prevout].ToString().c_str(), tx.GetHash().ToString().c_str()));
                        }
                    }
                }
            }
        }
    }
    else
    {
        if(fDebug)
        {
            LogPrint("core", "%s : WARNING - Skipping transaction locking checks \n", __FUNCTION__);
        }
    }

    // ----------- masternode payments -----------

    bool MasternodePayments = false;
    bool fIsInitialDownload = IsInitialBlockDownload();

    if(nTime > START_MASTERNODE_PAYMENTS)
    {
        MasternodePayments = true;
    }

    if (!fIsInitialDownload)
    {
        if(MasternodePayments)
        {
            LOCK2(cs_main, mempool.cs);

            CBlockIndex *pindex = pindexBest;

            if(IsProofOfStake()
                && pindex != NULL)
            {
                if(pindex->GetBlockHash() == hashPrevBlock)
                {
                    // If we don't already have its previous block, skip masternode payment step
                    CAmount masternodePaymentAmount;

                    for (int i = vtx[1].vout.size(); i--> 0; )
                    {
                        masternodePaymentAmount = vtx[1].vout[i].nValue;

                        break;
                    }

                    bool foundPaymentAmount = false;
                    bool foundPayee = false;
                    bool foundPaymentAndPayee = false;

                    CScript payee;
                    CTxIn vin;

                    if(!masternodePayments.GetBlockPayee(pindexBest->nHeight+1, payee, vin) || payee == CScript())
                    {
                        int DeActivationHeight = 1;

                        // PIP 3
                        // Do not allow blank payments
                        
                        DeActivationHeight = Params().PIP3_Height(); // DeActivation

                        if (pindexBest->nHeight+1 >= DeActivationHeight)
                        {
                            foundPayee = false; //doesn't require a specific payee
                            foundPaymentAmount = false;
                            foundPaymentAndPayee = false;
                        }
                        else
                        {
                            foundPayee = true; //doesn't require a specific payee
                            foundPaymentAmount = true;
                            foundPaymentAndPayee = true;
                        }

                        if(fDebug)
                        {
                            LogPrint("blockshield", "%s : ERROR - Detected non-specific masternode payments %d \n", __FUNCTION__, pindexBest->nHeight+1);
                        }
                    }

                    for (unsigned int i = 0; i < vtx[1].vout.size(); i++)
                    {
                        if(vtx[1].vout[i].nValue == masternodePaymentAmount)
                        {
                            foundPaymentAmount = true;
                        }

                        if(vtx[1].vout[i].scriptPubKey == payee)
                        {
                            foundPayee = true;
                        }

                        if(vtx[1].vout[i].nValue == masternodePaymentAmount
                            && vtx[1].vout[i].scriptPubKey == payee)
                        {
                            foundPaymentAndPayee = true;
                        }
                    }

                    bool foundDevFee = false;

                    // PIP4 - Developers Fee (TO-DO: troubleshoot and test)
                    if (pindex->nHeight >= Params().PIP4_Height())
                    {
                        CCoinAddress devRewardAddress(getDevRewardAddress(pindex->nHeight + 1));
                        
                        CScript devRewardscriptPubKey = GetScriptForDestination(devRewardAddress.Get());

                        foundDevFee = false;

                        for (unsigned int i = 0; i < vtx[1].vout.size(); i++)
                        {
                            if(vtx[1].vout[i].scriptPubKey == devRewardscriptPubKey)
                            {
                                foundDevFee = true;
                            }
                        }
                    }

                    CTxDestination address1;

                    ExtractDestination(payee, address1);

                    CCoinAddress address2(address1);

                    if (pindex->nHeight >= Params().PIP4_Height())
                    {
                        if (!foundDevFee)
                        {
                            if(fDebug)
                            {
                                LogPrint("core", "%s : ERROR - Couldn't find devfee payment(%d|%d) or payee(%d|%s) nHeight %d. \n", __FUNCTION__, foundPaymentAmount, masternodePaymentAmount, foundPayee, address2.ToString().c_str(), pindexBest->nHeight+1);
                            }

                            return DoS(100, error("%s : ERROR - Couldn't find devfee payment(%d|%d) or payee(%d|%s) nHeight %d. \n", __FUNCTION__, foundPaymentAmount, masternodePaymentAmount, foundPayee, address2.ToString().c_str(), pindexBest->nHeight+1));
                        }
                    }
                    
                    if(!foundPaymentAndPayee)
                    {
                        if(fDebug)
                        {
                            LogPrint("core", "%s : ERROR - Couldn't find masternode payment(%d|%d) or payee(%d|%s) nHeight %d. \n", __FUNCTION__, foundPaymentAmount, masternodePaymentAmount, foundPayee, address2.ToString().c_str(), pindexBest->nHeight+1);
                        }

                        return DoS(100, error("%s : ERROR - Couldn't find masternode payment(%d|%d) or payee(%d|%s) nHeight %d. \n", __FUNCTION__, foundPaymentAmount, masternodePaymentAmount, foundPayee, address2.ToString().c_str(), pindexBest->nHeight+1));
                    }
                    else
                    {
                        LogPrint("core", "%s : NOTICE - Found payment(%d|%d) or payee(%d|%s) nHeight %d. \n", __FUNCTION__, foundPaymentAmount, masternodePaymentAmount, foundPayee, address2.ToString().c_str(), pindexBest->nHeight+1);
                    }
                }
                else
                {
                    if(fDebug)
                    {
                        LogPrint("core", "%s : WARNING - Skipping masternode payment check - nHeight %d Hash %s \n", __FUNCTION__, pindexBest->nHeight+1, GetHash().ToString().c_str());
                    }
                }
            }
            else
            {
                if(fDebug)
                {
                    LogPrint("core", "%s : WARNING - pindex is null, skipping masternode payment check \n", __FUNCTION__);
                }
            }
        }
        else
        {
            if(fDebug)
            {
                LogPrint("core", "%s : WARNING - Skipping masternode payment checks \n", __FUNCTION__);
            }
        }
    }
    else
    {
        if(fDebug)
        {
            LogPrint("core", "%s : WARNING - Is initial download, skipping masternode payment check %d \n", __FUNCTION__, pindexBest->nHeight+1);
        }
    }

    // Check transactions
    for(const CTransaction& tx: vtx)
    {
        if (!tx.CheckTransaction())
        {
            return DoS(tx.nDoS, error("%s : ERROR - CheckTransaction failed", __FUNCTION__));
        }

        // ppcoin: check transaction timestamp
        if (GetBlockTime() < (int64_t)tx.nTime)
        {
            return DoS(50, error("%s : ERROR - Block timestamp earlier than transaction timestamp", __FUNCTION__));
        }
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    set<uint256> uniqueTx;

    for(const CTransaction& tx: vtx)
    {
        uniqueTx.insert(tx.GetHash());
    }

    if (uniqueTx.size() != vtx.size())
    {
        return DoS(100, error("%s : ERROR - Duplicate transaction", __FUNCTION__));
    }

    unsigned int nSigOps = 0;

    for(const CTransaction& tx: vtx)
    {
        nSigOps += GetLegacySigOpCount(tx);
    }

    if (nSigOps > MAX_BLOCK_SIGOPS)
    {
        return DoS(100, error("%s : ERROR - Out-of-bounds SigOpCount", __FUNCTION__));
    }

    // Check merkle root
    if (fCheckMerkleRoot
        && hashMerkleRoot != BuildMerkleTree())
    {
        return DoS(100, error("%s : ERROR - HashMerkleRoot mismatch", __FUNCTION__));
    }

    return true;
}


bool CBlock::BlockShield(int Block_nHeight) const
{  
    // BLOCK SHIELD 1.2.1 - Profit Hunters Coin Version

    // Block #1 (Default)
    int ActivationHeight = 1;

    bool LogGeneralStats = false;
    double BlockSpaceMin = 1; // Minutes
    double Compare1;
    double Compare2;
    double Compare3;
    std::string TempLogCache;

    // PIP 5
    ActivationHeight = Params().PIP5_Height();

    if (Block_nHeight >= ActivationHeight)
    {
        // Increment Block check counter
        BlockShieldCounter++;

        ////////////////////
        // Proof of Work Checks Only
        //
        if (IsProofOfWork())
        {
            // Not implemented
        }
        //
        ////////////////////

        ////////////////////
        // Proof of Stake Checks Only
        //
        if (IsProofOfStake())
        {
            // **********************************************
            // ** POS RULE #1: INFLATED MN + POS REWARD
            // **

            CAmount STAKEVOUT_TOTAL = 0;
            
            // Calculate PoS + MN Rewards total
            for (int i = vtx[1].vout.size(); i--> 0;)
            {
                STAKEVOUT_TOTAL +=  vtx[1].vout[i].nValue;

                // TODO 1.0.0.8: Keep log of MN + Stake addresses and make sure they don't repeat too often (POS Rule #2)
            }

            // Check for inflated rewards after 1000 blocks to get proper average
            if (BlockShieldCounter > 1000)
            {
                if (StakeRewardAverage > 0)
                {
                    if (STAKEVOUT_TOTAL > (StakeRewardAverage * 0.01) + StakeRewardAverage)
                    {
                        if (fDebug)
                        {
                            // Verify Logfile flooding before outputing debug
                            TempLogCache = "failed"
                                            + std::to_string(Block_nHeight)
                                            + std::to_string(STAKEVOUT_TOTAL)
                                            + std::to_string(StakeRewardAverage);

                            if (BlockShieldLogCache != TempLogCache)
                            {
                                LogPrint("blockshield", "%s : ERROR - Rule #1 FAILED @ Block #: %d, StakeVoutTotal: %d VoutAverage: %d \n", __FUNCTION__, Block_nHeight, FormatMoney(STAKEVOUT_TOTAL), FormatMoney(StakeRewardAverage));
                            
                                BlockShieldLogCache = TempLogCache;
                            }
                        }

                        // Failed test
                        return true;
                    }
                }
            }

            // General Stats
            if (LogGeneralStats)
            {
                if (fDebug)
                {
                    // Verify Logfile flooding before outputing debug
                    TempLogCache = "general"
                                    + std::to_string(Block_nHeight)
                                    + std::to_string(STAKEVOUT_TOTAL)
                                    + std::to_string(StakeRewardAverage);

                    if (BlockShieldLogCache != TempLogCache)
                    {
                        LogPrint("blockshield", "%s : ERROR - Block #: %d, StakeVoutTotal: %d VoutAverage: %d \n", __FUNCTION__, Block_nHeight, FormatMoney(STAKEVOUT_TOTAL), FormatMoney(StakeRewardAverage));
                    
                        BlockShieldLogCache = TempLogCache;
                    }
                }
            }

            // Modify Global Average
            if (STAKEVOUT_TOTAL > 0)
            {   
                if (STAKEVOUT_TOTAL > StakeRewardAverage)
                {
                    StakeRewardAverage = (StakeRewardAverage + STAKEVOUT_TOTAL) / 2;
                }
            }

            // **
            // **********************************************
        }
        //
        ////////////////////

        ////////////////////
        // PoW & PoS Checks (C) 2018 Crypostle - Block_Shield 1.2
        //

            // **********************************************
            // ** HYBRID RULE #1: BlockTime Space Minimum
            // **
            // Do not allow current block to be accepted if last block was before minimum time space
            //
            Compare1 = GetBlockTime() - pindexBest->GetBlockTime();
            Compare2 = BlockSpaceMin * 60;

            if (Compare1 < Compare2)
            {
                if (fDebug)
                {
                    // Verify Logfile flooding before outputing debug
                    TempLogCache = "hybrid-1" 
                                    + std::to_string(Block_nHeight)
                                    + std::to_string(Compare1)
                                    + std::to_string(Compare2);

                    if (BlockShieldLogCache != TempLogCache)
                    {                       
                        LogPrint("blockshield", "%s : ERROR - Block #: %d, Previous block space %d below %d seconds \n", __FUNCTION__, Block_nHeight, Compare1, Compare2);

                        BlockShieldLogCache = TempLogCache;
                    }
                }

                return true;
            }
            // **
            // **********************************************

            // **********************************************
            // ** HYBRID RULE #2: BlockTime Future Maximum
            // **
            // Do not allow current block to be accepted if it's in the future above time spacing
            //
            Compare1 = GetBlockTime();
            Compare2 = BlockSpaceMin * 60 + GetTime();

            if (Compare1 > Compare2)
            {
                if (fDebug)
                {
                    // Verify Logfile flooding before outputing debug
                    TempLogCache = "hybrid-2" 
                                    + std::to_string(Block_nHeight)
                                    + std::to_string(Compare1)
                                    + std::to_string(Compare2);

                    if (BlockShieldLogCache != TempLogCache)
                    {
                        LogPrint("blockshield", "%s : ERROR - Block #: %d, Current block age: %d above %d minutes \n", __FUNCTION__, Block_nHeight, Compare1, Compare2);
                
                        BlockShieldLogCache = TempLogCache;
                    }
                }

                return true;
            }

            // **
            // **********************************************

            // **********************************************
            // ** HYBRID RULE #3: BlockTime Minimum With Delay
            // **
            // Do not allow Last block and current block spacing to be below minimum
            //
            Compare1 = GetTime() - pindexBest->GetBlockTime();
            Compare2 = BlockSpaceMin * 60;
            Compare3 = GetTime() - GetBlockTime();

            if (Compare1 < Compare2 && Compare3 < Compare2)
            {
                if (fDebug)
                {
                    // Verify Logfile flooding before outputing debug
                    TempLogCache = "hybrid-3" 
                                    + std::to_string(Block_nHeight)
                                    + std::to_string(Compare1)
                                    + std::to_string(Compare2)
                                    + std::to_string(Compare3);

                    if (BlockShieldLogCache != TempLogCache)
                    {
                        LogPrint("blockshield", "%s : ERROR - Block #: %d, last block: %d & current block: %d spacing below %d minutes \n", __FUNCTION__, Block_nHeight, Compare1, Compare2, Compare3);
                    
                        BlockShieldLogCache = TempLogCache;
                    }
                }

                return true;
            }

            // **********************************************
            // ** HYBRID RULE #4: BlockTime Spoofing
            // **
            // Do not allow Last block and current block time to be equal
            //
            Compare1 = pindexBest->GetBlockTime();
            Compare2 = GetBlockTime();

            if (Compare1 == Compare2)
            {
                if (fDebug)
                {
                    // Verify Logfile flooding before outputing debug
                    TempLogCache = "hybrid-4" 
                                    + std::to_string(Block_nHeight)
                                    + std::to_string(Compare1)
                                    + std::to_string(Compare2);

                    if (BlockShieldLogCache != TempLogCache)
                    { 
                        LogPrint("blockshield", "%s : ERROR - Block #: %d, last block: %d & current block: %d are both equal \n", __FUNCTION__, Block_nHeight, Compare1, Compare2);

                        BlockShieldLogCache = TempLogCache;
                    }
                }

                return true;
            }

            // **********************************************
            // ** HYBRID RULE #5: BlockTime Shitfting Attack
            // **
            // Do not allow block time-shifting
            //
            Compare1 = pindexBest->GetBlockTime();
            Compare2 = GetBlockTime();

            if (Compare1 > Compare2)
            {
                if (fDebug)
                {
                    // Verify Logfile flooding before outputing debug
                    TempLogCache = "hybrid-5"
                                    + std::to_string(Block_nHeight)
                                    + std::to_string(Compare1)
                                    + std::to_string(Compare2);

                    if (BlockShieldLogCache != TempLogCache)
                    {
                        LogPrint("blockshield", "%s : ERROR - Block #: %d, time-shifting detected: Previous Block: %d & Current Block: %d \n", __FUNCTION__, Block_nHeight, Compare1, Compare2);
                        
                        BlockShieldLogCache = TempLogCache;
                    }
                }

                return true;
            }
            
            // **
            // **********************************************
        //
        ////////////////////
    }

    // Passed all checks
    return false;
}


bool CBlock::AcceptBlock()
{
    AssertLockHeld(cs_main);

    // Remove for BIP-0034 FORK
    if (nVersion > CURRENT_VERSION)
    {
        return DoS(100, error("%s : NOTICE - Reject unknown block version %d", __FUNCTION__, nVersion));
    }

    // Check for duplicate
    uint256 hash = GetHash();

    if (mapBlockIndex.count(hash))
    {
        return error("%s : NOTICE - Block already in mapBlockIndex", __FUNCTION__);
    }

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);

    if (mi == mapBlockIndex.end())
    {
        return DoS(10, error("%s : NOTICE - Prev block not found", __FUNCTION__));
    }

    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight+1;
    uint256 hashProof;

    if (IsProofOfWork()
        && nHeight > Params().LastPOWBlock())
    {
        return DoS(100, error("%s : NOTICE - Reject proof-of-work at height %d", __FUNCTION__, nHeight));
    }
    else
    {
        // PoW is checked in CheckBlock()
        if (IsProofOfWork())
        {
            hashProof = GetPoWHash();
        }
    }

    if (IsProofOfStake()
        && nHeight < Params().POSStartBlock())
    {
        return DoS(100, error("%s : NOTICE - Reject proof-of-stake at height <= %d", __FUNCTION__, nHeight));
    }

    // BlockShield
    if (BlockShield(nHeight))
    {
        return DoS(100, error("%s : NOTICE - Block Shield test failed", __FUNCTION__));
    }

    // Check coinbase timestamp
    if (GetBlockTime() > FutureDrift((int64_t)vtx[0].nTime)
        && IsProofOfStake())
    {
        return DoS(50, error("%s : NOTICE - Coinbase timestamp is too early", __FUNCTION__));
    }

    // Check coinstake timestamp
    if (IsProofOfStake()
        && !CheckCoinStakeTimestamp(nHeight, GetBlockTime(), (int64_t)vtx[1].nTime))
    {
        return DoS(50, error("%s : NOTICE - Coinstake timestamp violation nTimeBlock=%d nTimeTx=%u", __FUNCTION__, GetBlockTime(), vtx[1].nTime));
    }

    // Check proof-of-work or proof-of-stake
    if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake())
        && hash != uint256("0x474619e0a58ec88c8e2516f8232064881750e87acac3a416d65b99bd61246968"))
    {
        return DoS(100, error("%s : NOTICE - Incorrect %s", __FUNCTION__, IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));
    }

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetPastTimeLimit()
        || FutureDrift(GetBlockTime()) < pindexPrev->GetBlockTime())
    {
        return error("%s : NOTICE - Block's timestamp is too early", __FUNCTION__);
    }

    // Check that all transactions are finalized
    for(const CTransaction& tx: vtx)
    {
        if (!IsFinalTx(tx, nHeight, GetBlockTime()))
        {
            return DoS(10, error("%s : NOTICE - Contains a non-final transaction", __FUNCTION__));
        }
    }

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
    {
        return DoS(100, error("%s : NOTICE - Rejected by hardened checkpoint lock-in at %d", __FUNCTION__, nHeight));
    }

    // Verify hash target and signature of coinstake tx
    if (IsProofOfStake())
    {
        uint256 targetProofOfStake;

        if (!CheckProofOfStake(pindexPrev, vtx[1], nBits, hashProof, targetProofOfStake))
        {
            return error("%s : NOTICE - Check proof-of-stake failed for block %s", __FUNCTION__, hash.ToString());
        }
    }

    // Check that the block satisfies synchronized checkpoint
    if (!Checkpoints::CheckSync(nHeight))
    {
        return error("%s : NOTICE - Rejected by synchronized checkpoint", __FUNCTION__);
    }

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;

    if (vtx[0].vin[0].scriptSig.size() < expect.size()
        || !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
    {
        return DoS(100, error("%s : NOTICE - Block height mismatch in coinbase", __FUNCTION__));
    }

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
    {
        return error("%s : NOTICER - Out of disk space", __FUNCTION__);
    }

    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;

    if (!WriteToDisk(nFile, nBlockPos))
    {
        return error("%s : NOTICE - WriteToDisk failed", __FUNCTION__);
    }

    if (!AddToBlockIndex(nFile, nBlockPos, hashProof))
    {
        return error("%s : NOTICE - AddToBlockIndex failed", __FUNCTION__);
    }

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();

    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);

        for(CNode* pnode: vNodes)
        {
            // Push Inventory to CNode
            if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
            {
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
            }

            // Push Dynamic Checkpoint Data, even if not received from peer
            if (pnode->dCheckpointRecv.height == 0)
            {
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);

                if (mi != mapBlockIndex.end())
                {
                    CBlockIndex* pindex = (*mi).second;

                    if (pindex && pindex->IsInMainChain())
                    {
                        pnode->dCheckpointRecv.hash = hash;
                        pnode->dCheckpointRecv.height = pindex->nHeight;
                        pnode->dCheckpointRecv.timestamp = GetTime();
                    }
                }
            }
        }
    }

    if (!fReindex
        || !fImporting
        || !IsInitialBlockDownload()
        || Consensus::ChainShield::ChainShieldCache < pindexBest->nHeight)
    {
        if (Consensus::ChainShield::Enabled == true
            && Consensus::ChainBuddy::Enabled == true)
        {
            // Double check to make sure local blockchain remains in sync with new blocks from nodes & new blocks mines or staked
            Consensus::ChainBuddy::WalletHasConsensus();

            Consensus::ChainShield::Protect();
        }
    }

    return true;
}


uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    if (bnTarget <= 0)
    {
        return 0;
    }

    return ((CBigNum(1)<<256) / (bnTarget+1)).getuint256();
}


bool static IsCanonicalBlockSignature(CBlock* pblock)
{
    if (pblock->IsProofOfWork())
    {
        return pblock->vchBlockSig.empty();
    }

    return IsDERSignature(pblock->vchBlockSig, false);
}



void Misbehaving(NodeId pnode, int howmuch)
{
    if (howmuch == 0)
    {
        return;
    }

    CNodeState *state = State(pnode);

    if (state == NULL)
    {
        return;
    }

    state->nMisbehavior += howmuch;

    if (state->nMisbehavior >= GetArg("-banscore", 100))
    {
        if(fDebug)
        {
            LogPrint("net", "%s : %s (%d -> %d) BAN THRESHOLD EXCEEDED \n", __FUNCTION__, state->name.c_str(), state->nMisbehavior-howmuch, state->nMisbehavior);
        }

        state->fShouldBan = true;
    }
    else
    {
        if(fDebug)
        {
            LogPrint("net", "%s : %s (%d -> %d) \n", __FUNCTION__, state->name.c_str(), state->nMisbehavior-howmuch, state->nMisbehavior);
        }
    }
}


bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = pblock->GetHash();

    if (mapBlockIndex.count(hash))
    {
        if(fDebug)
        {
            LogPrint("core", "%s : already have block %d %s \n", __FUNCTION__, mapBlockIndex[hash]->nHeight, hash.ToString());
        }

        return error("%s : already have block %d %s", __FUNCTION__, mapBlockIndex[hash]->nHeight, hash.ToString());
    }

    if (mapOrphanBlocks.count(hash))
    {
        if(fDebug)
        {
            LogPrint("core", "%s : already have block (orphan) %s \n", __FUNCTION__, hash.ToString());
        }

        return error("%s : already have block (orphan) %s", __FUNCTION__, hash.ToString());
    }

    // ppcoin: check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (!fReindex
        && !fImporting
        && pblock->IsProofOfStake()
        && setStakeSeen.count(pblock->GetProofOfStake())
        && !mapOrphanBlocksByPrev.count(hash))
    {       
        if(fDebug)
        {
            LogPrint("core", "%s : duplicate proof-of-stake (%s, %d) for block %s \n", __FUNCTION__, pblock->GetProofOfStake().first.ToString(), pblock->GetProofOfStake().second, hash.ToString());
        }

        return error("%s : duplicate proof-of-stake (%s, %d) for block %s", __FUNCTION__, pblock->GetProofOfStake().first.ToString(), pblock->GetProofOfStake().second, hash.ToString());
    }

    // Block signature can be malleated in such a way that it increases block size up to maximum allowed by protocol
    // For now we just strip garbage from newly received blocks
    if (!IsCanonicalBlockSignature(pblock))
    {
        return error("ProcessBlock(): bad block signature encoding");
    }

   // Preliminary checks
    if (!pblock->CheckBlock())
    {
        if(fDebug)
        {
            LogPrint("core", "%s : ERROR - Check FAILED: %s \n", __FUNCTION__, hash.ToString());
        }

        return error("%s : ERROR - Check FAILED: %s", __FUNCTION__, hash.ToString());
    }

    // If we don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        if(fDebug)
        {
            LogPrint("core", "%s : WARNING - ORPHAN BLOCK %lu, prev=%s \n", __FUNCTION__, (unsigned long)mapOrphanBlocks.size(), pblock->hashPrevBlock.ToString());
        }

        // Accept orphans as long as there is a node to request its parents from
        if (pfrom)
        {
            // ppcoin: check proof-of-stake
            if (pblock->IsProofOfStake())
            {
                // Limited duplicity on stake: prevents block flood attack
                // Duplicate stake allowed only when there is orphan child block
                if (setStakeSeenOrphan.count(pblock->GetProofOfStake())
                    && !mapOrphanBlocksByPrev.count(hash))
                {
                    return error("%s : ERROR - Duplicate proof-of-stake (%s, %d) for orphan block %s", __FUNCTION__, pblock->GetProofOfStake().first.ToString(), pblock->GetProofOfStake().second, hash.ToString());
                }
            }
            
            CChain::PruneOrphanBlocks();
            
            COrphanBlock* pblock2 = new COrphanBlock();
            {
                CDataStream ss(SER_DISK, CLIENT_VERSION);
                ss << *pblock;
                pblock2->vchBlock = std::vector<unsigned char>(ss.begin(), ss.end());
            }

            pblock2->hashBlock = hash;
            pblock2->hashPrev = pblock->hashPrevBlock;
            pblock2->stake = pblock->GetProofOfStake();

            mapOrphanBlocks.insert(make_pair(hash, pblock2));
            mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrev, pblock2));

            if (pblock->IsProofOfStake())
            {
                setStakeSeenOrphan.insert(pblock->GetProofOfStake());
            }

            // Only request orphan chain if enabled (default) and node has not previously sent a duplicate orphan block
            if (GetBoolArg("-orphansync", false) == true
                && pfrom->dOrphanRecv.hash != hash)
            {
                // Only request for orphan chain if not InitialBlockDownload or Importing
                if (!IsInitialBlockDownload()
                    && !fImporting
                    && !fReindex)
                {
                    // Ask this guy to fill in what we're missing
                    pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(hash));

                    // ppcoin: getblocks may not obtain the ancestor block rejected
                    // earlier by duplicate-stake check so we ask for it again directly
                    pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));
                }
            }

            // Keep track of last received orphans from nodes to prevent flooding attacks
            if (pfrom->dOrphanRecv.hash != hash)
            {   
                if (pindexBest)
                {
                    pfrom->dOrphanRecv.height = pindexBest->nHeight;
                    pfrom->dOrphanRecv.hash = hash;
                    pfrom->dOrphanRecv.timestamp = GetTime();
                    pfrom->dOrphanRecv.synced = true;
                }
            }
        }

        // Auto Chain pruning Max X blocks, 0 block max default
        // EXPERIMENTAL
        int nAutoPrune = GetArg("-autoprune", 0);

        if (nAutoPrune > 0)
        {
            if (fReorganizeCount < nAutoPrune)
            {
                CTxDB txdbAddr("rw");

                CBlock block;

                pindexBest->pprev->pprev->pnext = NULL;

                block.ReadFromDisk(pindexBest->pprev);
                block.DisconnectBlock(txdbAddr, pindexBest->pprev);
                block.SetBestChain(txdbAddr, pindexBest->pprev);

                fReorganizeCount = fReorganizeCount + 1;
            }
            else
            {
                fReorganizeCount = 0;
            }
        }

        if (!IsInitialBlockDownload()
            && !fReindex
            && !fImporting)
        {
            // Limit Orphan list to set max to avoid memory flooding attacks
            if (mapOrphanBlocks.size() > DEFAULT_MAX_ORPHAN_BLOCKS)
            {
                mapOrphanBlocks.erase(mapOrphanBlocks.begin());
            }
        }

        if(fDebug)
        {
            LogPrint("core", "%s : WARNING - Orphan chain %s detected \n", __FUNCTION__, hash.ToString());
        }

        // Clear the mempool to avoid getting stuck on this orphan chain
        mempool.clear();

        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
    {
        return error("%s : ERROR - AcceptBlock FAILED @ Block: %s", __FUNCTION__, hash.ToString());
    }

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;

    vWorkQueue.push_back(hash);

    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];

        for (multimap<uint256, COrphanBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock block;
            {
                CDataStream ss(mi->second->vchBlock, SER_DISK, CLIENT_VERSION);
                ss >> block;
            }

            block.BuildMerkleTree();

            if (block.AcceptBlock())
            {
                vWorkQueue.push_back(mi->second->hashBlock);
            }

            mapOrphanBlocks.erase(mi->second->hashBlock);
            setStakeSeenOrphan.erase(block.GetProofOfStake());

            delete mi->second;
        }

        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    if(!IsInitialBlockDownload())
    {
        CScript payee;
        CTxIn vin;

        // If we're in LiteMode disable darksend features without disabling masternodes
        if (!fLiteMode
            && !fImporting
            && !fReindex
            && pindexBest->nHeight > Checkpoints::GetTotalBlocksEstimate())
        {
            if(masternodePayments.GetBlockPayee(pindexBest->nHeight, payee, vin))
            {
                //UPDATE MASTERNODE LAST PAID TIME
                CMasternode* pmn = mnodeman.Find(vin);

                if(pmn != NULL)
                {
                    pmn->nLastPaid = GetAdjustedTime();
                }

                if(fDebug)
                {
                    LogPrint("core", "%s : OK - Update Masternode Last Paid Time - %d \n", __FUNCTION__, pindexBest->nHeight);
                }
            }

            darkSendPool.CheckTimeout();
            darkSendPool.NewBlock();
            masternodePayments.ProcessBlock(GetHeight()+10);

        }
        else if (fLiteMode
            && !fImporting
            && !fReindex
            && pindexBest->nHeight > Checkpoints::GetTotalBlocksEstimate())
        {
            if(masternodePayments.GetBlockPayee(pindexBest->nHeight, payee, vin))
            {
                //UPDATE MASTERNODE LAST PAID TIME
                CMasternode* pmn = mnodeman.Find(vin);

                if(pmn != NULL)
                {
                    pmn->nLastPaid = GetAdjustedTime();
                }

                if(fDebug)
                {
                    LogPrint("core", "%s : NOTICE - Update Masternode Last Paid Time - %d \n", __FUNCTION__, pindexBest->nHeight);
                }
            }

            masternodePayments.ProcessBlock(GetHeight()+10);
        }

    }

    if (!fReindex && !fImporting)
    {
        // Quickly download the rest of chain from other peers
        // Skips downloading orphan chain (Hypersync)
        if (GetBoolArg("-hypersync", false) == true)
        {
            if (fForceSyncAfterOrphan > DEFAULT_MAX_ORPHAN_BLOCKS)
            {
                CChain::ForceSync(pfrom, hash);

                fForceSyncAfterOrphan = fForceSyncAfterOrphan + 1;
            }
            else
            {
                fForceSyncAfterOrphan = 0;
            }
        }
        else if (GetBoolArg("-randomsync", false) == true)
        {
            // Force Random Sync with 3 connected nodes, filter nodes with orphan hash checkpoint
            CChain::ForceRandomSync(pfrom, hash, 3);
        }
    }

    if(fDebug)
    {
        LogPrint("core", "%s : OK - ACCEPTED Block: %s", __FUNCTION__, hash.ToString());
    }

    // Block processed and written to disk
    return true;
}

#ifdef ENABLE_WALLET
// novacoin: attempt to generate suitable proof-of-stake
bool CBlock::SignBlock(CWallet& wallet, int64_t nFees)
{
    // if we are trying to sign something except proof-of-stake block template
    if (!vtx[0].vout[0].IsEmpty())
    {
        if (fDebug)
        {
            LogPrint("mining", "%s : ERROR - Attempted to sign something except proof-of-stake block template \n", __FUNCTION__);
        }

        return false;
    }

    // if we are trying to sign a complete proof-of-stake block
    if (IsProofOfStake())
    {
        if (fDebug)
        {
            LogPrint("mining", "%s : ERROR - Attempted to sign something except proof-of-stake block template \n", __FUNCTION__);
        }

        return true;
    }

    if (vNodes.size() == 0)
    {
        if (fDebug)
        {
            LogPrint("mining", "%s : ERROR - Your wallet needs to be connected to peers \n", __FUNCTION__);
        }

        return false;
    }

    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime(); // startup timestamp

    CKey key;
    CTransaction txCoinStake;

    txCoinStake.nTime &= ~STAKE_TIMESTAMP_MASK;

    int64_t nSearchTime = txCoinStake.nTime; // search to current time

    if (nSearchTime > nLastCoinStakeSearchTime)
    {
        int64_t nSearchInterval = 1;

        if (wallet.CreateCoinStake(wallet, nBits, nSearchInterval, nFees, txCoinStake, key))
        {
            if (txCoinStake.nTime >= pindexBest->GetPastTimeLimit()+1)
            {
                // make sure coinstake would meet timestamp protocol as it would be the same as the block timestamp
                vtx[0].nTime = nTime = txCoinStake.nTime;

                // we have to make sure that we have no future timestamps in our transactions set
                for (vector<CTransaction>::iterator it = vtx.begin(); it != vtx.end();)
                {
                    if (it->nTime > nTime)
                    {
                        it = vtx.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }

                vtx.insert(vtx.begin() + 1, txCoinStake);
                hashMerkleRoot = BuildMerkleTree();

                if (fDebug)
                {
                    LogPrint("mining", "%s : OK - Block signed! \n", __FUNCTION__);
                }

                // append a signature to our block
                return key.Sign(GetHash(), vchBlockSig);
            }
        }

        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
        nLastCoinStakeSearchTime = nSearchTime;
    }

    if (fDebug)
    {
        LogPrint("mining", "%s : ERROR - Block signing failure \n", __FUNCTION__);
    }

    return false;
}
#endif


bool CBlock::CheckBlockSignature() const
{
    if (IsProofOfWork())
    {
        return vchBlockSig.empty();
    }

    if (vchBlockSig.empty())
    {
        return false;
    }

    vector<valtype> vSolutions;
    txnouttype whichType;

    const CTxOut& txout = vtx[1].vout[1];

    if (!Solver(txout.scriptPubKey, whichType, vSolutions))
    {
        return false;
    }

    if (whichType == TX_PUBKEY)
    {
        valtype& vchPubKey = vSolutions[0];

        return CPubKey(vchPubKey).Verify(GetHash(), vchBlockSig);
    }

    return false;
}


bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = filesystem::space(GetDataDir(true)).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        string strMessage = _("Error: Disk space is low!");
        strMiscWarning = strMessage;

        if(fDebug)
        {
            LogPrint("core", "%s : ERROR - *** %s \n", __FUNCTION__, strMessage);
        }

        uiInterface.ThreadSafeMessageBox(strMessage, "", CClientUIInterface::MSG_ERROR);

        StartShutdown();

        return false;
    }

    return true;
}


static filesystem::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);

    return GetDataDir(true) / strBlockFn;
}


FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1)
        || (nFile == (unsigned int) -1))
    {
        return NULL;
    }

    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
    {
        return NULL;
    }

    if (nBlockPos != 0
        && !strchr(pszMode, 'a')
        && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);

            return NULL;
        }
    }

    return file;
}


static unsigned int nCurrentBlockFile = 1;


FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;

    while (true)
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");

        if (!file)
        {
            return NULL;
        }

        if (fseek(file, 0, SEEK_END) != 0)
        {
            return NULL;
        }

        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;

            return file;
        }

        fclose(file);

        nCurrentBlockFile++;
    }
}


bool LoadBlockIndex()
{
    LOCK(cs_main);

    //
    // Load block index
    //
    CTxDB txdb("cr+");

    if (!txdb.LoadBlockIndex())
    {
        return error("%s : ERROR - Txdb.LoadBlockIndex Failed", __FUNCTION__);
    }

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        CBlock &block = const_cast<CBlock&>(Params().GenesisBlock());

        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        
        if (!block.WriteToDisk(nFile, nBlockPos))
        {
            return error("%s : ERROR - Writing genesis block to disk failed", __FUNCTION__);
        }
        
        if (!block.AddToBlockIndex(nFile, nBlockPos, Params().HashGenesisBlock()))
        {
            return error("%s : ERROR - Genesis block not accepted", __FUNCTION__);
        }

    }

    return true;
}


void PrintBlockTree()
{
    if(!fDebug)
    {
        return;
    }

    AssertLockHeld(cs_main);

    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;

    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;

        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;

    while (!vStack.empty())
    {
        int nCol = vStack.back().first;

        CBlockIndex* pindex = vStack.back().second;

        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
            {
                LogPrint("blocktree", "| ");
            }

            LogPrint("blocktree", "|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
            {
                LogPrint("blocktree", "| ");
            }

            LogPrint("blocktree", "|\n");
        }
        
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
        {
            LogPrint("blocktree", "| ");
        }

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);

#ifndef LOWMEM
        LogPrint("blocktree", "%d (%u,%u) %s  %08x  %s  POWmint %7s POSmint %7s tx %u",
#else
        LogPrint("blocktree", "%d (%u,%u) %s  %08x  %s  tx %u",
#endif        
        pindex->nHeight, pindex->nFile, pindex->nBlockPos, block.GetHash().ToString(), block.nBits, DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()),
#ifndef LOWMEM
        FormatMoney(pindex->nPOWMint), FormatMoney(pindex->nPOSMint),
#endif            
        block.vtx.size());

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);

                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            vStack.push_back(make_pair(nCol+i, vNext[i]));
        }

    }
}


bool LoadExternalBlockFile(FILE* fileIn)
{
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        try
        {
            CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);

            unsigned int nPos = 0;

            while (nPos != (unsigned int)-1 && blkdat.good())
            {
                boost::this_thread::interruption_point();

                unsigned char pchData[65536];

                do
                {
                    fseek(blkdat.Get(), nPos, SEEK_SET);

                    int nRead = fread(pchData, 1, sizeof(pchData), blkdat.Get());

                    if (nRead <= 8)
                    {
                        nPos = (unsigned int)-1;
                        break;
                    }

                    void* nFind = memchr(pchData, Params().MessageStart()[0], nRead+1-MESSAGE_START_SIZE);

                    if (nFind)
                    {
                        if (memcmp(nFind, Params().MessageStart(), MESSAGE_START_SIZE) == 0)
                        {
                            nPos += ((unsigned char*)nFind - pchData) + MESSAGE_START_SIZE;

                            break;
                        }

                        nPos += ((unsigned char*)nFind - pchData) + 1;
                    }
                    else
                    {
                        nPos += sizeof(pchData) - MESSAGE_START_SIZE + 1;
                    }

                    boost::this_thread::interruption_point();
                }
                while(true);
                
                if (nPos == (unsigned int)-1)
                {
                    break;
                }

                fseek(blkdat.Get(), nPos, SEEK_SET);

                unsigned int nSize;
                blkdat >> nSize;

                if (nSize > 0 && nSize <= MAX_BLOCK_SIZE)
                {
                    CBlock block;
                    blkdat >> block;

                    LOCK(cs_main);

                    if (ProcessBlock(NULL,&block))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (std::exception &e)
        {
            if (fDebug)
            {
                LogPrint("core", "%s : ERROR - Deserialize or I/O error caught during load\n", __FUNCTION__);
            }
        }
    }

    if (fDebug)
    {
        LogPrint("core", "%s : ERROR - Loaded %i blocks from external file in %dms\n", __FUNCTION__, nLoaded, GetTimeMillis() - nStart);
    }

    return nLoaded > 0;
}


struct CImportingNow
{
    CImportingNow()
    {
        if (fImporting == true)
        {
            LogPrint("core", "%s : NOTICE - fImporting == true\n", __FUNCTION__);
        }
        else
        {
            fImporting = true;
        }
    }

    ~CImportingNow()
    {
        if (fImporting == false)
        {
            LogPrint("core", "%s : NOTICE - fImporting == false\n", __FUNCTION__);
        }
        else
        {
            fImporting = false;
        }
    }
};


void ThreadImport(std::vector<boost::filesystem::path> vImportFiles)
{
    RenameThread("PHC-loadblk");

    CImportingNow imp;

    // -loadblock=
    for(boost::filesystem::path &path: vImportFiles)
    {
        FILE *file = fopen(path.string().c_str(), "rb");
        if (file)
        {
            LoadExternalBlockFile(file);
        }
    }

    // hardcoded $DATADIR/bootstrap.dat
    filesystem::path pathBootstrap = GetDataDir(true) / "bootstrap.dat";

    if (filesystem::exists(pathBootstrap))
    {
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");

        if (file)
        {
            filesystem::path pathBootstrapOld = GetDataDir(true) / "bootstrap.dat.old";

            LoadExternalBlockFile(file);

            RenameOver(pathBootstrap, pathBootstrapOld);
        }
    }
}


//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;


string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode", false))
    {
        strRPC = "test";
    }

    if (!CLIENT_VERSION_IS_RELEASE)
    {
        strStatusBar = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");
    }

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // Global Namespace Start
    {
        // Alerts
        LOCK(cs_mapAlerts);
        
        for(PAIRTYPE(const uint256, CAlert)& item: mapAlerts)
        {
            const CAlert& alert = item.second;

            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;

                if (nPriority > 1000)
                {
                    strRPC = strStatusBar;
                }
            }
        }
    }
    // Global Namespace End

    if (strFor == "statusbar")
    {
        return strStatusBar;
    }
    else if (strFor == "rpc")
    {
        return strRPC;
    }

    return strprintf("%s : NOTICE - GetWarnings() : invalid parameter", __FUNCTION__);
}


//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

bool static AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
        case MSG_DSTX:
        {
            return mapDarksendBroadcastTxes.count(inv.hash);
        }

        case MSG_TX:
        {
            bool txInMap = false;
            txInMap = mempool.exists(inv.hash);

            return txInMap
                || mapOrphanTransactions.count(inv.hash)
                || txdb.ContainsTx(inv.hash);
        }

        case MSG_BLOCK:
        {
            return mapBlockIndex.count(inv.hash)
                || mapOrphanBlocks.count(inv.hash);
        }

        case MSG_TXLOCK_REQUEST:
        {
            return mapTxLockReq.count(inv.hash)
                || mapTxLockReqRejected.count(inv.hash);
        }

        case MSG_TXLOCK_VOTE:
        {
            return mapTxLockVote.count(inv.hash);
        }

        case MSG_SPORK:
        {
            return mapSporks.count(inv.hash);
        }

        case MSG_MASTERNODE_WINNER:
        {
            return mapSeenMasternodeVotes.count(inv.hash);
        }
    }

    // Don't know what it is, just say we already got one
    return true;
}


void static ProcessGetData(CNode* pfrom)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    LOCK(cs_main);

    while (it != pfrom->vRecvGetData.end())
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
        {
            break;
        }

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BLOCK
                || inv.type == MSG_FILTERED_BLOCK)
            {
                if (IsInitialBlockDownload() == false
                    && fImporting == false
                    && fReindex == false)
                {
                    // Send block from disk
                    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                    
                    if (mi != mapBlockIndex.end())
                    {
                        CBlock block;

                        block.ReadFromDisk((*mi).second);
                        pfrom->PushMessage("block", block);

                        // Trigger them to send a getblocks request for the next batch of inventory
                        if (inv.hash == pfrom->hashContinue)
                        {
                            // Bypass PushInventory, this must send even if redundant,
                            // and we want it right after the last block so they don't
                            // wait for other stuff first.
                            vector<CInv> vInv;

                            vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
                            pfrom->PushMessage("inv", vInv);

                            pfrom->hashContinue = 0;
                        }
                    }

                    pfrom->hashContinue = 0;
                }
            }
            else if (inv.IsKnownType())
            {
                if(fDebug)
                {
                    LogPrint("core", "%s : Starting \n", __FUNCTION__);
                }

                // Send stream from relay memory
                bool pushed = false;
                /*{
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        if(fDebug) 
                        {
                            LogPrint("net", "%s : pushed = true Rest will fail \n", __FUNCTION__);
                        }
                        pushed = true;
                    }
                }*/

                if (!pushed
                    && inv.type == MSG_TX)
                {

                    CTransaction tx;

                    if (mempool.lookup(inv.hash, tx))
                    {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

                        ss.reserve(GetMaxAddrBandwidth(pfrom->nTurboSync));

                        ss << tx;

                        pfrom->PushMessage("tx", ss);

                        pushed = true;
                    }
                }

                if (!pushed
                    && inv.type == MSG_TXLOCK_VOTE)
                {
                    if(mapTxLockVote.count(inv.hash))
                    {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

                        ss.reserve(GetMaxAddrBandwidth(pfrom->nTurboSync));

                        ss << mapTxLockVote[inv.hash];

                        pfrom->PushMessage("txlvote", ss);

                        pushed = true;
                    }
                }

                if (!pushed
                    && inv.type == MSG_TXLOCK_REQUEST)
                {
                    if(mapTxLockReq.count(inv.hash))
                    {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

                        ss.reserve(GetMaxAddrBandwidth(pfrom->nTurboSync));

                        ss << mapTxLockReq[inv.hash];

                        pfrom->PushMessage("txlreq", ss);

                        pushed = true;
                    }
                }

                if (!pushed
                    && inv.type == MSG_SPORK)
                {
                    if(mapSporks.count(inv.hash))
                    {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

                        ss.reserve(GetMaxAddrBandwidth(pfrom->nTurboSync));

                        ss << mapSporks[inv.hash];

                        pfrom->PushMessage("spork", ss);

                        pushed = true;
                    }
                }

                if (!pushed
                    && inv.type == MSG_MASTERNODE_WINNER)
                {
                    if(mapSeenMasternodeVotes.count(inv.hash))
                    {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

                        ss.reserve(GetMaxAddrBandwidth(pfrom->nTurboSync));

                        ss << mapSeenMasternodeVotes[inv.hash];

                        pfrom->PushMessage("mnw", ss);

                        pushed = true;
                    }
                }

                if (!pushed
                    && inv.type == MSG_DSTX)
                {
                    if(mapDarksendBroadcastTxes.count(inv.hash))
                    {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

                        ss.reserve(GetMaxAddrBandwidth(pfrom->nTurboSync));
                        ss <<
                            mapDarksendBroadcastTxes[inv.hash].tx <<
                            mapDarksendBroadcastTxes[inv.hash].vin <<
                            mapDarksendBroadcastTxes[inv.hash].vchSig <<
                            mapDarksendBroadcastTxes[inv.hash].sigTime;

                        pfrom->PushMessage("dstx", ss);

                        pushed = true;
                    }
                }

                if (!pushed)
                {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            g_signals.Inventory(inv.hash);

            if (inv.type == MSG_BLOCK 
                || inv.type == MSG_FILTERED_BLOCK)
            {
                break;
            }

        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty())
    {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage("notfound", vNotFound);
    }
}


bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    RandAddSeedPerfmon();

    if(fDebug)
    {
        LogPrint("net", "%s : NOTICE - Received: %s (%u bytes) \n", __FUNCTION__, strCommand, vRecv.size());
    }

    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        if(fDebug)
        {
            LogPrint("net", "%s : WARNING - Dropmessagestest DROPPING RECV MESSAGE \n", __FUNCTION__);
        }

        return true;
    }


    /////////////////////
    //
    // Get Message: version
    //
    else if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            Misbehaving(pfrom->GetId(), 1);

            if (fDebug)
            {
                LogPrint("net", "%s : NOTICE - Peer %s banned for sending version command after received version %i; disconnecting \n", __FUNCTION__, pfrom->addr.ToStringIPPort(), pfrom->nVersion);
            }

            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;

        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            if(fDebug)
            {
                LogPrint("net", "%s : NOTICE - Partner %s using obsolete version %i; disconnecting \n", __FUNCTION__, pfrom->addr.ToStringIPPort(), pfrom->nVersion);
            }

            pfrom->fDisconnect = true;
            
            return false;
        }

        if (pfrom->nVersion == 10300)
        {
            pfrom->nVersion = 300;
        }

        if (!vRecv.empty())
        {
            vRecv >> addrFrom >> nNonce;
        }

        if (!vRecv.empty())
        {
            vRecv >> pfrom->strSubVer;
            pfrom->cleanSubVer = SanitizeString(pfrom->strSubVer);
        }

        if (!vRecv.empty())
        {
            vRecv >> pfrom->nStartingHeight;
        }

        if (!vRecv.empty())
            pfrom->fRelayTxes = true;

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            if(fDebug)
            {
                LogPrint("net", "%s : NOTICE - Connected to self at %s, disconnecting \n", __FUNCTION__, pfrom->addr.ToStringIPPort());
            }
            
            pfrom->fDisconnect = true;
            
            return true;
        }

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
        {
            pfrom->PushVersion();
        }

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);

                if (addr.IsRoutable())
                {
                    pfrom->PushAddress(addr);
                }
                else if (IsPeerAddrLocalGood(pfrom))
                {
                    addr.SetIP(pfrom->addrLocal);
                    pfrom->PushAddress(addr);
                }
            }

            // Get recent addresses
            if (pfrom->fOneShot
                || pfrom->nVersion >= CADDR_TIME_VERSION
                || (signed)addrman.size() < (signed)GetMaxAddrBandwidth(pfrom->nTurboSync))
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }

            addrman.Good(pfrom->addr);
        }
        else
        {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Global Namespace Start
        {
            // Relay alerts
            LOCK(cs_mapAlerts);

            for(PAIRTYPE(const uint256, CAlert)& item: mapAlerts)
            {
                item.second.RelayTo(pfrom);
            }

        }
        // Global Namespace End

        pfrom->fSuccessfullyConnected = true;

        if(fDebug)
        {
            LogPrint("net", "%s : NOTICE - Receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", __FUNCTION__, pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString(), addrFrom.ToString(), pfrom->addr.ToStringIPPort());
        }

        if (GetBoolArg("-synctime", true))
        {
            AddTimeData(pfrom->addr, nTime);
        }
    }


    /////////////////////
    //
    // Get Message: getaddr
    //
    else if ((strCommand == "getaddr")
        && (pfrom->fInbound))
    {
        // This asymmetric behavior for inbound and outbound connections was introduced
        // to prevent a fingerprinting attack: an attacker can send specific fake addresses
        // to users' AddrMan and later request them by sending getaddr messages.
        // Making users (which are behind NAT and can only make outgoing connections) ignore
        // getaddr message mitigates the attack.

        // Don't return addresses older than nCutOff timestamp
        int64_t nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);
        pfrom->vAddrToSend.clear();

        vector<CAddress> vAddr = addrman.GetAddr();

        for(const CAddress &addr: vAddr)
        {
            if(addr.nTime > nCutOff)
            {
                pfrom->PushAddress(addr);
            }
        }
    }

    /////////////////////
    //
    // Get Message: mempool
    //
    else if (strCommand == "mempool")
    {
        LOCK(cs_main);

        std::vector<uint256> vtxid;

        mempool.queryHashes(vtxid);

        vector<CInv> vInv;
        CInv inv;

        for (unsigned int i = 0; i < vtxid.size(); i++)
        {
            inv = CInv(MSG_TX, vtxid[i]);
            vInv.push_back(inv);

            if (i == (MAX_INV_SZ - 1))
            {
                break;
            }
        }

        if (vInv.size() > 0)
        {
            pfrom->PushMessage("inv", vInv);
        }

    }

    /////////////////////
    //
    // Get Message: ping
    //
    else if (strCommand == "ping")
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64_t nonce = 0;
            vRecv >> nonce;

            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }

    /////////////////////
    //
    // Get Message: pong
    //
    else if (strCommand == "pong")
    {
        int64_t pingUsecEnd = GetTimeMicros();
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();

        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce))
        {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0)
            {
                if (nonce == pfrom->nPingNonceSent)
                {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;

                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;

                    if (pingUsecTime > 0)
                    {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                    }
                    else
                    {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                }
                else
                {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";

                    if (nonce == 0)
                    {
                        // This is most likely a bug in another implementation somewhere, cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            }
            else
            {
                sProblem = "Unsolicited pong without ping";
            }
        }
        else
        {
            // This is most likely a bug in another implementation somewhere, cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty()))
        {
            if(fDebug)
            {
                LogPrint("net", "%s : ERROR - pong %s %s: %s, %x expected, %x received, %zu bytes \n", __FUNCTION__, pfrom->addr.ToStringIPPort(), pfrom->strSubVer, sProblem, pfrom->nPingNonceSent, nonce, nAvail);
            }
        }

        if (bPingFinished)
        {
            pfrom->nPingNonceSent = 0;
        }
    }

    /////////////////////
    //
    // Get Message: alert
    //
    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();

        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);

                    for(CNode* pnode: vNodes)
                    {
                        alert.RelayTo(pnode);
                    }
                }
            }
            else
            {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                Misbehaving(pfrom->GetId(), 10);
            }
        }
    }

    /////////////////////
    //
    // Get Message: getdata
    //
    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;

        if (vInv.size() > MAX_INV_SZ)
        {
            Misbehaving(pfrom->GetId(), 20);

            return error("%s : ERROR - Message getdata size() = %u", __FUNCTION__, vInv.size());
        }

        if (fDebug
            || (vInv.size() != 1))
        {
            LogPrint("net", "%s : NOTICE - Received getdata (%u invsz) \n", __FUNCTION__, vInv.size());
        }

        if ((fDebug
            && vInv.size() > 0)
            || (vInv.size() == 1))
        {
            LogPrint("net", "%s : NOTICE - Received getdata for: %s \n", __FUNCTION__, vInv[0].ToString());
        }

        // Firewall
        // Keep track of received hash from node
        //pfrom->hashReceived = vInv[0].hash;

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());

        ProcessGetData(pfrom);
    }

    /////////////////////
    //
    // Get Message: version = (NULL)
    //
    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        Misbehaving(pfrom->GetId(), 1);

        if(fDebug)
        {
            LogPrint("net", "%s : ERROR - Failed to receive version message from peer: %s (banned)\n", __FUNCTION__, pfrom->addr.ToStringIPPort());
        }

        return false;
    }

    /////////////////////
    //
    // Get Message: verack
    //
    else if (strCommand == "verack")
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }

    /////////////////////
    //
    // Get Message: addr
    //
    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
        {
            return true;
        }

        if ((signed)vAddr.size() > (signed)GetMaxAddrBandwidth(pfrom->nTurboSync))
        {
            Misbehaving(pfrom->GetId(), 20);

            return error("%s : ERROR - Message addr size() = %u", __FUNCTION__, vAddr.size());
        }

        pfrom->nRecvAddrs = vAddr.size();

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;

        for(CAddress& addr: vAddr)
        {
            boost::this_thread::interruption_point();

            if (addr.nTime <= 100000000
                || addr.nTime > nNow + 10 * 60)
            {
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            }

            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);

            if (addr.nTime > nSince
                && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {

                // Global Namespace Start
                {
                    // Relay to a limited number of other nodes
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;

                    if (hashSalt == 0)
                    {
                        hashSalt = GetRandHash();
                    }

                    uint64_t hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;

                    for(CNode* pnode: vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                        {
                            continue;
                        }

                        unsigned int nPointer;

                        memcpy(&nPointer, &pnode, sizeof(nPointer));

                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }

                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)

                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                    {
                        ((*mi).second)->PushAddress(addr);
                    }

                }
                // Global Namespace End
            }

            // Do not store addresses outside our network
            if (fReachable)
            {
                vAddrOk.push_back(addr);
            }
        }

        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);

        if ((signed)vAddr.size() < (signed)GetMaxAddrBandwidth(pfrom->nTurboSync))
        {
            pfrom->fGetAddr = false;
        }

        if (pfrom->fOneShot)
        {
            pfrom->fDisconnect = true;
        }

    }

    /////////////////////
    //
    // Get Message: inv
    //
    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;

        if (vInv.size() > MAX_INV_SZ)
        {
            Misbehaving(pfrom->GetId(), 20);

            return error("%s : ERROR - Message inv size() = %u", __FUNCTION__, vInv.size());
        }

        // find last block in inv vector
        unsigned int nLastBlock = (unsigned int)(-1);
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK)
            {
                nLastBlock = vInv.size() - 1 - nInv;

                break;
            }
        }
        
        LOCK(cs_main);
        CTxDB txdb("r");

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);

            if(fDebug)
            {
                LogPrint("net", "%s : ERROR - Got inventory: %s  %s \n", __FUNCTION__, inv.ToString(), fAlreadyHave ? "have" : "new");
            }

            if (!fAlreadyHave)
            {
                pfrom->AskFor(inv, IsInitialBlockDownload()); // peershares: immediate retry during initial download
            }
            else if (inv.type == MSG_BLOCK
                && mapOrphanBlocks.count(inv.hash))
            {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(inv.hash));
            }
            else if (nInv == nLastBlock)
            {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));

                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - Force request: %s \n", __FUNCTION__, inv.ToString());
                }
            }

            // Track requests for our stuff
            g_signals.Inventory(inv.hash);
        }
    }

    /////////////////////
    //
    // Get Message: block (Legacy sync method)
    //
    else if (strCommand == "block"
        && fImporting == false 
        && fReindex == false) // Ignore blocks received while importing
    {
        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();

        if(fDebug)
        {
            LogPrint("net", "%s : NOTICE - Received block %s \n", __FUNCTION__, hashBlock.ToString());
        }

        LOCK(cs_main);

        CInv inv(MSG_BLOCK, hashBlock);

        // Firewall
        // Keep track of hash received for from node
        //pfrom->hashReceived = inv.hash;

        if (pfrom)
        {
            pfrom->AddInventoryKnown(inv);

            if (ProcessBlock(pfrom, &block))
            {
                mapAlreadyAskedFor.erase(inv);
            }
        }

        if (fSecMsgEnabled)
        {
            SecureMsgScanBlock(block);
        }
    }

    /////////////////////
    //
    // Get Message: getblocks (Legacy Sync Method)
    //
    else if (strCommand == "getblocks"
        && !fImporting
        && !fReindex) // Ignore sending blocks while importing
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        if (IsInitialBlockDownload() == true)
        {
            // Do not send blocks while syncing
            return true;
        }

        CBlockIndex* pindex = NULL;

        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);

            if (mi == mapBlockIndex.end())
            {
                return true;
            }

            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();

            if (pindex)
            {
                pindex = pindex->pnext;
            }
        }

        vector<CBlock> vHeaders;

        int nLimit = 2000;
        
        if(fDebug)
        {
            LogPrint("net", "%s : NOTICE - Getblocks %d to %s \n", __FUNCTION__, (pindex ? pindex->nHeight : -1), hashStop.ToString());
        }

        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlock());

            if (--nLimit <= 0
                || pindex->GetBlockHash() == hashStop)
            {
                break;
            }
        }

        pfrom->PushMessage("blocks", vHeaders);
    }

    /////////////////////
    //
    // Get Message: getheaders (NOT USED)
    //
    else if (strCommand == "getheaders"
        && !fImporting
        && !fReindex) // Ignore sending headers while importing
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        if (IsInitialBlockDownload() == true)
        {
            // Do not send headers while syncing
            return true;
        }

        CBlockIndex* pindex = NULL;

        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);

            if (mi == mapBlockIndex.end())
            {
                return true;
            }

            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();

            if (pindex)
            {
                pindex = pindex->pnext;
            }
        }

        vector<CBlock> vHeaders;

        int nLimit = 2000;
        
        if(fDebug)
        {
            LogPrint("net", "%s : NOTICE - Getheaders %d to %s \n", __FUNCTION__, (pindex ? pindex->nHeight : -1), hashStop.ToString());
        }

        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());

            if (--nLimit <= 0
                || pindex->GetBlockHash() == hashStop)
            {
                break;
            }
        }

        pfrom->PushMessage("headers", vHeaders);
    }

    /////////////////////
    //
    // Get Message: headers (NOT USED)
    //
    else if (strCommand == "headers"
        && !fImporting
        && !fReindex) // Ignore headers received while importing
    {
        std::vector<CBlockHeader> headers;

        // Bypass the normal CBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
        unsigned int nCount = ReadCompactSize(vRecv);

        if (nCount > MAX_HEADERS_RESULTS)
        {
            Misbehaving(pfrom->GetId(), 20);

            return error("headers message size = %u", nCount);
        }

        headers.resize(nCount);
        
        for (unsigned int n = 0; n < nCount; n++)
        {
            vRecv >> headers[n];

            ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
        }

        LOCK(cs_main);

        if (nCount == 0)
        {
            // Nothing interesting. Stop asking this peers for more headers.
            return true;
        }

        CBlockIndex *pindexLast = NULL;
        
        for(const CBlockHeader& header: headers)
        {
            CValidationState state;

            if (pindexLast != NULL && header.hashPrevBlock != pindexLast->GetBlockHash())
            {
                Misbehaving(pfrom->GetId(), 20);

                return error("non-continuous headers sequence");
            }

            /* PHC TO-DO
            if (!AcceptBlockHeader(header, state, &pindexLast))
            {
                int nDoS;

                if (state.IsInvalid(nDoS))
                {
                    return error("invalid header received");
                }
            }
            */
            
        }

        /* PHC TO-DO
        if (pindexLast)
        {
            UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());
        }
        */

        if (nCount == MAX_HEADERS_RESULTS && pindexLast)
        {
            // Headers message had its maximum size; the peer may have more headers.
            // TODO: optimize: if pindexLast is an ancestor of chainActive.Tip or pindexBestHeader, continue
            // from there instead.
            if (fDebug)
            {
                LogPrint("net", "more getheaders (%d) to end to peer=%d (startheight:%d)\n", pindexLast->nHeight, pfrom->id, pfrom->nStartingHeight);
            }

            /* PHC TO-DO
            pfrom->PushMessage("getheaders", chainActive.GetLocator(pindexLast), uint256());
            */
        }

    }

    /////////////////////
    //
    // Get Message: chain
    //
    else if (strCommand == "chain"
        && fImporting == false 
        && fReindex == false) // Ignore blocks received while importing
    {
        std::vector<CBlock> chain;

        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();

        if(fDebug)
        {
            LogPrint("net", "%s : NOTICE - Received chained blocks %s \n", __FUNCTION__, hashBlock.ToString());
        }

        LOCK(cs_main);

        CInv inv(MSG_BLOCK, hashBlock);

        // Firewall
        // Keep track of hash asked for from node
        //pfrom->hashReceived = inv.hash;

        if (pfrom)
        {
            pfrom->AddInventoryKnown(inv);

            if (ProcessBlock(pfrom, &block))
            {
                mapAlreadyAskedFor.erase(inv);
            }
        }

        if (fSecMsgEnabled)
        {
            SecureMsgScanBlock(block);
        }

    }

    /////////////////////
    //
    // Get Message: getchain (NOT USED)
    //
    else if (strCommand == "getchain"
        && !fImporting
        && !fReindex) // Ignore sending chained blocks while importing
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        if (IsInitialBlockDownload() == true)
        {
            // Do not send chained blocks while syncing
            return true;
        }

        CBlockIndex* pindex = NULL;

        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);

            if (mi == mapBlockIndex.end())
            {
                return true;
            }

            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();

            if (pindex)
            {
                pindex = pindex->pnext;
            }
        }

        vector<CBlock> vChain;

        int nLimit = 2000;
        
        if(fDebug)
        {
            LogPrint("net", "%s : NOTICE - Getchain %d to %s \n", __FUNCTION__, (pindex ? pindex->nHeight : -1), hashStop.ToString());
        }

        for (; pindex; pindex = pindex->pnext)
        {
            vChain.push_back(pindex->GetBlock());

            if (--nLimit <= 0
                || pindex->GetBlockHash() == hashStop)
            {
                break;
            }
        }

        pfrom->PushMessage("chain", vChain);
    }

    /////////////////////
    //
    // Get Message: tx or dstx
    //
    else if (strCommand == "tx"
        || strCommand == "dstx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CTransaction tx;

        //masternode signed transaction
        bool ignoreFees = false;

        CTxIn vin;
        CInv inv;

        vector<unsigned char> vchSig;
        int64_t sigTime;
        CTxDB txdb("r");

        if(strCommand == "tx")
        {
            vRecv >> tx;
            inv = CInv(MSG_TX, tx.GetHash());

            // Check for recently rejected (and do other quick existence checks)
            if (AlreadyHave(txdb, inv))
            {
                return true;
            }
        }
        else if (strCommand == "dstx")
        {
            vRecv >> tx >> vin >> vchSig >> sigTime;
            inv = CInv(MSG_DSTX, tx.GetHash());

            // Check for recently rejected (and do other quick existence checks)
            if (AlreadyHave(txdb, inv))
            {
                return true;
            }

            //these allow masternodes to publish a limited amount of free transactions
            CMasternode* pmn = mnodeman.Find(vin);

            if(pmn != NULL)
            {
                if(!pmn->allowFreeTx)
                {
                    //multiple peers can send us a valid masternode transaction
                    if(fDebug)
                    {
                        LogPrint("masternode", "%s : ERROR - Masternode sending too many transactions %s \n", __FUNCTION__, tx.GetHash().ToString().c_str());
                    }

                    return false;
                }

                std::string strMessage = tx.GetHash().ToString() + boost::lexical_cast<std::string>(sigTime);

                std::string errorMessage = "";

                if(!darkSendSigner.VerifyMessage(pmn->pubkey2, vchSig, strMessage, errorMessage))
                {
                    if(fDebug)
                    {
                        LogPrint("masternode", "%s : ERROR - Got bad masternode address signature %s \n", __FUNCTION__, vin.ToString().c_str());
                    }

                    Misbehaving(pfrom->GetId(), 20);
                    
                    return false;
                }

                if(fDebug)
                {
                    LogPrint("masternode", "%s : ERROR - Got Masternode transaction %s \n", __FUNCTION__, tx.GetHash().ToString().c_str());
                }

                ignoreFees = true;
                pmn->allowFreeTx = false;

                if(!mapDarksendBroadcastTxes.count(tx.GetHash()))
                {
                    CDarksendBroadcastTx dstx;
                    
                    dstx.tx = tx;
                    dstx.vin = vin;
                    dstx.vchSig = vchSig;
                    dstx.sigTime = sigTime;

                    mapDarksendBroadcastTxes.insert(make_pair(tx.GetHash(), dstx));
                }
            }
        }

        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);

        bool fMissingInputs = false;

        pfrom->setAskFor.erase(inv.hash);
        mapAlreadyAskedFor.erase(inv);

        if (AcceptToMemoryPool(mempool, tx, true, &fMissingInputs, false, ignoreFees))
        {
            RelayTransaction(tx, inv.hash);
            vWorkQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                map<uint256, set<uint256> >::iterator itByPrev = mapOrphanTransactionsByPrev.find(vWorkQueue[i]);

                if (itByPrev == mapOrphanTransactionsByPrev.end())
                {
                    continue;
                }

                for (set<uint256>::iterator mi = itByPrev->second.begin(); mi != itByPrev->second.end(); ++mi)
                {
                    const uint256& orphanTxHash = *mi;
                    CTransaction& orphanTx = mapOrphanTransactions[orphanTxHash];

                    bool fMissingInputs2 = false;

                    if (AcceptToMemoryPool(mempool, orphanTx, true, &fMissingInputs2))
                    {
                        if(fDebug)
                        {
                            LogPrint("mempool", "%s : NOTICE - Accepted orphan tx %s \n", __FUNCTION__, orphanTxHash.ToString());
                        }

                        RelayTransaction(orphanTx, orphanTxHash);
                        
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // Has inputs but not accepted to mempool
                        // Probably non-standard or insufficient fee/priority
                        vEraseQueue.push_back(orphanTxHash);

                        if(fDebug)
                        {
                            LogPrint("mempool", "%s : NOTICE - Removed orphan tx %s \n", __FUNCTION__, orphanTxHash.ToString());
                        }
                    }
                }
            }

            for(uint256 hash: vEraseQueue)
            {
                EraseOrphanTx(hash);
            }

        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);

            if (nEvicted > 0)
            {
                if(fDebug)
                {   
                    LogPrint("mempool", "%s : NOTICE - MapOrphan overflow, removed %u tx \n", __FUNCTION__, nEvicted);
                }
            }
        }
        
        if(strCommand == "dstx")
        {
            inv = CInv(MSG_DSTX, tx.GetHash());

            RelayInventory(inv);
        }

        if (tx.nDoS)
        {
            Misbehaving(pfrom->GetId(), tx.nDoS);
        }
    }

    /////////////////////
    //
    // Get Message: checkpoint
    //
    else if (strCommand == "checkpoint")
    {
        bool UpdateNodeCheckpoint = false;
       
        if (pfrom->dCheckpointRecv.synced == false
            && pfrom->dCheckpointRecv.timestamp == 0)
        {
            UpdateNodeCheckpoint = true; // Update first time
        }

        if (pfrom->dCheckpointRecv.synced == true)
        {
            if (GetTime() - pfrom->dCheckpointRecv.timestamp > DYNAMICCHECKPOINTS_INTERVAL) // Auto-update
            {
                UpdateNodeCheckpoint = true;
            }
        }

        if (pfrom->nVersion < MIN_PEER_DCHECKPOINTS_VERSION)
        {
            UpdateNodeCheckpoint = false; // Skip sending to older versions
        }

        if (UpdateNodeCheckpoint == true)
        {
            vector<DynamicCheckpoints::Checkpoint> vCheckpoint;

            vRecv >> vCheckpoint;

            if (vCheckpoint.size() > 0)
            {
                if (vCheckpoint[0].height > 0)
                {
                    if (vCheckpoint[0].hash > 0)
                    {
                        // Update Checkpoint to CNode Data Cache
                        pfrom->dCheckpointRecv.height = vCheckpoint[0].height;
                        pfrom->dCheckpointRecv.hash = vCheckpoint[0].hash;
                        pfrom->dCheckpointRecv.timestamp = GetTime();
                        pfrom->dCheckpointRecv.synced = true;
                    }
                }
            }
        }
    }

    /////////////////////
    //
    // Get Message: turbosync
    //
    if (strCommand == "turbosync")
    {
        if (pfrom->nVersion >= MIN_PEER_TURBOSYNC_VERSION)
        {
            int64_t TurboSync = 0;          

            if (!vRecv.empty())
            {
                vRecv >> TurboSync;

                if (TurboSync > TURBOSYNC_MAX)
                {
                    TurboSync = TURBOSYNC_MAX;
                }

                if (TurboSync < 0)
                {
                    TurboSync = 0;
                }

                // Update peer with TurboSyncMax
                pfrom->nTurboSync = TurboSync;
                pfrom->fTurboSyncRecv = true;
            }
        }
    }

    /////////////////////
    //
    // Get Message: unknown
    //
    else
    {
        if (fSecMsgEnabled)
        {
            SecureMsgReceiveData(pfrom, strCommand, vRecv);
        }

        darkSendPool.ProcessMessageDarksend(pfrom, strCommand, vRecv);
        mnodeman.ProcessMessage(pfrom, strCommand, vRecv);

        ProcessMessageMasternodePayments(pfrom, strCommand, vRecv);
        ProcessMessageInstantX(pfrom, strCommand, vRecv);
        ProcessSpork(pfrom, strCommand, vRecv);

        // Ignore unknown commands for extensibility


        // TODO: Invalidpacket count if all above fail
    }

    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
    {
        if (strCommand == "version"
            || strCommand == "addr"
            || strCommand == "inv"
            || strCommand == "getdata"
            || strCommand == "block"
            || strCommand == "checkpoint"
            || strCommand == "ping")
        {
            AddressCurrentlyConnected(pfrom->addr);
        }
    }

    return true;
}


// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom)
{
    //if (fDebug)
    //{
    //    LogPrint("net", "%s : NOTICE - (%zu messages) \n", __FUNCTION__, pfrom->vRecvMsg.size());
    //}

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
    {
        ProcessGetData(pfrom);
    }

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty())
    {
        return fOk;
    }

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();

    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end())
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
        {
            break;
        }

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //{
        //    LogPrint("net", "%s : NOTICE - (message %u msgsz, %zu bytes, complete:%s) \n", __FUNCTION__, msg.hdr.nMessageSize, msg.vRecv.size(), msg.complete() ? "Y" : "N");
        //}

        // end, if an incomplete message is found
        if (!msg.complete())
        {
            break;
        }

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, Params().MessageStart(), MESSAGE_START_SIZE) != 0)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - INVALID MESSAGESTART \n\n", __FUNCTION__);
            }

            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;

        if (!hdr.IsValid())
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - ERRORS IN HEADER %s \n\n\n", __FUNCTION__, hdr.GetCommand());
            }

            continue;
        }

        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);

        unsigned int nChecksum = 0;

        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        
        if (nChecksum != hdr.nChecksum)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - (%s, %u bytes) CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x \n", __FUNCTION__, strCommand, nMessageSize, nChecksum, hdr.nChecksum);
            }

            // Increment this nodes invalid packet count
            pfrom->nInvalidRecvPackets++;

            continue;
        }

        // Process message
        bool fRet = false;

        try
        {
            fRet = ProcessMessage(pfrom, strCommand, vRecv);

            boost::this_thread::interruption_point();
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - (%s, %u bytes) Exception '%s' caught, normally caused by a message being shorter than its stated length \n", __FUNCTION__, strCommand, nMessageSize, e.what());
                }

                // Increment this nodes invalid packet count
                pfrom->nInvalidRecvPackets++;
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                if (fDebug)
                {
                    LogPrint("net", "%s : ERROR - (%s, %u bytes) : Exception '%s' caught \n", __FUNCTION__, strCommand, nMessageSize, e.what());
                }

                // Increment this nodes invalid packet count
                pfrom->nInvalidRecvPackets++;
            }
            else
            {
                PrintExceptionContinue(&e, "Unknown Data Error: ProcessMessage()");
            }
        }
        catch (boost::thread_interrupted)
        {
            throw;
        }
        catch (std::exception& e)
        {
            PrintExceptionContinue(&e, "ProcessMessage()");
        }
        catch (...)
        {
            PrintExceptionContinue(NULL, "Null Error - ProcessMessage()");
        }

        if (!fRet)
        {
            if (fDebug)
            {
                LogPrint("net", "%s : ERROR - (%s, %u bytes) FAILED \n", __FUNCTION__, strCommand, nMessageSize);
            }

            // Increment this nodes invalid packet count
            pfrom->nInvalidRecvPackets++;
        }

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
    {
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);
    }

    return fOk;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    TRY_LOCK(cs_main, lockMain);

    if (lockMain)
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
        {
            return true;
        }

        /////////////////////
        //
        // Send Message: turbosync
        //
        if (pto->nVersion >= MIN_PEER_TURBOSYNC_VERSION)
        {
            if (pto->fTurboSyncSent == false)
            {
                pto->fTurboSyncSent = true;

                pto->PushMessage("turbosync", (int64_t)TURBOSYNC_MAX);
            }
        }

        /////////////////////
        //
        // Send Message: ping
        //
        bool pingSend = false;

        if (pto->fPingQueued)
        {
            // RPC ping request by user
            pingSend = true;
        }

        if (pto->nPingNonceSent == 0
            && pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros())
        {
            // Ping automatically sent as a latency probe & keepalive.
            pingSend = true;
        }

        if (pingSend)
        {
            uint64_t nonce = 0;

            while (nonce == 0)
            {
                GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
            }

            pto->fPingQueued = false;
            pto->nPingUsecStart = GetTimeMicros();
            
            if (pto->nVersion > BIP0031_VERSION)
            {
                pto->nPingNonceSent = nonce;

                pto->PushMessage("ping", nonce);
            }
            else
            {
                // Peer is too old to support ping command with nonce, pong will never arrive.
                pto->nPingNonceSent = 0;

                pto->PushMessage("ping");
            }
        }

        /////////////////////
        //
        // Send Message: getblocks
        //

        TRY_LOCK(cs_main, lockMain); // Acquire cs_main for IsInitialBlockDownload() and CNodeState()
        
        if (!lockMain)
        {
            return true;
        }

        // Start block sync
        if (pto->fSyncNode
            && !fImporting
            && !fReindex)
        {
            pto->PushGetBlocks(pindexBest->pprev, uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBlockDownload())
        {
            ResendWalletTransactions();
        }

        // Address refresh broadcast
        static int64_t nLastRebroadcast;

        if (!IsInitialBlockDownload()
            && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            // Global Namespace Start
            {
                LOCK(cs_vNodes);

                for(CNode* pnode: vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                    {
                        pnode->setAddrKnown.clear();
                    }

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);

                        if (addr.IsRoutable())
                        {
                            pnode->PushAddress(addr);
                        }
                    }
                }
            }
            // Global Namespace End

            nLastRebroadcast = GetTime();
        }

        /////////////////////
        //
        // Send Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;

            vAddr.reserve(pto->vAddrToSend.size());

            for(const CAddress& addr: pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);

                    // receiver rejects addr messages larger than 1000 by default
                    if ((signed)vAddr.size() >= (signed)GetMaxAddrBandwidth(pto->nTurboSync))
                    {
                        pto->PushMessage("addr", vAddr);

                        vAddr.clear();
                    }
                }
            }

            pto->vAddrToSend.clear();

            if (!vAddr.empty())
            {
                pto->PushMessage("addr", vAddr);
            }
        }

        if (State(pto->GetId())->fShouldBan)
        {
            if (pto->addr.IsLocal())
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : WARNING - Not banning local node %s! \n", __FUNCTION__, pto->addr.ToStringIPPort().c_str());
                }
            }
            else
            {
                pto->fDisconnect = true;

                CNode::Ban(pto->addr, BanReasonNodeMisbehaving);
            }

            State(pto->GetId())->fShouldBan = false;
        }


        /////////////////////
        //
        // Send Message: checkpoint
        //

        bool SendCheckpoint = false;

        if (pto->dCheckpointSent.synced == false
            && pto->dCheckpointSent.timestamp == 0)
        {
            SendCheckpoint = true; // First checkpoint send
        }

        if (pto->dCheckpointSent.synced == true)
        {
            if (GetTime() - pto->dCheckpointSent.timestamp > DYNAMICCHECKPOINTS_INTERVAL)
            {
                SendCheckpoint = true; // Auto-resend
            }
        }

        if (pto->nVersion < MIN_PEER_DCHECKPOINTS_VERSION)
        {
            SendCheckpoint = false; // Skip sending to older versions
        }

        if (SendCheckpoint == true)
        {
            if (pindexBest)
            {
                pto->dCheckpointSent.height = pindexBest->nHeight;
                pto->dCheckpointSent.hash = pindexBest->GetBlockHash();
                pto->dCheckpointSent.timestamp = GetTime();
                pto->dCheckpointSent.synced = true;

                vector<DynamicCheckpoints::Checkpoint> vCheckpoint;

                vCheckpoint.push_back(pto->dCheckpointSent);

                if (!vCheckpoint.empty())
                {
                    pto->PushMessage("checkpoint", vCheckpoint);

                    vCheckpoint.clear();
                }
            }
        }


        /////////////////////
        //
        // Send Message: inv
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;

        // Global Namespace Start
        {
            LOCK(pto->cs_inventory);

            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());

            pto->hashAskedFor = uint256(0);
            pto->hashReceived = uint256(0);

            for(const CInv& inv: pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                {
                    continue;
                }

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX
                    && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;

                    if (hashSalt == 0)
                    {
                        hashSalt = GetRandHash();
                    }

                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));

                    bool fTrickleWait = ((hashRand & 3) != 0);

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);

                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);

                    if ((signed)vInv.size() >= (signed)GetMaxAddrBandwidth(pto->nTurboSync))
                    {
                        pto->PushMessage("inv", vInv);

                        // Firewall
                        // Keep track of hash asked for from node
                        pto->hashAskedFor = inv.hash;

                        vInv.clear();
                    }
                }
            }

            pto->vInventoryToSend = vInvWait;
        }
        // Global Namespace End

        if (!vInv.empty())
        {
            pto->PushMessage("inv", vInv);
        }

        /////////////////////
        //
        // Send Message: getdata
        //
        vector<CInv> vGetData;
        int64_t nNow = GetTime() * 1000000;
        
        CTxDB txdb("r");
        
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            
            if (!AlreadyHave(txdb, inv))
            {
                if (fDebug)
                {
                    LogPrint("net", "%s : NOTICE - Sending getdata: %s \n", __FUNCTION__, inv.ToString());
                }

                vGetData.push_back(inv);

                if ((signed)vGetData.size() >= (signed)GetMaxAddrBandwidth(pto->nTurboSync))
                {
                    pto->PushMessage("getdata", vGetData);

                    vGetData.clear();
                }
            }
            else
            {
                //If we're not going to ask, don't expect a response.
                pto->setAskFor.erase(inv.hash);
            }

            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }

        if (!vGetData.empty())
        {
            pto->PushMessage("getdata", vGetData);
        }

        if (fSecMsgEnabled)
        {
            SecureMsgSendData(pto, fSendTrickle); // should be in cs_main?
        }
    }

    return true;
}


int64_t GetMasternodePayment(int nHeight, int64_t blockValue)
{
    int64_t ret = blockValue * 3/4; //75%

	//if(nHeight>53000)
    //       ret = blockValue * 1/10; //10%

    return ret;
}


//////////////////////////////////////////////////////////////////////////////
//
// CChain
//

namespace CChain
{
    int ForceRandomSync(CNode* pfrom, uint256 hashfilter, int maxrandom)
    {
        // ForceSync - Forces random sync of X amount of nodes to resend blocks
        // (C) 2019 Profit Hunters Coin

        if (vNodes.size() < 1)
        {
            // Zero connections available, skip
            return 0;
        }

        int NodeCount = 0;

        int SyncNode = false;

        std::vector<int> NodePos;
        std::vector<int>::iterator it; 

        // select random nodes X times
        for (int i=0; i<maxrandom - 1; i++)
        {
            NodePos.push_back ((rand() % vNodes.size()) + 1);
        }
        
        // look through nodes and see if it should try resync
        // Global Namespace Start
        {
            LOCK(cs_vNodes);

            int tNodePos = 0;

            for(CNode* pnode: vNodes)
            {
                // Enable syncing to to node if different than Node Filter Input
                it = std::find (NodePos.begin(), NodePos.end(), tNodePos); 

                if (it != NodePos.end()
                    && pfrom != pnode) 
                {
                    SyncNode = true;
                }

                // Skip sync to node if it has the Hash Filter in their CheckpointRecv or OrphanRecv buffers
                if (hashfilter != uint256(0))
                {
                    if (pnode->dOrphanRecv.hash == hashfilter
                        || pnode->dCheckpointRecv.hash == hashfilter)
                    {
                        SyncNode = false;
                    }
                }

                if (SyncNode == true)
                {
                    if (pindexBest)
                    {
                        // Start a new fresh sync
                        pnode->PushGetBlocks(pindexBest->pprev, uint256(0));

                        NodeCount++;

                        if(fDebug)
                        {
                            LogPrint("core", "%s : NOTICE - Asking other peer %s for valid chain @ %s \n", __FUNCTION__, pnode->addrName, pindexBest->pprev->GetBlockHash().ToString());
                        }
                    }
                }

                tNodePos++;
            }
        }
        // Global Namespace End

        return NodeCount;
    }

    int ForceSync(CNode* pfrom, uint256 hashfilter)
    {
        // ForceSync - Forces all connected nodes to resend blocks
        // (C) 2019 Profit Hunters Coin

        if (vNodes.size() < 1)
        {
            // Zero connections available, skip
            return 0;
        }

        int NodeCount = 0;

        int SyncNode = false;

        // Global Namespace Start
        {
            LOCK(cs_vNodes);

            for(CNode* pnode: vNodes)
            {
                // Enable syncing to to node if different than Node Filter Input
                if (pfrom != pnode)
                {
                    SyncNode = true;
                }

                // Skip sync to node if it has the Hash Filter in their CheckpointRecv or OrphanRecv buffers
                if (hashfilter != uint256(0))
                {
                    if (pnode->dOrphanRecv.hash == hashfilter
                        || pnode->dCheckpointRecv.hash == hashfilter)
                    {
                        SyncNode = false;
                    }
                }

                if (SyncNode == true)
                {
                    // Start a new fresh sync
                    pnode->PushGetBlocks(pindexBest->pprev, uint256(0));

                    NodeCount++;

                    if(fDebug)
                    {
                        LogPrint("core", "%s : NOTICE - Asking other peer %s for valid chain @ %s \n", __FUNCTION__, pnode->addrName, pindexBest->pprev->GetBlockHash().ToString());
                    }

                    MilliSleep(1200);
                }
            }
        }
        // Global Namespace End

        return NodeCount;
    }


    int BlockBroadCast(CBlock* pblock)
    {
        // BlockBroadCast - Forces block broadcast to all connected nodes
        // (C) 2020 Profit Hunters Coin

        if (vNodes.size() < 1)
        {
            // Zero connections available, skip
            return 0;
        }

        if (IsInitialBlockDownload() == true
            || fImporting == true
            || fReindex == true)
        {
            // Not fully synced
            return 0;
        }

        int NodeCount = 0;

        // Global Namespace Start
        {
            LOCK(cs_vNodes);

            for(CNode* pnode: vNodes)
            {
                // Broadcast Block
                pnode->PushMessage("block", *pblock);

                MilliSleep(1200);

                // Trigger them to send a getblocks request for the next batch of inventory

                // Bypass PushInventory, this must send even if redundant,
                // and we want it right after the last block so they don't
                // wait for other stuff first.
                vector<CInv> vInv;

                vInv.push_back(CInv(MSG_BLOCK, hashBestChain));

                pnode->PushMessage("inv", vInv);

                NodeCount++;

                if(fDebug)
                {
                    LogPrint("core", "%s : NOTICE - Broadcasting block %s to peer %s \n", __FUNCTION__, pblock->GetHash().ToString(), pnode->addrName);
                }

                MilliSleep(1200);
            }
        }
        // Global Namespace End

        return NodeCount;        
    }


    int Backtoblock(int nNewHeight)
    {
        // Backtoblock 1.1 - (C) 2019 TaliumTech & Profit Hunters Coin

        if (nNewHeight < 0)
        {
            if (fDebug)
            {
                LogPrint("core", "%s : ERROR - Block %d not valid \n", nNewHeight);
            }

            return 0;
        }

        CBlockIndex* pindex = pindexBest;

        while (pindex != NULL && pindex->nHeight > nNewHeight)
        {
            pindex->pprev->pnext = NULL;
            pindex = pindex->pprev;
        }

        if (pindex != NULL)
        {
            if (fDebug)
            {
                LogPrint("core", "%s : NOTICE - Back to block index %d \n", __FUNCTION__, nNewHeight);
            }

            CTxDB txdbAddr("rw");

            CBlock block;

            block.ReadFromDisk(pindex);

            block.DisconnectBlock(txdbAddr, pindex);

            block.SetBestChain(txdbAddr, pindex);

            return nNewHeight;
        }

        if (fDebug)
        {
            LogPrint("core",  "%s : NOTICE - Block %d not found \n", __FUNCTION__, nNewHeight);
        }

        return 0;

    }


    int RollbackChain(int nBlockCount)
    {
        // Rollbackchain 1.1 - (C) 2019 Profit Hunters Coin
        // Thanks to TaliumTech for crash fixes

        CBlockIndex* pindex = pindexBest;

        for (int counter = 1; counter != nBlockCount + 1; counter = counter + 1)
        {
            pindex->pprev->pnext = NULL;
            pindex = pindex->pprev;
        }

        if (pindex != NULL)
        {
            if (fDebug)
            {
                LogPrint("core", "%s : NOTICE - Back to block index %d rolled back by: %d blocks \n", __FUNCTION__, pindex->nHeight, nBlockCount);
            }

            CTxDB txdbAddr("rw");

            CBlock block;

            block.ReadFromDisk(pindex);

            block.DisconnectBlock(txdbAddr, pindex);

            block.SetBestChain(txdbAddr, pindex);

            return pindex->nHeight;
        }

        if (fDebug)
        {
            LogPrint("core", "%s : NOTICE - Block %d not found \n",__FUNCTION__, pindex->nHeight);
        }

        return 0;

    }


    // Remove a random orphan block (which does not have any dependent orphans).
    void PruneOrphanBlocks()
    {
        if (mapOrphanBlocksByPrev.size() <= (size_t)std::max((int64_t)0, GetArg("-maxorphanblocks", DEFAULT_MAX_ORPHAN_BLOCKS)))
        {
            return;
        }

        // Pick a random orphan block.
        int pos = insecure_rand() % mapOrphanBlocksByPrev.size();
        std::multimap<uint256, COrphanBlock*>::iterator it = mapOrphanBlocksByPrev.begin();

        while (pos--)
        {
            it++;
        }

        // As long as this block has other orphans depending on it, move to one of those successors.
        do
        {
            std::multimap<uint256, COrphanBlock*>::iterator it2 = mapOrphanBlocksByPrev.find(it->second->hashBlock);

            if (it2 == mapOrphanBlocksByPrev.end())
            {
                break;
            }

            it = it2;
        }
        while(1);

        setStakeSeenOrphan.erase(it->second->stake);
        uint256 hash = it->second->hashBlock;

        delete it->second;
        
        mapOrphanBlocksByPrev.erase(it);
        mapOrphanBlocks.erase(hash);
    }


    bool Reorganize(CTxDB& txdb, CBlockIndex* pindexNew)
    {
        if (fDebug)
        {
            LogPrint("core", "%s : NOTICE - REORGANIZE \n", __FUNCTION__);
        }

        CBlockIndex* pfork;

        if (IsInitialBlockDownload() == true)
        {
            // Find the fork (Step back 5 parent blocks to reduce resource use & increase security)
            pfork = pindexBest->pprev->pprev->pprev->pprev->pprev;
        }
        else
        {
            pfork = pindexBest;
        }

        CBlockIndex* plonger = pindexNew;

        while (pfork != plonger)
        {
            while (plonger->nHeight > pfork->nHeight)
            {
                if (!(plonger = plonger->pprev))
                {
                    return error("%s : ERROR - Plonger->pprev is null", __FUNCTION__);
                }
            }

            if (pfork == plonger)
            {
                break;
            }

            if (!(pfork = pfork->pprev))
            {
                return error("%s : ERROR - Pfork->pprev is null", __FUNCTION__);
            }
        }
        
        // List of what to disconnect
        vector<CBlockIndex*> vDisconnect;

        for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        {
            vDisconnect.push_back(pindex);
        }

        // List of what to connect
        vector<CBlockIndex*> vConnect;

        for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        {
            vConnect.push_back(pindex);
        }

        reverse(vConnect.begin(), vConnect.end());

        if (fDebug)
        {
            LogPrint("core", "%s : NOTICE - Disconnect %u blocks; %s..%s \n", __FUNCTION__, vDisconnect.size(), pfork->GetBlockHash().ToString(), pindexBest->GetBlockHash().ToString());
            LogPrint("core", "%s : NOTICE - Connect %u blocks; %s..%s \n", __FUNCTION__, vConnect.size(), pfork->GetBlockHash().ToString(), pindexNew->GetBlockHash().ToString());
        }

        // Disconnect shorter branch
        list<CTransaction> vResurrect;

        for(CBlockIndex* pindex: vDisconnect)
        {
            CBlock block;

            if (!block.ReadFromDisk(pindex))
            {
                return error("%s : ERROR - ReadFromDisk for disconnect failed", __FUNCTION__);
            }

            if (!block.DisconnectBlock(txdb, pindex))
            {
                return error("%s : ERROR - DisconnectBlock %s failed", __FUNCTION__, pindex->GetBlockHash().ToString());
            }

            // Queue memory transactions to resurrect.
            // We only do this for blocks after the last checkpoint (reorganisation before that
            // point should only happen with -reindex/-loadblock, or a misbehaving peer.
            for(const CTransaction& tx: boost::adaptors::reverse(block.vtx))
            {
                if (!(tx.IsCoinBase()
                    || tx.IsCoinStake())
                    && pindex->nHeight > Checkpoints::GetTotalBlocksEstimate())
                {
                    vResurrect.push_front(tx);
                }
            }
        }

        // Connect longer branch
        vector<CTransaction> vDelete;

        for (unsigned int i = 0; i < vConnect.size(); i++)
        {
            CBlockIndex* pindex = vConnect[i];
            CBlock block;

            if (!block.ReadFromDisk(pindex))
            {
                return error("%s : ERROR - ReadFromDisk for connect failed", __FUNCTION__);
            }

            if (!block.ConnectBlock(txdb, pindex))
            {
                // Invalid block
                return error("%s : ERROR - ConnectBlock %s failed", __FUNCTION__, pindex->GetBlockHash().ToString());
            }

            // Queue memory transactions to delete
            for(const CTransaction& tx: block.vtx)
            {
                vDelete.push_back(tx);
            }
        }

        if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        {
            return error("%s : ERROR - WriteHashBestChain failed", __FUNCTION__);
        }

        // Make sure it's successfully written to disk before changing memory structure
        if (!txdb.TxnCommit())
        {
            return error("%s : ERROR - TxnCommit failed", __FUNCTION__);
        }

        // Disconnect shorter branch
        for(CBlockIndex* pindex: vDisconnect)
        {
            if (pindex->pprev)
            {
                pindex->pprev->pnext = NULL;
            }
        }

        // Connect longer branch
        for(CBlockIndex* pindex: vConnect)
        {
            if (pindex->pprev)
            {
                pindex->pprev->pnext = pindex;
            }
        }

        // Resurrect memory transactions that were in the disconnected branch
        for(CTransaction& tx: vResurrect)
        {
            AcceptToMemoryPool(mempool, tx, false, NULL);
        }

        // Delete redundant memory transactions that are in the connected branch
        for(CTransaction& tx: vDelete)
        {
            mempool.remove(tx);
            mempool.removeConflicts(tx);
        }

        if (fDebug)
        {
            LogPrint("core", "%s : NOTICE - REORGANIZE: done \n", __FUNCTION__);
        }
        
        return true;
    }

}


/* To fix for CBlockHeader upgrade
uint256 CBlockHeader::GetHash() const
{
    //return SerializeHash(*this);
}
*/