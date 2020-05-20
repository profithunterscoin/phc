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


#include "masternode.h"
#include "masternodeman.h"
#include "darksend.h"
#include "core.h"
#include "main.h"
#include "sync.h"
#include "util.h"
#include "addrman.h"
#include <boost/lexical_cast.hpp>

/* ONLY NEEDED FOR UNIT TESTING */
#include <iostream>
using namespace std;

CCriticalSection cs_masternodes;

// keep track of the scanning errors I've seen
map<uint256, int> mapSeenMasternodeScanningErrors;

// cache block hashes as we calculate them
std::map<int64_t, uint256> mapCacheBlockHashes;

struct CompareValueOnly
{
    bool operator()(const pair<int64_t, CTxIn>& t1, const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};


//Get the last hash that matches the modulus given. Processed in reverse order
bool GetBlockHash(uint256& hash, int nBlockHeight)
{
    if (pindexBest == NULL)
    {
        return false;
    }

    if(nBlockHeight == 0)
    {
        nBlockHeight = pindexBest->nHeight;
    }

    if(mapCacheBlockHashes.count(nBlockHeight))
    {
        hash = mapCacheBlockHashes[nBlockHeight];

        return true;
    }

    const CBlockIndex *BlockLastSolved = pindexBest;
    const CBlockIndex *BlockReading = pindexBest;

    if (BlockLastSolved == NULL 
        || BlockLastSolved->nHeight == 0
        || pindexBest->nHeight+1 < nBlockHeight)
    {
        return false;
    }

    int nBlocksAgo = 0;

    if(nBlockHeight > 0)
    {
        nBlocksAgo = (pindexBest->nHeight+1)-nBlockHeight;
    }

    if (nBlocksAgo < 0)
    {
        if (fDebug)
        {
            LogPrint("masternode", "%s : ERROR - nBlocksAgo < 0 \n", __FUNCTION__);
        }

        return false;
    }

    int n = 0;

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++)
    {
        if(n >= nBlocksAgo)
        {
            hash = BlockReading->GetBlockHash();

            mapCacheBlockHashes[nBlockHeight] = hash;
        
            return true;
        }

        n++;

        if (BlockReading->pprev == NULL)
        {
            if (BlockReading == 0)
            {
                if (fDebug)
                {
                    LogPrint("masternode", "%s : ERROR - BlockReading = 0 \n", __FUNCTION__);
                }

                return false;
            }
            
            break;
        }
        
        BlockReading = BlockReading->pprev;
    }

    return false;
}


CMasternode::CMasternode()
{
    LOCK(cs);

    vin = CTxIn();
    addr = CService();
    pubkey = CPubKey();
    pubkey2 = CPubKey();
    sig = std::vector<unsigned char>();
    activeState = MASTERNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastDseep = 0;
    lastTimeSeen = 0;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = PROTOCOL_VERSION;
    nLastDsq = 0;
    rewardAddress = CScript();
    rewardPercentage = 0;
    nVote = 0;
    lastVote = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    
    //mark last paid as current for new entries
    nLastPaid = GetAdjustedTime();

    isPortOpen = false;
    isOldNode = true;
}


CMasternode::CMasternode(const CMasternode& other)
{
    LOCK(cs);

    vin = other.vin;
    addr = other.addr;
    pubkey = other.pubkey;
    pubkey2 = other.pubkey2;
    sig = other.sig;
    activeState = other.activeState;
    sigTime = other.sigTime;
    lastDseep = other.lastDseep;
    lastTimeSeen = other.lastTimeSeen;
    cacheInputAge = other.cacheInputAge;
    cacheInputAgeBlock = other.cacheInputAgeBlock;
    unitTest = other.unitTest;
    allowFreeTx = other.allowFreeTx;
    protocolVersion = other.protocolVersion;
    nLastDsq = other.nLastDsq;
    rewardAddress = other.rewardAddress;
    rewardPercentage = other.rewardPercentage;
    nVote = other.nVote;
    lastVote = other.lastVote;
    nScanningErrorCount = other.nScanningErrorCount;
    nLastScanningErrorBlockHeight = other.nLastScanningErrorBlockHeight;
    nLastPaid = other.nLastPaid;
    nLastPaid = GetAdjustedTime();
    isPortOpen = other.isPortOpen;
    isOldNode = other.isOldNode;
}


CMasternode::CMasternode(CService newAddr, CTxIn newVin, CPubKey newPubkey, std::vector<unsigned char> newSig, int64_t newSigTime, CPubKey newPubkey2, int protocolVersionIn, CScript newRewardAddress, int newRewardPercentage)
{
    LOCK(cs);

    vin = newVin;
    addr = newAddr;
    pubkey = newPubkey;
    pubkey2 = newPubkey2;
    sig = newSig;
    activeState = MASTERNODE_ENABLED;
    sigTime = newSigTime;
    lastDseep = 0;
    lastTimeSeen = 0;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = protocolVersionIn;
    nLastDsq = 0;
    rewardAddress = newRewardAddress;
    rewardPercentage = newRewardPercentage;
    nVote = 0;
    lastVote = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    isPortOpen = false;
    isOldNode = true;
}


//
// Deterministically calculate a given "score" for a masternode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
uint256 CMasternode::CalculateScore(int mod, int64_t nBlockHeight)
{
    if(pindexBest == NULL)
    {
        return 0;
    }

    uint256 hash = 0;
    uint256 aux = vin.prevout.hash + vin.prevout.n;

    if(!GetBlockHash(hash, nBlockHeight))
    {
        return 0;
    }

    uint256 hash2 = Hash(BEGIN(hash), END(hash));
    uint256 hash3 = Hash(BEGIN(hash), END(hash), BEGIN(aux), END(aux));

    uint256 r = (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);

    return r;
}


void CMasternode::Check()
{
    if(ShutdownRequested())
    {
        return;
    }

    //TODO: Random segfault with this line removed
    TRY_LOCK(cs_main, lockRecv);

    if(!lockRecv)
    {
        return;
    }

    //once spent, stop doing the checks
    if(activeState == MASTERNODE_VIN_SPENT)
    {
        return;
    }

    if(!UpdatedWithin(MASTERNODE_REMOVAL_SECONDS))
    {
        activeState = MASTERNODE_REMOVE;

        return;
    }

    if(!UpdatedWithin(MASTERNODE_EXPIRATION_SECONDS))
    {
        activeState = MASTERNODE_EXPIRED;

        return;
    }

    if(!unitTest)
    {
        CValidationState state;
        CTransaction tx = CTransaction();
        CTxOut vout = CTxOut((GetMNCollateral(pindexBest->nHeight)-1)*COIN, darkSendPool.collateralPubKey);
        
        tx.vin.push_back(vin);
        tx.vout.push_back(vout);

	    if(!AcceptableInputs(mempool, tx, false, NULL))
        {
            activeState = MASTERNODE_VIN_SPENT;
        
            return;
        }
    }

    addrman.Add(CAddress(addr), addr, 2*60*60);

    LOCK(cs_vNodes);

    bool node_found = false;

    // Check for peer connection
    for(CNode* pnode: vNodes)
    {
        if (pnode->addr.ToStringIP() == addr.ToStringIP())
        {   
            node_found = true;

            // OK
            isPortOpen = true;
            activeState = MASTERNODE_ENABLED;

            return;
        }
        
        node_found = false;
    }

    if (node_found == false)
    {
        activeState = MASTERNODE_UNREACHABLE;

        return;
    }

    // Test Node for incoming connectivity (minimum requirements for active masternode status)
    if (!CheckNode((CAddress)addr))
    {
        isPortOpen = false;
        activeState = MASTERNODE_UNREACHABLE;

        return;
    }

    // OK
    isPortOpen = true;
    activeState = MASTERNODE_ENABLED;
}