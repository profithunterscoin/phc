// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (C) 2017-2018 Crypostle Core developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#include "txdb.h"
#include "main.h"
#include "miner.h"
#include "kernel.h"
#include "masternodeman.h"
#include "masternode-payments.h"
#include "consensus.h"

#include "arith_uint256.h"

#include <string>

using namespace std;

bool fGenerating;
int GenerateProcLimit;

bool fStaking;

extern unsigned int nMinerSleep;

static const unsigned int pSHA256InitState[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
int64_t nLastCoinStakeSearchInterval = 0;

// LogCache for Miner
std::string MinerLogCache;

// Log for InternalStakeMiner
int LastBlockStake;
int LastBlockStakeTime;

//////////////////////////////////////////////////////////////////////////////
//
// Miner Functions
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;

    memset(pdata + len, 0, 64 * blocks - len);

    pdata[len] = 0x80;

    unsigned int bits = len * 8;

    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;

    return blocks;
}


void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;

    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
    {
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);
    }

    for (int i = 0; i < 8; i++)
    {
        ctx.h[i] = ((uint32_t*)pinit)[i];
    }

    SHA256_Update(&ctx, data, sizeof(data));

    for (int i = 0; i < 8; i++)
    {
        ((uint32_t*)pstate)[i] = ctx.h[i];
    }
}


// Some explaining would be appreciated
class COrphan
{
    public:

        CTransaction* ptx;
        set<uint256> setDependsOn;

        double dPriority;
        double dFeePerKb;

        COrphan(CTransaction* ptxIn)
        {
            ptx = ptxIn;
            dPriority = 0;
            dFeePerKb = 0;
        }
};


class TxPriorityCompare
{
    bool byFee;

    public:

        TxPriorityCompare(bool _byFee) : byFee(_byFee)
        { }
        
        bool operator()(const TxPriority& a, const TxPriority& b)
        {
            if (byFee)
            {
                if (a.get<1>() == b.get<1>())
                {
                    return a.get<0>() < b.get<0>();
                }

                return a.get<1>() < b.get<1>();
            }
            else
            {
                if (a.get<0>() == b.get<0>())
                {
                    return a.get<1>() < b.get<1>();
                }

                return a.get<0>() < b.get<0>();
            }
        }
};


CBlock* CreateNewBlockWithKey(CReserveKey& reservekey, CWallet *pwallet)
{
    if (IsInitialBlockDownload()
        || fReindex
        || fImporting)
    {
        return NULL;
    }

    int64_t pFees = 0;

    CPubKey pubkey;

    if (!reservekey.GetReservedKey(pubkey))
    {
        return NULL;
    }

    CScript scriptPubKey = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;

    // Create new block
    unique_ptr<CBlock> pblock(new CBlock());

    if (!pblock.get())
    {
        return NULL;
    }

    CBlockIndex* pindexPrev = pindexBest;
    int nHeight = pindexPrev->nHeight + 1;

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);

    txNew.vout[0].scriptPubKey = scriptPubKey;


    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);

    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64_t nMinTxFee = MIN_TX_FEE;

    if (mapArgs.count("-mintxfee"))
    {
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);
    }

    pblock->nBits = GetNextTargetRequired(pindexPrev, false);

    // Collect memory pool transactions into the block
    int64_t nFees = 0;

    // Global Namespace Start
    {
        LOCK2(cs_main, mempool.cs);

        CTxDB txdb("r");

        //>PHC<
        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());

        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;

            if (tx.IsCoinBase()
                || tx.IsCoinStake()
                || !IsFinalTx(tx, nHeight))
            {
                continue;
            }

            COrphan* porphan = NULL;

            double dPriority = 0;
            int64_t nTotalIn = 0;

            bool fMissingInputs = false;

            for(const CTxIn& txin: tx.vin)
            {
                // Read prev transaction
                CTransaction txPrev;
                CTxIndex txindex;

                if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        if (fDebug)
                        {
                            LogPrint("mempool", "%s : ERROR - Mempool transaction missing input \n", __FUNCTION__);
                        }

                        fMissingInputs = true;

                        if (porphan)
                        {
                            vOrphan.pop_back();
                        }

                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }

                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    
                    continue;
                }

                int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = txindex.GetDepthInMainChain();
                dPriority += (double)nValueIn * nConf;
            }

            if (fMissingInputs)
            {
                continue;
            }

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
            {
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
            }
        }

        // Collect transactions into block
        map<uint256, CTxIndex> mapTestPool;
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;

        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

            if (nBlockSize + nTxSize >= nBlockMaxSize)
            {
                continue;
            }

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);

            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
            {
                continue;
            }

            // Timestamp limit
            if (tx.nTime > GetAdjustedTime()
                || (false && tx.nTime > pblock->vtx[0].nTime))
            {
                continue;
            }

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee
                && (dFeePerKb < nMinTxFee)
                && (nBlockSize + nTxSize >= nBlockMinSize))
            {
                continue;
            }

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee
                && ((nBlockSize + nTxSize >= nBlockPrioritySize)
                || (dPriority < COIN * 144 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            // Connecting shouldn't fail due to dependency on other memory pool transactions
            // because we're already processing them in order of dependency
            map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
            MapPrevTx mapInputs;

            bool fInvalid;

            if (!tx.FetchInputs(txdb, mapTestPoolTmp, false, true, mapInputs, fInvalid))
            {
                continue;
            }

            int64_t nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();

            nTxSigOps += GetP2SHSigOpCount(tx, mapInputs);

            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
            {
                continue;
            }

            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            if (!tx.ConnectInputs(txdb, mapInputs, mapTestPoolTmp, CDiskTxPos(1,1,1), pindexPrev, false, true, MANDATORY_SCRIPT_VERIFY_FLAGS))
            {
                continue;
            }

            mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), tx.vout.size());

            swap(mapTestPool, mapTestPoolTmp);

            // Added
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fDebug && GetBoolArg("-printpriority", false))
            {
                LogPrint("miner", "%s : NOTICE - Priority %.1f feeperkb %.1f txid %s \n", __FUNCTION__, dPriority, dFeePerKb, tx.GetHash().ToString());
            }

            // Add transactions that depend on this one to the priority queue
            uint256 hash = tx.GetHash();

            if (mapDependers.count(hash))
            {
                for(COrphan* porphan: mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);

                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));

                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        if (fDebug && GetBoolArg("-printpriority", false))
        {
            LogPrint("miner", "%s : NOTICE - Total size %u \n", __FUNCTION__, nBlockSize);
        }
        
        // >PHC< POW
        pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pindexPrev->nHeight + 1, nFees);

        if (pFees)
        {
            pFees = nFees;
        }

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->nTime          = max(pindexPrev->GetPastTimeLimit()+1, pblock->GetMaxTransactionTime());


        pblock->UpdateTime(pindexPrev);


        pblock->nNonce         = 0;
    }
    // Global Namespace End

    return pblock.release();

}


// CreateNewBlock: create new block (without proof-of-work/proof-of-stake)
CBlock* CreateNewBlock(CReserveKey& reservekey, bool fProofOfStake, int64_t* pFees)
{
    if (IsInitialBlockDownload()
        || fReindex
        || fImporting)
    {
        return NULL;
    }

    // Create new block
    unique_ptr<CBlock> pblock(new CBlock());

    if (!pblock.get())
    {
        return NULL;
    }

    CBlockIndex* pindexPrev = pindexBest;
    int nHeight = pindexPrev->nHeight + 1;

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);

    if (!fProofOfStake)
    {
        CPubKey pubkey;

        if (!reservekey.GetReservedKey(pubkey))
        {
            return NULL;
        }

        txNew.vout[0].scriptPubKey.SetDestination(pubkey.GetID());
    }
    else
    {
        // Height first in coinbase required for block.version=2
        txNew.vin[0].scriptSig = (CScript() << nHeight) + COINBASE_FLAGS;

        if (txNew.vin[0].scriptSig.size() > 100)
        {
            if (fDebug)
            {
                LogPrint("miner", "%s : ERROR - VIN ScriptSig Size Invalid: %d \n", __FUNCTION__, pblock->vtx[0].vin[0].scriptSig.size());
            }

            return NULL;
        }

        txNew.vout[0].SetEmpty();
    }

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);

    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64_t nMinTxFee = MIN_TX_FEE;

    if (mapArgs.count("-mintxfee"))
    {
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);
    }

    pblock->nBits = GetNextTargetRequired(pindexPrev, fProofOfStake);

    // Collect memory pool transactions into the block
    int64_t nFees = 0;

    // Global Namespace Start
    {
        LOCK2(cs_main, mempool.cs);

        CTxDB txdb("r");

        //>PHC<
        // Priority order to process transactions

        // list memory doesn't move
        list<COrphan> vOrphan;
        map<uint256, vector<COrphan*> > mapDependers;

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());

        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;

            if (tx.IsCoinBase()
                || tx.IsCoinStake()
                || !IsFinalTx(tx, nHeight))
            {
                continue;
            }

            COrphan* porphan = NULL;

            double dPriority = 0;
            int64_t nTotalIn = 0;

            bool fMissingInputs = false;

            for(const CTxIn& txin: tx.vin)
            {
                // Read prev transaction
                CTransaction txPrev;
                CTxIndex txindex;

                if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        if (fDebug)
                        {
                            LogPrint("mempool", "%s : ERROR - Mempool transaction missing input \n", __FUNCTION__);
                        }

                        fMissingInputs = true;

                        if (porphan)
                        {
                            vOrphan.pop_back();
                        }

                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }

                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    
                    continue;
                }

                int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = txindex.GetDepthInMainChain();
                dPriority += (double)nValueIn * nConf;
            }

            if (fMissingInputs)
            {
                continue;
            }

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
            {
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
            }
        }

        // Collect transactions into block
        map<uint256, CTxIndex> mapTestPool;
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;

        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            
            if (nBlockSize + nTxSize >= nBlockMaxSize)
            {
                continue;
            }

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);

            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
            {
                continue;
            }

            // Timestamp limit
            if (tx.nTime > GetAdjustedTime()
                || (fProofOfStake && tx.nTime > pblock->vtx[0].nTime))
            {
                continue;
            }

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee
                && (dFeePerKb < nMinTxFee)
                && (nBlockSize + nTxSize >= nBlockMinSize))
            {
                continue;
            }

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee && ((nBlockSize + nTxSize >= nBlockPrioritySize)
                || (dPriority < COIN * 144 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            // Connecting shouldn't fail due to dependency on other memory pool transactions
            // because we're already processing them in order of dependency
            map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
            MapPrevTx mapInputs;

            bool fInvalid;

            if (!tx.FetchInputs(txdb, mapTestPoolTmp, false, true, mapInputs, fInvalid))
            {
                continue;
            }

            int64_t nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();

            nTxSigOps += GetP2SHSigOpCount(tx, mapInputs);

            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
            {
                continue;
            }

            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            if (!tx.ConnectInputs(txdb, mapInputs, mapTestPoolTmp, CDiskTxPos(1,1,1), pindexPrev, false, true, MANDATORY_SCRIPT_VERIFY_FLAGS))
            {
                continue;
            }

            mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), tx.vout.size());

            swap(mapTestPool, mapTestPoolTmp);

            // Added
            pblock->vtx.push_back(tx);

            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fDebug
                && GetBoolArg("-printpriority", false))
            {
                LogPrint("miner", "%s : NOTICE - Priority %.1f feeperkb %.1f txid %s \n", __FUNCTION__, dPriority, dFeePerKb, tx.GetHash().ToString());
            }

            // Add transactions that depend on this one to the priority queue
            uint256 hash = tx.GetHash();

            if (mapDependers.count(hash))
            {
                for(COrphan* porphan: mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);

                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        if (fDebug && GetBoolArg("-printpriority", false))
        {
            LogPrint("miner", "%s : NOTICE - Total size %u\n", __FUNCTION__, nBlockSize);
        }
        
        // >PHC<
        
        if (!fProofOfStake)
        {
            pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pindexPrev->nHeight + 1, nFees);
        }

        if (pFees)
        {
            *pFees = nFees;
        }

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->nTime          = max(pindexPrev->GetPastTimeLimit()+1, pblock->GetMaxTransactionTime());

        if (!fProofOfStake)
        {
            pblock->UpdateTime(pindexPrev);
        }

        pblock->nNonce         = 0;
    }
    // Global Namespace End

    return pblock.release();
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;

    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }

    ++nExtraNonce;

    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2

    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;

    if (pblock->vtx[0].vin[0].scriptSig.size() > 100)
    {
        if (fDebug)
        {
            LogPrint("miner", "%s : ERROR - VIN ScriptSig Size Invalid: %d \n", __FUNCTION__, pblock->vtx[0].vin[0].scriptSig.size());
        }

        return;
    }

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
        }
        block;

        unsigned char pchPadding0[64];

        uint256 hash1;

        unsigned char pchPadding1[64];
    }

    tmp;

    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
    {
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);
    }

    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool ProcessBlockStake(CBlock* pblock, CWallet& wallet)
{
    uint256 proofHash = 0, hashTarget = 0;
    uint256 hashBlock = pblock->GetHash();

    if(!pblock->IsProofOfStake())
    {
        return error("%s : ERROR - %s is not a proof-of-stake block", __FUNCTION__, hashBlock.GetHex());
    }

    // verify hash target and signature of coinstake tx
    if (!CheckProofOfStake(mapBlockIndex[pblock->hashPrevBlock], pblock->vtx[1], pblock->nBits, proofHash, hashTarget))
    {
        return error("%s : ERROR - Proof-of-stake checking failed", __FUNCTION__);
    }

    if (fDebug)
    {
        //// debug print
        LogPrint("coinstake", "%s : WARNING - New proof-of-stake block found \n hash: %s \n proofhash: %s  \n target: %s \n", __FUNCTION__, hashBlock.GetHex(), proofHash.GetHex(), hashTarget.GetHex());
        LogPrint("coinstake", "%s : WARNING - %s \n", __FUNCTION__, pblock->ToString());
        LogPrint("coinstake", "%s : WARNING - Out %s \n", __FUNCTION__, FormatMoney(pblock->vtx[1].GetValueOut()));
    }

    // Global Namespace Start
    {
        // Found a solution

        LOCK(cs_main);

        if (pblock->hashPrevBlock != hashBestChain)
        {
            return error("%s : ERROR - Generated block is stale", __FUNCTION__);
        }

        // Global Namespace Start
        {
            // Track how many getdata requests this block gets
            LOCK(wallet.cs_wallet);

            wallet.mapRequestCount[hashBlock] = 0;
        }
        // Global Namespace End

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
        {
            return error("%s : ERROR - Block not accepted", __FUNCTION__);
        }
        else
        {
            //ProcessBlock successful for PoS. now FixSpentCoins.
            int nMismatchSpent;

            CAmount nBalanceInQuestion;

            wallet.FixSpentCoins(nMismatchSpent, nBalanceInQuestion);

            if (nMismatchSpent != 0)
            {
                if (fDebug)
                {
                    LogPrint("coinstake", "%s : NOTICE - PoS mismatched spent coins = %d and balance affects = %d \n", __FUNCTION__, nMismatchSpent, nBalanceInQuestion);
                }
            }
        }
    }
    // Global Namespace End

    return true;
}


void ThreadStakeMiner(CWallet *pwallet)
{
    Set_ThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread("PHC-stake-miner");

    CReserveKey reservekey(pwallet);

    unsigned int nExtraNonce = 0;


    while (fStaking == true)
    {
        if (!IsInitialBlockDownload()
            && !fReindex
            && !fImporting)
        {
            if (Consensus::ChainShield::Enabled == true
                && Consensus::ChainBuddy::Enabled == true)
            {
                if (Consensus::ChainBuddy::WalletHasConsensus() == false)
                {
                    Consensus::ChainShield::Protect();
                }

                if (Consensus::ChainShield::DisableNewBlocks == true)
                {
                    nLastCoinStakeSearchInterval = 0;

                    if (fDebug)
                    {
                        LogPrint("coinstake", "%s : ERROR - ChainShield disabled blocks \n", __FUNCTION__);
                    }

                    MilliSleep(nMinerSleep * 100);

                    // Skip tryng to stake this round
                    continue;
                }
            }
        }
        
        // No less than 10 masternodes in list allowed for staking
        if (mnodeman.size() < 10
            && TestNet() == false)
        {
            nLastCoinStakeSearchInterval = 0;

            if (fDebug)
            {
                LogPrint("coinstake", "%s : ERROR - Minimum masternodes less than 10 \n", __FUNCTION__);
            }

            MilliSleep(nMinerSleep * 100);

            // Skip tryng to stake this round
            continue;
        }

        // Wait for another block from network to continue staking (max 5 minutes)
        if (pindexBest->nHeight == LastBlockStake
            || pindexBest->nHeight-1 == LastBlockStake)
        {
            if (LastBlockStakeTime > 0
                && GetTime() - LastBlockStakeTime < 5 * 60)
            {
                nLastCoinStakeSearchInterval = 0;

                // Force asking all other peers for new blocks
                CChain::ForceSync(NULL, pindexBest->pprev->pprev->GetBlockHash());

                if (fDebug)
                {
                    LogPrint("coinstake", "%s : ERROR - Generating Stake Blocks too quickly, waiting... \n", __FUNCTION__);
                }

                MilliSleep(nMinerSleep * 100);

                // Skip tryng to stake this round
                continue;
            }
        }

        if (pwallet->IsLocked() == true
                || pwallet->GetStake() > 0)
        {
            nLastCoinStakeSearchInterval = 0;

            if (fDebug)
            {
                LogPrint("coinstake", "%s : ERROR - Coins are locked or currently staking \n", __FUNCTION__);
            }

            MilliSleep(nMinerSleep * 100);

            // Skip tryng to stake this round
            continue;
        }

        if (vNodes.empty() == true
                || IsInitialBlockDownload()
                || vNodes.size() < 8)
        {
            nLastCoinStakeSearchInterval = 0;

            if (fDebug)
            {
                LogPrint("coinstake", "%s : ERROR - Wallet is not synced \n", __FUNCTION__);
            }

            MilliSleep(nMinerSleep * 100);

            // Skip tryng to stake this round
            continue;
        }

        if (fDebug)
        {
            LogPrint("coinstake", "%s : NOTICE - Attempting to create new PoS block \n", __FUNCTION__);
        }

        LOCK(cs_main);

        //
        // Create new block
        //
        int64_t nFees;

        unique_ptr<CBlock> pblock(CreateNewBlock(reservekey, true, &nFees));

        if (!pblock.get())
        {
            if (fDebug)
            {
                LogPrint("coinstake", "%s : ERROR - FAILED creating a PoS block \n", __FUNCTION__);
            }

            return;
        }

        // PIP7 - Activate IncrementExtraNonce
        if (pindexBest->nHeight >= Params().PIP7_Height())
        {
            IncrementExtraNonce(pblock.get(), pindexBest, nExtraNonce);
        }

        if (fDebug)
        {
            LogPrint("coinstake", "%s : NOTICE - Trying to sign new PoS block \n", __FUNCTION__);
        }

        // Trying to sign a block
        if (pblock->SignBlock(*pwallet, nFees))
        {
            // Set Thread Priority to Normal
            Set_ThreadPriority(THREAD_PRIORITY_NORMAL);

            // Process the pblock (Attempt to accept)
            if (ProcessBlockStake(pblock.get(), *pwallet) == true)
            {
                // LastStakeEarned (Block Number)
                LastBlockStake = pindexBest->nHeight;
                LastBlockStakeTime = GetTime();

                // Broadcast Block to connected peers
                CChain::BlockBroadCast(pblock.get());

                if (fDebug)
                {
                    LogPrint("coinstake", "%s : OK - New PoS block ACCEPTED: %s @ %d \n", __FUNCTION__,  pblock->GetHash().ToString().c_str(), LastBlockStake);
                }

                MilliSleep(500);

                // Force asking all other peers for new blocks
                CChain::ForceSync(NULL, pindexBest->pprev->pprev->GetBlockHash());

                MilliSleep(500);
            }
            else
            {
                if (fDebug)
                {
                    LogPrint("coinstake", "%s : ERROR - New PoS block REJECTED: %s @ %d \n", __FUNCTION__, pblock->GetHash().ToString().c_str(), LastBlockStake);
                }
            }

            // Set Thread Priority to Lowest
            Set_ThreadPriority(THREAD_PRIORITY_LOWEST);
        }
        else
        {
            if (fDebug)
            {
                LogPrint("coinstake", "%s : ERROR - New PoS block signing failed \n", __FUNCTION__);
            }
        }
        
        MilliSleep(nMinerSleep);
    }
}


//////////////////////////////////////////////////////////////////////////////
//
// 
// Internal Coin Miner
//


bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hashBlock = pblock->GetHash();
    uint256 hashProof = pblock->GetPoWHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if(!pblock->IsProofOfWork())
    {
        return error("%s : ERROR - %s is not a proof-of-work block", __FUNCTION__, hashBlock.GetHex());
    }

    if (hashProof > hashTarget)
    {
        return error("%s : ERROR - Proof-of-work not meeting target", __FUNCTION__);
    }

    if (fDebug)
    {
        //// debug print
        LogPrint("miner", "%s : NOTICE - New proof-of-work block found  \n  proof hash: %s  \ntarget: %s \n",  __FUNCTION__, hashProof.GetHex(), hashTarget.GetHex());
        LogPrint("miner", "%s : NOTICE - %s \n", __FUNCTION__, pblock->ToString());
        LogPrint("miner", "%s : NOTICE - generated %s \n", __FUNCTION__, FormatMoney(pblock->vtx[0].vout[0].nValue));
    }

    // Global Namespace Start
    {
        // Found a solution

        LOCK(cs_main);

        if (pblock->hashPrevBlock != hashBestChain)
        {
            return error("%s : ERROR - Generated block is stale", __FUNCTION__);
        }

        // Remove key from key pool
        reservekey.KeepKey();

        // Global Namespace Start
        {
            // Track how many getdata requests this block gets

            LOCK(wallet.cs_wallet);

            wallet.mapRequestCount[hashBlock] = 0;
        }
        // Global Namespace End

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
        {
            return error("%s : ERROR - ProcessBlock, block not accepted", __FUNCTION__);
        }
    }
    // Global Namespace End

    return true;
}

void static InternalcoinMiner(CWallet *pwallet)
{
    std::string TempMinerLogCache;

    if (fDebug)
    {
        LogPrint("miner", "%s : NOTICE - PoW-Miner - Started! \n", __FUNCTION__);
    }

    Set_ThreadPriority(THREAD_PRIORITY_LOWEST);

    RenameThread("PHC-PoW-Miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);

    unsigned int nExtraNonce = 0;

    try
    {
        while (true)
        {
            if (!IsInitialBlockDownload()
                && !fReindex
                && !fImporting)
            {
                if (Consensus::ChainShield::Enabled == true
                    && Consensus::ChainBuddy::Enabled == true)
                {
                    if (Consensus::ChainBuddy::WalletHasConsensus() == false)
                    {
                        Consensus::ChainShield::Protect();
                    }

                    if (Consensus::ChainShield::DisableNewBlocks == true)
                    {
                        return;
                    }
                }
            }

            // Busy-wait for the network to come online so we don't waste time mining
            // on an obsolete chain. In regtest mode we expect to fly solo.

            bool fvNodesEmpty;

            // Global Namespace Start
            {
                LOCK(cs_vNodes);

                fvNodesEmpty = vNodes.empty();
            }
            // Global Namespace End

            if (fvNodesEmpty == true
                || IsInitialBlockDownload() == true
                || vNodes.size() < 2 
                || pindexBest->GetBlockTime() < GetTime() - 10 * 60)
            {
                if (fDebug)
                {
                    LogPrint("mining", "%s : ERROR - PoW-Miner - Aborted: Not Synced! \n", __FUNCTION__);
                }
                
                return;
            }

            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();

            CBlockIndex* pindexPrev = pindexBest;
           
            unique_ptr<CBlock> pblocktemplate(CreateNewBlockWithKey(reservekey, pwallet));

            if (!pblocktemplate.get())
            {
                if (fDebug)
                {
                    LogPrint("mining", "%s : ERROR - PoW-Miner Keypool ran out, please call keypoolrefill before restarting the mining thread \n", __FUNCTION__);
                }

                return;
            }

            CBlock *pblock = pblocktemplate.get();

            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            if (fDebug)
            {
                LogPrint("mining", "%s : ERROR - Running PoW-Miner with %u transactions in block (%u bytes) \n", __FUNCTION__, pblock->vtx.size(), ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));
            }

            //
            // Search
            //
            int64_t nStart = GetTime();
            uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
            uint256 thash;

            while (true)
            {
                unsigned int nHashesDone = 0;
                char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

                while(true)
                {
                    scrypt_1024_1_1_256_sp(BEGIN(pblock->nVersion), BEGIN(thash), scratchpad);

                    if (thash <= hashTarget)
                    {
                        // Found a solution
                        Set_ThreadPriority(THREAD_PRIORITY_NORMAL);
                        
                        if (ProcessBlockFound(pblock, *pwallet, reservekey) == true)
                        {
                            TempMinerLogCache = "accepted:" + thash.GetHex();

                            if (MinerLogCache != TempMinerLogCache)
                            {
                                if (fDebug)
                                {
                                    LogPrint("mining", "%s : OK - Proof-of-work found! (ACCEPTED) Hash: %s Nonce: %d \n", __FUNCTION__, thash.GetHex(), pblock->nNonce);
                                }
                            }

                            MinerLogCache = "accepted:" + thash.GetHex();

                            // Broadcast Block to connected peers
                            CChain::BlockBroadCast(pblock);

                            MilliSleep(120000);
                        }
                        else
                        {
                            TempMinerLogCache = "rejected:" + thash.GetHex();

                            if (MinerLogCache != TempMinerLogCache)
                            {
                                if (fDebug)
                                {
                                    LogPrint("mining", "%s : ERROR - Proof-of-work found! (REJECTED) Hash: %s Nonce: %d \n", __FUNCTION__, thash.GetHex(), pblock->nNonce);
                                }
                            }

                            MinerLogCache = "rejected:" + thash.GetHex();
                        }
                        
                        Set_ThreadPriority(THREAD_PRIORITY_LOWEST);

                        // In regression test mode, stop mining after a block is found.
                        /*
                        if (Params().MineBlocksOnDemand())
                            throw boost::thread_interrupted();
                        */

                        break;
                    }

                    pblock->nNonce += 1;
                    nHashesDone += 1;

                    if ((pblock->nNonce & 0xFF) == 0)
                    {
                        break;
                    }
                }

                // Meter hashes/sec
                static int64_t nHashCounter;

                if (nHPSTimerStart == 0)
                {
                    nHPSTimerStart = GetTimeMillis();
                    nHashCounter = 0;
                }
                else
                {
                    nHashCounter += nHashesDone;
                }

                if (GetTimeMillis() - nHPSTimerStart > 4000)
                {
                    static CCriticalSection cs;
                    {
                        LOCK(cs);

                        if (GetTimeMillis() - nHPSTimerStart > 4000)
                        {
                            dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                            nHPSTimerStart = GetTimeMillis();
                            nHashCounter = 0;

                            static int64_t nLogTime;

                            if (GetTime() - nLogTime > 30 * 60)
                            {
                                nLogTime = GetTime();

                                if (fDebug)
                                {
                                    LogPrint("mining", "%s : NOTICE - PoW-Miner Hashmeter %6.0f khash/s \n", __FUNCTION__, dHashesPerSec/1000.0);
                                }
                            }
                        }
                    }
                }

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point();

                // Regtest mode doesn't require peers
                if (vNodes.empty())
                {
                    break;
                }

                if (pblock->nNonce >= 0xffff0000)
                {
                    break;
                }

                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast
                    && GetTime() - nStart > 60)
                {
                    break;
                }

                if (pindexPrev != pindexBest)
                {
                    break;
                }

                // Update nTime every few seconds
                UpdateTime(*pblock, pindexPrev);

                /*
                if (Params().AllowMinDifficultyBlocks())
                {
                    // Changing pblock->nTime can change work required on testnet:
                    hashTarget.SetCompact(pblock->nBits);
                }
                */
            }
        }
    }
    catch (boost::thread_interrupted)
    {
        if (fDebug)
        {
            LogPrint("mining", "%s : ERROR - PoW-Miner terminated \n", __FUNCTION__);
        }

        GenerateProcLimit = -1;
        fGenerating = false;

        throw;
    }
    catch (const std::runtime_error &e)
    {
        if (fDebug)
        {
            LogPrint("mining", "%s : ERROR - PoW-Miner runtime error: %s \n",__FUNCTION__, e.what());
        }

        GenerateProcLimit = -1;
        fGenerating = false;

        return;
    }
}

void GeneratePoWcoins(bool fGenerate, CWallet* pwallet)
{
    static boost::thread_group* minerThreads = NULL;

    int nThreads = GetArg("-genproclimit", -2);

    if (nThreads == 0)
    {
        nThreads = boost::thread::hardware_concurrency();
    }

    if (nThreads == -2)
    {
        nThreads = 1;
    }

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();

        delete minerThreads;

        minerThreads = NULL;
    }

    if (nThreads == -1 || !fGenerate)
    {
        return;
    }

    GenerateProcLimit = nThreads;
    fGenerating = true;

    minerThreads = new boost::thread_group();

    for (int i = 0; i < nThreads; i++)
    {
        minerThreads->create_thread(boost::bind(&InternalcoinMiner, pwallet));
    }
}