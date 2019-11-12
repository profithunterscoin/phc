// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2019 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#include "rpcserver.h"
#include "main.h"
#include "net.h"
#include "kernel.h"
#include "checkpoints.h"
#include "init.h"
#include "consensus.h"

using namespace json_spirit;
using namespace std;
using namespace CBan;


extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);


double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
        {
            return 1.0;
        }
        else
        {
            blockindex = GetLastBlockIndex(pindexBest, false);
        }
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff = (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }

    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}


double GetPoWMHashPS()
{
    if (pindexBest->nHeight >= Params().LastPOWBlock())
    {
        return 0;
    }

    int nPoWInterval = 72;

    int64_t nTargetSpacingWorkMin = 30, nTargetSpacingWork = 30;

    CBlockIndex* pindex = pindexGenesisBlock;
    CBlockIndex* pindexPrevWork = pindexGenesisBlock;

    while (pindex)
    {
        if (pindex->IsProofOfWork())
        {
            int64_t nActualSpacingWork = pindex->GetBlockTime() - pindexPrevWork->GetBlockTime();
            
            nTargetSpacingWork = ((nPoWInterval - 1) * nTargetSpacingWork + nActualSpacingWork + nActualSpacingWork) / (nPoWInterval + 1);
            nTargetSpacingWork = max(nTargetSpacingWork, nTargetSpacingWorkMin);
            
            pindexPrevWork = pindex;
        }

        pindex = pindex->pnext;
    }

    return GetDifficulty() * 4294.967296 / nTargetSpacingWork;
}


double GetPoSKernelPS()
{
    int nPoSInterval = 72;
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    CBlockIndex* pindex = pindexBest;;
    CBlockIndex* pindexPrevStake = NULL;

    while (pindex && nStakesHandled < nPoSInterval)
    {
        if (pindex->IsProofOfStake())
        {
            if (pindexPrevStake)
            {
                dStakeKernelsTriedAvg += GetDifficulty(pindexPrevStake) * 4294967296.0;
                nStakesTime += pindexPrevStake->nTime - pindex->nTime;
                nStakesHandled++;
            }

            pindexPrevStake = pindex;
        }

        pindex = pindex->pprev;
    }

    double result = 0;

    if (nStakesTime)
    {
        result = dStakeKernelsTriedAvg / nStakesTime;
    }

    result *= STAKE_TIMESTAMP_MASK + 1;

    return result;
}


Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    
    int confirmations = -1;
    
    // Only report confirmations if the block is on the main chain
    if (blockindex->IsInMainChain())
    {
        confirmations = nBestHeight - blockindex->nHeight + 1;
    }
    
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
#ifndef LOWMEM
    result.push_back(Pair("POWmint", ValueFromAmount(blockindex->nPOWMint)));
    result.push_back(Pair("POSmint", ValueFromAmount(blockindex->nPOSMint)));
#endif
    result.push_back(Pair("moneysupply", ValueFromAmount(blockindex->nMoneySupply)));
    result.push_back(Pair("time", (int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("blocktrust", leftTrim(blockindex->GetBlockTrust().GetHex(), '0')));
    result.push_back(Pair("chaintrust", leftTrim(blockindex->nChainTrust.GetHex(), '0')));
    
    if (blockindex->pprev)
    {
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    }
    
    if (blockindex->pnext)
    {
        result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));
    }

    result.push_back(Pair("flags", strprintf("%s%s", blockindex->IsProofOfStake()? "proof-of-stake" : "proof-of-work", blockindex->GeneratedStakeModifier()? " stake-modifier": "")));
    result.push_back(Pair("proofhash", blockindex->IsProofOfStake()? blockindex->hashProof.GetHex() : blockindex->GetBlockHash().GetHex()));
    result.push_back(Pair("entropybit", (int)blockindex->GetStakeEntropyBit()));
    result.push_back(Pair("modifier", strprintf("%016x", blockindex->nStakeModifier)));
    
    Array txinfo;
    
    for(const CTransaction& tx: block.vtx)
    {
        if (fPrintTransactionDetail)
        {
            Object entry;

            entry.push_back(Pair("txid", tx.GetHash().GetHex()));

            TxToJSON(tx, 0, entry);

            txinfo.push_back(entry);
        }
        else
        {
            txinfo.push_back(tx.GetHash().GetHex());
        }
    }

    result.push_back(Pair("tx", txinfo));

    if (block.IsProofOfStake())
    {
        result.push_back(Pair("signature", HexStr(block.vchBlockSig.begin(), block.vchBlockSig.end())));
    }

    return result;
}


Value getbestblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("getbestblockhash\n"
                            "Returns the hash of the best block in the longest block chain.");
    }

    return hashBestChain.GetHex();
}


Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("getblockcount\n"
                            "Returns the number of blocks in the longest block chain.");
    }

    return nBestHeight;
}


Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("getdifficulty\n"
                            "Returns the difficulty as a multiple of the minimum difficulty.");
    }

    //Object obj;
    //obj.push_back(Pair("proof-of-work",        GetDifficulty()));
    //obj.push_back(Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    return GetDifficulty(GetLastBlockIndex(pindexBest, true));
}


Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("getrawmempool\n"
                            "Returns all transaction ids in memory pool.");
    }

    vector<uint256> vtxid;

    mempool.queryHashes(vtxid);

    Array a;

    for(const uint256& hash: vtxid)
    {
        a.push_back(hash.ToString());
    }

    return a;
}


Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error("getblockhash <index>\n"
                            "Returns hash of block in best-block-chain at <index>.");
    }

    int nHeight = params[0].get_int();

    if (nHeight < 0 || nHeight > nBestHeight)
    {
        throw runtime_error("Block number out of range.");
    }

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    
    return pblockindex->phashBlock->GetHex();
}


Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error("getblock <hash> [txinfo]\n"
                            "txinfo optional to print more detailed tx info\n"
                            "Returns details of a block with given block-hash.");
    }

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    CBlock block;
    
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}


Value getblockbynumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error("getblockbynumber <number> [txinfo]\n"
                            "txinfo optional to print more detailed tx info\n"
                            "Returns details of a block with given block-number.");
    }

    int nHeight = params[0].get_int();
    
    if (nHeight < 0 || nHeight > nBestHeight)
    {
        throw runtime_error("Block number out of range.");
    }

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hashBestChain];
    
    while (pblockindex->nHeight > nHeight)
    {
        pblockindex = pblockindex->pprev;
    }

    uint256 hash = *pblockindex->phashBlock;

    pblockindex = mapBlockIndex[hash];

    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}


// ppcoin: get information of sync-checkpoint
Value getcheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("getcheckpoint\n"
                            "Show info of synchronized checkpoint.\n");
    }

    Object result;
    
    const CBlockIndex* pindexCheckpoint = Checkpoints::AutoSelectSyncCheckpoint();

    result.push_back(Pair("synccheckpoint", pindexCheckpoint->GetBlockHash().ToString().c_str()));
    result.push_back(Pair("height", pindexCheckpoint->nHeight));
    result.push_back(Pair("timestamp", DateTimeStrFormat(pindexCheckpoint->GetBlockTime()).c_str()));
    result.push_back(Pair("policy", "rolling"));

    return result;
}


Value prune(const Array& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp || params.size() > 1)
    {
        throw runtime_error("prune\n"
                            "prune Orphan blocks (blockchain index)"
                            );
    }
    
    CChain::PruneOrphanBlocks();

    return true;
}


Value rollbackchain(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
    {
        throw runtime_error("rollbackchain <blockcount>\n"
                            "Rollbackchain blockchain index by X blocks (100 default)"
                            );
    }

    int nBlockCount = (int)strtod(params[0].get_str().c_str(), NULL);

    if (nBlockCount == 0)
    {
        nBlockCount = 100;
    }

    int OldHeight = nBestHeight;

    nBestHeight = CChain::RollbackChain(nBlockCount);

    throw runtime_error(strprintf("%s : Rollback completed: %d blocks total (%d -> %d)", __FUNCTION__, nBlockCount, OldHeight, nBestHeight));

    return true;
}


Value backtoblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
    {
        throw runtime_error("backtoblock <blockheight>\n"
                            "Rollbacktoblock local database to block height (default: 100000)"
                            );
    }

    int nNewHeight = (int)strtod(params[0].get_str().c_str(), NULL);

    if (nNewHeight == 0)
    {
        nNewHeight = 100000;
    }

    int OldHeight = nBestHeight;
    int nBlockCount = nBestHeight - nNewHeight;

    nBestHeight = CChain::Backtoblock(nNewHeight);

    throw runtime_error(strprintf("%s : Backtoblock %d completed: %d blocks total (%d -> %d)", __FUNCTION__, nNewHeight, nBlockCount, OldHeight, nBestHeight));

    return true;
}


Value forcesync(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("forcesync\n"
                            "Forces nodes to sync from current local block height.");
    }

    CNode* blank_filter = 0;
    
    return strprintf("ForceSync nodes: %d", CChain::ForceSync(blank_filter, uint256(0)));
}


Value getchainbuddyinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("getchainbuddyinfo\n"
                            "Show info of Chain Buddy.\n");
    }

    Object result, map, mapitem;

    result.push_back(Pair("enabled",                            Consensus::ChainBuddy::Enabled));
    result.push_back(Pair("wallethasconsensus",                 Consensus::ChainBuddy::WalletHasConsensus()));
    result.push_back(Pair("nodeshaveconsensus",                 Consensus::ChainBuddy::GetNodeCount(Consensus::ChainBuddy::BestCheckpoint.hash)));
    result.push_back(Pair("bestcheckpointheight",               (int)Consensus::ChainBuddy::BestCheckpoint.height));
    result.push_back(Pair("bestcheckpointhash",                 Consensus::ChainBuddy::BestCheckpoint.hash.GetHex()));
    result.push_back(Pair("bestcheckpointtimestamp",            Consensus::ChainBuddy::BestCheckpoint.timestamp));
    result.push_back(Pair("bestcheckpointaddrlog",              Consensus::ChainBuddy::BestCheckpoint.fromnode));
    result.push_back(Pair("checkpointmapsize",                  (int)Consensus::ChainBuddy::ConsensusCheckpointMap.size()));

        if (Consensus::ChainBuddy::ConsensusCheckpointMap.size() > 0)
        {
            int cnt;

            for (int item = 0; item <= (signed)Consensus::ChainBuddy::ConsensusCheckpointMap.size() - 1; ++item)
            {
                cnt = cnt + 1;
                Object mapitem;

                    mapitem.push_back(Pair("hash",              Consensus::ChainBuddy::ConsensusCheckpointMap[item].second.hash.GetHex()));
                    mapitem.push_back(Pair("nodes",             Consensus::ChainBuddy::ConsensusCheckpointMap[item].first));
                    mapitem.push_back(Pair("height",            Consensus::ChainBuddy::ConsensusCheckpointMap[item].second.height));
                    mapitem.push_back(Pair("timestamp",         Consensus::ChainBuddy::ConsensusCheckpointMap[item].second.timestamp));
                    //mapitem.push_back(Pair("synced",            Consensus::ChainBuddy::ConsensusCheckpointMap[item].second.synced));
                    mapitem.push_back(Pair("nodelog",            Consensus::ChainBuddy::ConsensusCheckpointMap[item].second.fromnode));
                
                map.push_back(Pair(strprintf("%d", cnt),         mapitem));       
            }
        }

    result.push_back(Pair("checkpointmap",                      map));

    return result;
}


Value chainbuddyenabled(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error("chainbuddyenabled\n"
                            "Set Chain Buddy Enabled: TRUE/FALSE.");
    }

    if (params.size()  == 1)
    {
        Consensus::ChainBuddy::Enabled = StringToBool(params[0].get_str());
    }

    return strprintf("Consensus::ChainBuddy::Enabled %d", Consensus::ChainBuddy::Enabled);
}


Value getchainshieldinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("getchainshieldinfo\n"
                            "Show info of Chain Shield.\n");
    }

    Object result;
    
    result.push_back(Pair("enabled",                           Consensus::ChainShield::Enabled));
    result.push_back(Pair("disablenewblocks",                  Consensus::ChainShield::DisableNewBlocks));
    result.push_back(Pair("cacheheight",                       Consensus::ChainShield::ChainShieldCache));
    result.push_back(Pair("rollbackrunaway",                   Consensus::ChainShield::Rollback_Runaway));
    
    return result;
}


Value chainshieldenabled(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error("chainshieldenabled\n"
                            "Set Chain Shield Enabled: TRUE/FALSE.");
    }

    Consensus::ChainShield::Enabled = StringToBool(params[0].get_str());

    return strprintf("Consensus::ChainShield::Enabled %d", Consensus::ChainShield::Enabled);
}

Value chainshieldrollbackrunaway(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error("chainshieldrollbackrunaway\n"
                            "Set Chain Shield Rollback Runaway Exception (Auto-Fix) Enabled: TRUE/FALSE.");
    }

    Consensus::ChainShield::Rollback_Runaway = StringToBool(params[0].get_str());

    return strprintf("Consensus::ChainShield::Rollback_Runaway %d", Consensus::ChainShield::Rollback_Runaway);
}

