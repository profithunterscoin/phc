// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (C) 2017-2018 Crypostle Core developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#include "rpcserver.h"
#include "chainparams.h"
#include "db.h"
#include "txdb.h"
#include "init.h"
#include "miner.h"
#include "kernel.h"

#ifdef ENABLE_WALLET
#include "wallet.h"
#include "walletdb.h"
#endif


#include <boost/assign/list_of.hpp>

#include <string>     // std::string, std::stoi

using namespace json_spirit;
using namespace std;
using namespace boost::assign;

// Key used by getwork/getblocktemplate miners.
// Allocated in InitRPCMining, free'd in ShutdownRPCMining
static CReserveKey* pMiningKey = NULL;

void InitRPCMining()
{
    if (!pwalletMain)
    {
        return;
    }

    // getwork/getblocktemplate mining rewards paid here:
    pMiningKey = new CReserveKey(pwalletMain);
}


void ShutdownRPCMining()
{
    if (!pMiningKey)
    {
        return;
    }

    delete pMiningKey; pMiningKey = NULL;
}


Value getsubsidy(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() > 1)
    {
        throw runtime_error("getsubsidy [nTarget] \n"
                            "Returns proof-of-work subsidy value for the specified value of target.");
    }

    return (int64_t)GetProofOfStakeReward(pindexBest->pprev, 0, 0);
}


Value getstakesubsidy(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() != 1)
    {
        throw runtime_error("getstakesubsidy <hex string> \n"
                            "Returns proof-of-stake subsidy value for the specified coinstake.");
    }

    RPCTypeCheck(params, list_of(str_type));

    vector<unsigned char> txData(ParseHex(params[0].get_str()));
    
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    
    try
    {
        ssData >> tx;
    }
    catch (std::exception &e)
    {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "ERROR - TX decode failed");
    }

    uint64_t nCoinAge;

    CTxDB txdb("r");

    if (!tx.GetCoinAge(txdb, pindexBest, nCoinAge))
    {
        throw JSONRPCError(RPC_MISC_ERROR, "ERROR - GetCoinAge failed");
    }

    return (uint64_t)GetProofOfStakeReward(pindexBest->pprev, nCoinAge, 0);
}


Value getgenerate(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() != 0)
    {
        throw runtime_error(
            "getgenerate \n"
            "Returns true or false."
            );
    }

    if (!pMiningKey)
    {
        return false;
    }

    return GetBoolArg("-gen", false);
}


Value setgenerate(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() < 1
        || params.size() > 3)
    {
        throw runtime_error(
            "setgenerate <generate> [genproclimit] <debugtoconsole> \n"
            "<generate> is true or false to turn generation on or off. \n"
            "[genproclimit] CPU threads to use for mining \n"
            "<debugtoconsole> optional to display live debug to unix/dos console (default: false)"
            "Generation is limited to [genproclimit] processors, -1 is unlimited."
            );

    }

    bool fGenerate = true;
    
    if (params.size() > 0)
    {
        if (params[0].get_str() == "true")
        {
            fGenerate = true;
            mapArgs["-gen"] = "1";
        }
        else
        {
            fGenerate = false;
            mapArgs["-gen"] = "0";
        }
    }
    
    if (params.size() > 1)
    {
        int nGenProcLimit = std::stoi(params[1].get_str());

        mapArgs["-genproclimit"] = itostr(nGenProcLimit);

        if (nGenProcLimit == 0)
        {
            fGenerate = false;
        }
    }
    else
    {
        if (fGenerate == true)
        {
            mapArgs["-genproclimit"] = "1";
        }
    }

    if (params.size() > 2)
    {
        if (params[2].get_str() == "true")
        {
            fDebug = true;
            fPrintToConsole = true;
            fPrintToDebugLog = false;
        }
    }   

    if (pwalletMain == NULL)
    {
        if (fDebug)
        {
            LogPrint("rpc", "%s : ERROR - pwalletMain = NULL \n", __FUNCTION__);
        }

        return Value::null;
    }
    
    GeneratePoWcoins(fGenerate, pwalletMain);

    return Value::null;
}


Value setstaking(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() < 1
        || params.size() > 3)
    {
        throw runtime_error(
            "setstaking <generate> \n"
            "<true|false> is true or false to turn staking on or off. \n"
            );

    }
    
    if (params.size() > 0)
    {
        if (params[0].get_str() == "true")
        {
            fStaking = true;
        }
        else
        {
            fStaking = false;
        }
    }

    Object obj;

    obj.push_back(Pair("enabled",                                   fStaking));

    return obj;
}


Value gethashespersec(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() != 0)
    {
        throw runtime_error(
            "gethashespersec \n"
            "Returns a recent hashes per second performance measurement while generating.");
    }

    if (GetTimeMillis() - nHPSTimerStart > 8000)
    {
        return (boost::int64_t)0;
    }

    return (boost::int64_t)dHashesPerSec;
}


Value getmininginfo(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() != 0)
    {
        throw runtime_error(
            "getmininginfo \n"
            "Returns an object containing mining-related information.");
    }
   
    Object obj, diff, weight, chainshield, chainbuddy;

    obj.push_back(Pair("protocol_testnet",                          TestNet()));
    diff.push_back(Pair("proof-of-work minimum",                    GetDifficulty()));
    obj.push_back(Pair("difficulty",                                GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("netmhashps",                                GetPoWMHashPS()));
    obj.push_back(Pair("generate",                                  fGenerating));
    obj.push_back(Pair("genproclimit",                              GenerateProcLimit));
    obj.push_back(Pair("hashespersec",                              gethashespersec(params, false)));
    obj.push_back(Pair("errors",                                    GetWarnings("statusbar")));

    /*
    obj.push_back(Pair("blocks",                                    (int)nBestHeight));
    obj.push_back(Pair("bestblockhash",                             pindexBest->GetBlockHash().GetHex()));
    obj.push_back(Pair("blockvalue",                                (int64_t)GetProofOfWorkReward(pindexBest->nHeight, false)));
    obj.push_back(Pair("currentblocksize",                          (uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",                            (uint64_t)nLastBlockTx));
    obj.push_back(Pair("pooledtx",                                  (uint64_t)mempool.size()));
    */
    //diff.push_back(Pair("search-interval",                          (int)nLastCoinStakeSearchInterval));
    
    return obj;
}


Value getnetworkhashps(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() != 0)
    {
        throw runtime_error(
            "getnetworkhashps \n"
            "Returns network PoW hashes per second");
    }
   
    return GetPoWMHashPS();
}

Value getstakinginfo(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() != 0)
    {
        throw runtime_error("getstakinginfo \n"
                            "Returns an object containing staking-related information.");
    }

    uint64_t nWeight = 0;
    uint64_t nExpectedTime = 0;
    
    if (pwalletMain)
    {
        nWeight = pwalletMain->GetStakeWeight();
    }


    uint64_t nNetworkWeight = GetPoSKernelPS();
    bool staking = nLastCoinStakeSearchInterval && nWeight;
    nExpectedTime = staking ? (TARGET_SPACING * nNetworkWeight / nWeight) : 0;

    Object obj, errors, stakelog;

    std::string stake_error;

    if (staking == false)
    {
		if (pwalletMain
            && pwalletMain->IsLocked() == true)
		{
			stake_error = "Not staking because wallet is locked";
		}
        else if (vNodes.empty() == true)
		{
			stake_error = "Not staking because wallet is offline";
		}
		else if (vNodes.size() < 8)
		{
			stake_error = "Not staking because you need minimum 8 peers";
		}
		else if (IsInitialBlockDownload() == true)
		{
			stake_error = "Not staking because wallet is syncing";
		}
        else if (pindexBest->GetBlockTime() < GetTime() - 10 * 60)
		{
			stake_error = "Not staking, Waiting for full syncronization";
		}
        else if (!nWeight)
		{
			stake_error = "Not staking because you don't have mature coins";
		}
        else if (fStaking == true
            && nLastCoinStakeSearchInterval == 0
            && pwalletMain->GetStake() > 0)
		{
			stake_error = "Not staking, waiting to unlock coins...";
		}
        else if (fStaking == true
            && nLastCoinStakeSearchInterval == 0)
		{
			stake_error = "Not staking, waiting to sign a block.";
		}
        else if (fStaking == true)
		{
			stake_error = "Not staking, unknown error.";
		}
		else
		{
			stake_error = "Staking disabled.";
		}
    }		

    obj.push_back(Pair("protocol_testnet",                          TestNet()));
    obj.push_back(Pair("stake_enabled",                             fStaking));
    obj.push_back(Pair("stake_now",                                 staking));


#ifdef ENABLE_WALLET
    if (pwalletMain)
    {
        obj.push_back(Pair("stake_locked",                          ValueFromAmount(pwalletMain->GetStake())));
        obj.push_back(Pair("wallet_locked",                         pwalletMain->IsLocked()));
    }
#endif

    obj.push_back(Pair("stakeweight",                               (uint64_t)nWeight));
    obj.push_back(Pair("stakethreshold",                            GetStakeCombineThreshold() / COIN));
    obj.push_back(Pair("netstakeweight",                            (uint64_t)nNetworkWeight));
    obj.push_back(Pair("expectedtime",                              nExpectedTime));
    obj.push_back(Pair("difficulty",                                GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("search_interval",                           (int)nLastCoinStakeSearchInterval));

    stakelog.push_back(Pair("height",                                (int)LastBlockStake));
    stakelog.push_back(Pair("timestamp",                             (int)LastBlockStakeTime));
    obj.push_back(Pair("lastblockstake",                             stakelog));

    errors.push_back(Pair("stake_error",                            stake_error));
    errors.push_back(Pair("statusbar",                              GetWarnings("statusbar")));
    obj.push_back(Pair("errors",                                    errors));

    /*
    weight.push_back(Pair("minimum",                                (uint64_t)nWeight));
    weight.push_back(Pair("maximum",                                (uint64_t)0));
    weight.push_back(Pair("combined",                               (uint64_t)nWeight));
    obj.push_back(Pair("stakeweight",                               weight));
    */

    /*
    obj.push_back(Pair("blocks",                                    (int)nBestHeight));
    obj.push_back(Pair("bestblockhash",                             pindexBest->GetBlockHash().GetHex()));
    obj.push_back(Pair("blockvalue",                                (int64_t)GetProofOfWorkReward(pindexBest->nHeight, false)));
    obj.push_back(Pair("currentblocksize",                          (uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",                            (uint64_t)nLastBlockTx));
    obj.push_back(Pair("pooledtx",                                  (uint64_t)mempool.size()));
    */


    return obj;
}


Value checkkernel(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() < 1
        || params.size() > 2)
    {
        throw runtime_error("checkkernel [{\"txid\":txid,\"vout\":n},...] [createblocktemplate=false] \n"
                            "Check if one of given inputs is a kernel input at the moment. \n"
        );
    }

    RPCTypeCheck(params, list_of(array_type)(bool_type));

    Array inputs = params[0].get_array();
    
    bool fCreateBlockTemplate = params.size() > 1 ? params[1].get_bool() : false;

    if (vNodes.empty())
    {
        throw JSONRPCError(-9, "ERROR - PHC is not connected!");
    }

    if (IsInitialBlockDownload())
    {
        throw JSONRPCError(-10, "ERROR - PHC is downloading blocks...");
    }

    COutPoint kernel;
    CBlockIndex* pindexPrev = pindexBest;
    
    unsigned int nBits = GetNextTargetRequired(pindexPrev, true);
    
    int64_t nTime = GetAdjustedTime();
    
    nTime &= ~STAKE_TIMESTAMP_MASK;

    for(Value& input: inputs)
    {
        const Object& o = input.get_obj();

        const Value& txid_v = find_value(o, "txid");
        
        if (txid_v.type() != str_type)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "ERROR - Invalid parameter, missing txid key");
        }
        
        string txid = txid_v.get_str();
        
        if (!IsHex(txid))
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "ERROR - Invalid parameter, expected hex txid");
        }

        const Value& vout_v = find_value(o, "vout");
        
        if (vout_v.type() != int_type)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "ERROR - Invalid parameter, missing vout key");
        }
        
        int nOutput = vout_v.get_int();
        
        if (nOutput < 0)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "ERROR - Invalid parameter, vout must be positive");
        }

        COutPoint cInput(uint256(txid), nOutput);
        
        if (CheckKernel(pindexPrev, nBits, nTime, cInput))
        {
            kernel = cInput;

            break;
        }
    }

    Object result;
    result.push_back(Pair("found", !kernel.IsNull()));

    if (kernel.IsNull())
    {
        return result;
    }

    Object oKernel;
    oKernel.push_back(Pair("txid", kernel.hash.GetHex()));
    oKernel.push_back(Pair("vout", (int64_t)kernel.n));
    oKernel.push_back(Pair("time", nTime));
    result.push_back(Pair("kernel", oKernel));

    if (!fCreateBlockTemplate)
    {
        return result;
    }

    int64_t nFees;

    unique_ptr<CBlock> pblock(CreateNewBlock(*pMiningKey, true, &nFees));

    pblock->nTime = pblock->vtx[0].nTime = nTime;

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << *pblock;

    result.push_back(Pair("blocktemplate", HexStr(ss.begin(), ss.end())));
    result.push_back(Pair("blocktemplatefees", nFees));

    CPubKey pubkey;

    if (!pMiningKey->GetReservedKey(pubkey))
    {
        throw JSONRPCError(RPC_MISC_ERROR, "ERROR - GetReservedKey failed");
    }

    result.push_back(Pair("blocktemplatesignkey", HexStr(pubkey)));

    return result;
}


Value getworkex(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() > 2)
    {
        throw runtime_error("getworkex [data, coinbase] \n"
                            "If [data, coinbase] is not specified, returns extended work data. \n"
        );
    }

    if (vNodes.empty())
    {
        throw JSONRPCError(-9, "ERROR - PHC is not connected!");
    }

    if (IsInitialBlockDownload())
    {
        throw JSONRPCError(-10, "ERROR - PHC is downloading blocks...");
    }

    if (pindexBest->nHeight >= Params().LastPOWBlock())
    {
        throw JSONRPCError(RPC_MISC_ERROR, "ERROR - No more PoW blocks");
    }

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;
    static vector<CBlock*> vNewBlock;

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static CBlock* pblock;
        
        if (pindexPrev != pindexBest
            || (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast
            && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                
                for(CBlock* pblock: vNewBlock)
                {
                    delete pblock;
                }
                
                vNewBlock.clear();
            }

            nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            pindexPrev = pindexBest;
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(*pMiningKey);

            if (!pblock)
            {
                throw JSONRPCError(-7, "ERROR - Out of memory");
            }

            vNewBlock.push_back(pblock);
        }

        // Update nTime
        pblock->nTime = max(pindexPrev->GetPastTimeLimit()+1, GetAdjustedTime());
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;

        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Prebuild hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];

        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        CTransaction coinbaseTx = pblock->vtx[0];
        std::vector<uint256> merkle = pblock->GetMerkleBranch(0);

        Object result;
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << coinbaseTx;
        result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));

        Array merkle_arr;

        for(uint256 merkleh: merkle)
        {
            merkle_arr.push_back(HexStr(BEGIN(merkleh), END(merkleh)));
        }

        result.push_back(Pair("merkle", merkle_arr));

        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        vector<unsigned char> coinbase;

        if(params.size() == 2)
        {
            coinbase = ParseHex(params[1].get_str());
        }

        if (vchData.size() != 128)
        {
            throw JSONRPCError(-8, "ERROR - Invalid parameter");
        }

        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128/4; i++)
        {
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);
        }

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
        {
            return false;
        }

        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;

        if(coinbase.size() == 0)
        {
            pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        }
        else
        {
            // FIXME - HACK!
            CDataStream(coinbase, SER_NETWORK, PROTOCOL_VERSION) >> pblock->vtx[0];
        }

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        if (pwalletMain == NULL)
        {
            if (fDebug)
            {
                LogPrint("rpc", "%s : ERROR - pwalletMain = NULL \n", __FUNCTION__);
            }

            return Value::null;
        }

        return ProcessBlockFound(pblock, *pwalletMain, *pMiningKey);
    }
}


Value getwork(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() > 1)
    {
        throw runtime_error("getwork [data] \n"
                            "If [data] is not specified, returns formatted hash data to work on: \n"
                            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED) \n" // deprecated
                            "  \"data\" : block data \n"
                            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED) \n" // deprecated
                            "  \"target\" : little endian hash target \n"
                            "If [data] is specified, tries to solve the block and returns true if it was successful.");
    }

    if (vNodes.empty())
    {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "PHC is not connected!");
    }

    if (IsInitialBlockDownload())
    {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "PHC is downloading blocks...");
    }

    if (pindexBest->nHeight >= Params().LastPOWBlock())
    {
        throw JSONRPCError(RPC_MISC_ERROR, "No more PoW blocks");
    }

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    
    // FIXME: thread safety
    static mapNewBlock_t mapNewBlock;
    
    static vector<CBlock*> vNewBlock;

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static CBlock* pblock;
        
        if (pindexPrev != pindexBest
            || (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast
            && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                
                for(CBlock* pblock: vNewBlock)
                {
                    delete pblock;
                }

                vNewBlock.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = NULL;

            // Store the pindexBest used before CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrevNew = pindexBest;
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(*pMiningKey);

            if (!pblock)
            {
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            }
            
            vNewBlock.push_back(pblock);

            // Need to update only after we know CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }

        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;

        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];

        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        Object result;
        
         // deprecated
        result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate))));

        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));

         // deprecated
        result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1))));

        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));
        
        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        
        if (vchData.size() != 128)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
        
        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128/4; i++)
        {
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);
        }

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
        {
            return false;
        }
        
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;
        pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        if (pwalletMain == NULL)
        {
            if (fDebug)
            {
                LogPrint("rpc", "%s : ERROR - pwalletMain = NULL \n", __FUNCTION__);
            }

            return Value::null;
        }
        
        return ProcessBlockFound(pblock, *pwalletMain, *pMiningKey);
    }
}


Value getblocktemplate(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() > 1)
    {
        throw runtime_error("getblocktemplate [params] \n"
                            "Returns data needed to construct a block to work on: \n"
                            "  \"version\" : block version \n"
                            "  \"previousblockhash\" : hash of current highest  \n"
                            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block \n"
                            "  \"coinbaseaux\" : data that should be included in coinbase \n"
                            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees \n"
                            "  \"target\" : hash target \n"
                            "  \"mintime\" : minimum timestamp appropriate for next block \n"
                            "  \"curtime\" : current timestamp \n"
                            "  \"mutable\" : list of ways the block template may be changed \n"
                            "  \"noncerange\" : range of valid nonces \n"
                            "  \"sigoplimit\" : limit of sigops in blocks \n"
                            "  \"sizelimit\" : limit of block size \n"
                            "  \"bits\" : compressed target of next block \n"
                            "  \"height\" : height of the next block \n"
                            "  \"payee\" : \"xxx\",                (string) required payee for the next block \n"
                            "  \"payee_amount\" : n,               (numeric) required amount to pay \n"
                            "  \"votes\" : [\n                     (array) show vote candidates \n"
                            "        { ... }                       (json object) vote candidate \n"
                            "        ,...\n"
                            "  ],\n"
                            "  \"masternode_payments\" : true|false,         (boolean) true, if masternode payments are enabled"
                            "  \"enforce_masternode_payments\" : true|false  (boolean) true, if masternode payments are enforced"
                            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    }

    std::string strMode = "template";

    if (params.size() > 0)
    {
        const Object& oparam = params[0].get_obj();
        const Value& modeval = find_value(oparam, "mode");
        
        if (modeval.type() == str_type)
        {
            strMode = modeval.get_str();
        }
        else if (modeval.type() == null_type)
        {
            /* Do nothing */
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "ERROR - Invalid mode");
        }
    }

    if (strMode != "template")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ERROR - Invalid mode");
    }

    if (vNodes.empty())
    {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "ERROR - PHC is not connected!");
    }

    if (IsInitialBlockDownload())
    {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "ERROR - PHC is downloading blocks...");
    }

    if (pindexBest->nHeight >= Params().LastPOWBlock())
    {
        throw JSONRPCError(RPC_MISC_ERROR, "ERROR - No more PoW blocks");
    }

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CBlock* pblock;
    
    if (pindexPrev != pindexBest
        || (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast
        && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = pindexBest;
        nStart = GetTime();

        // Create new block
        if(pblock)
        {
            delete pblock;
            
            pblock = NULL;
        }

        pblock = CreateNewBlock(*pMiningKey);
        
        if (!pblock)
        {
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
        }

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    Array transactions;
    map<uint256, int64_t> setTxIndex;
    
    int i = 0;
    
    CTxDB txdb("r");
    
    for(CTransaction& tx: pblock->vtx)
    {
        uint256 txHash = tx.GetHash();

        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase()
            || tx.IsCoinStake())
        {
            continue;
        }

        Object entry;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;

        entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));

        entry.push_back(Pair("hash", txHash.GetHex()));

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        
        bool fInvalid = false;
        
        if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            entry.push_back(Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

            Array deps;
            
            for(MapPrevTx::value_type& inp: mapInputs)
            {
                if (setTxIndex.count(inp.first))
                {
                    deps.push_back(setTxIndex[inp.first]);
                }
            }

            entry.push_back(Pair("depends", deps));

            int64_t nSigOps = GetLegacySigOpCount(tx);
            nSigOps += GetP2SHSigOpCount(tx, mapInputs);

            entry.push_back(Pair("sigops", nSigOps));
        }

        transactions.push_back(entry);
    }

    Object aux;
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    static Array aMutable;
    
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    Object result;

    result.push_back(Pair("version",                pblock->nVersion));
    result.push_back(Pair("previousblockhash",      pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions",           transactions));
    result.push_back(Pair("coinbaseaux",            aux));
    result.push_back(Pair("coinbasevalue",          (int64_t)pblock->vtx[0].vout[0].nValue));
    result.push_back(Pair("target",                 hashTarget.GetHex()));
    result.push_back(Pair("mintime",                (int64_t)pindexPrev->GetPastTimeLimit()+1));
    result.push_back(Pair("mutable",                aMutable));
    result.push_back(Pair("noncerange",             "00000000ffffffff"));
    result.push_back(Pair("sigoplimit",             (int64_t)MAX_BLOCK_SIGOPS));
    result.push_back(Pair("sizelimit",              (int64_t)MAX_BLOCK_SIZE));
    result.push_back(Pair("curtime",                (int64_t)pblock->nTime));
    result.push_back(Pair("bits",                   strprintf("%08x", pblock->nBits)));
    result.push_back(Pair("height",                 (int64_t)(pindexPrev->nHeight+1)));

    return result;
}


Value submitblock(const Array& params, bool fHelp)
{
    if (fHelp
        || params.size() < 1
        || params.size() > 2)
    {
        throw runtime_error("submitblock <hex data> [optional-params-obj] \n"
                            "[optional-params-obj] parameter is currently ignored. \n"
                            "Attempts to submit new block to network. \n"
                            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    }

    vector<unsigned char> blockData(ParseHex(params[0].get_str()));

    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);

    CBlock block;

    try
    {
        ssBlock >> block;
    }
    catch (std::exception &e)
    {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    bool fAccepted = ProcessBlock(NULL, &block);

    if (!fAccepted)
    {
        return "rejected";
    }

    return Value::null;
}

