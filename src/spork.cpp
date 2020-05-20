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


#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "key.h"
#include "util.h"
#include "script.h"
#include "base58.h"
#include "protocol.h"
#include "spork.h"
#include "main.h"
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost;

class CSporkMessage;
class CSporkManager;

CSporkManager sporkManager;

std::map<uint256, CSporkMessage> mapSporks;
std::map<int, CSporkMessage> mapSporksActive;

void ProcessSpork(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if(fLiteMode)
    {
        //disable all darksend/masternode related functionality
        return;
    }

    if (strCommand == "spork")
    {
        if (fDebug)
        {
            LogPrint("spork", "%s : \n", __FUNCTION__);
        }

        CDataStream vMsg(vRecv);
        CSporkMessage spork;
        vRecv >> spork;

        if(pindexBest == NULL)
        {
            return;
        }

        uint256 hash = spork.GetHash();

        if(mapSporksActive.count(spork.nSporkID))
        {
            if(mapSporksActive[spork.nSporkID].nTimeSigned >= spork.nTimeSigned)
            {
                if(fDebug)
                {
                    LogPrint("spork", "%s : ERROR - Seen %s block %d \n", __FUNCTION__, hash.ToString().c_str(), pindexBest->nHeight);
                }

                return;
            }
            else
            {
                if(fDebug)
                {
                    LogPrint("spork", "%s : OK - Got updated spork %s block %d \n", __FUNCTION__, hash.ToString().c_str(), pindexBest->nHeight);
                }
            }
        }

        if (fDebug)
        {
            LogPrint("spork", "%s : NOTICE - New %s ID %d Time %d bestHeight %d \n", __FUNCTION__, hash.ToString().c_str(), spork.nSporkID, spork.nValue, pindexBest->nHeight);
        }

        if(!sporkManager.CheckSignature(spork))
        {
            if (fDebug)
            {
                LogPrint("spork", "%s : ERROR - Invalid signature \n", __FUNCTION__);
            }

            Misbehaving(pfrom->GetId(), 100);

            return;
        }

        mapSporks[hash] = spork;
        mapSporksActive[spork.nSporkID] = spork;

        sporkManager.Relay(spork);

        //does a task if needed
        ExecuteSpork(spork.nSporkID, spork.nValue);
    }

    if (strCommand == "getsporks")
    {
        std::map<int, CSporkMessage>::iterator it = mapSporksActive.begin();

        while(it != mapSporksActive.end())
        {
            pfrom->PushMessage("spork", it->second);

            it++;
        }
    }

}

// grab the spork, otherwise say it's off
bool IsSporkActive(int nSporkID)
{
    int64_t r = -1;

    if(mapSporksActive.count(nSporkID))
    {
        r = mapSporksActive[nSporkID].nValue;
    }
    else
    {
        switch (nSporkID)
        {
            case SPORK_1_MASTERNODE_PAYMENTS_ENFORCEMENT:
            {
                r = SPORK_1_MASTERNODE_PAYMENTS_ENFORCEMENT_DEFAULT;
            }
            break;

            case SPORK_2_INSTANTX:
            {
                r = SPORK_2_INSTANTX_DEFAULT;
            }
            break;

            case SPORK_3_INSTANTX_BLOCK_FILTERING:
            {
                r = SPORK_3_INSTANTX_BLOCK_FILTERING_DEFAULT;
            }
            break;

            case SPORK_5_MAX_VALUE:
            {
                r = SPORK_5_MAX_VALUE_DEFAULT;
            }
            break;

            case SPORK_6_REPLAY_BLOCKS:
            {
                r = SPORK_6_REPLAY_BLOCKS_DEFAULT;
            }
            break;

            case SPORK_7_MASTERNODE_SCANNING:
            {
                r = SPORK_7_MASTERNODE_SCANNING;
            }
            break;

            case SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT:
            {
                r = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT_DEFAULT;
            }
            break;

            case SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT:
            {
                r = SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT_DEFAULT;
            }
            break;

            case SPORK_10_MASTERNODE_PAY_UPDATED_NODES:
            {
                r = SPORK_10_MASTERNODE_PAY_UPDATED_NODES_DEFAULT;
            }
            break;

            case SPORK_11_RESET_BUDGET:
            {
                r = SPORK_11_RESET_BUDGET_DEFAULT;
            }
            break;

            case SPORK_12_RECONSIDER_BLOCKS:
            {
                r = SPORK_12_RECONSIDER_BLOCKS_DEFAULT;
            }
            break;

            case SPORK_13_ENABLE_SUPERBLOCKS:
            {
                r = SPORK_13_ENABLE_SUPERBLOCKS_DEFAULT;
            }
            break;
        }

        if(r == -1)
        {
            if (fDebug)
            {
                LogPrint("spork", "%s : OK - Spork %d \n", __FUNCTION__, nSporkID);
            }
        }
    }

    if(r == -1)
    {
        //return 2099-1-1 by default
        r = 4070908800; 
    }

    return r < GetTime();
}

// grab the value of the spork on the network, or the default
int64_t GetSporkValue(int nSporkID)
{
    int64_t r = -1;

    if(mapSporksActive.count(nSporkID))
    {
        r = mapSporksActive[nSporkID].nValue;
    }
    else
    {
        switch (nSporkID)
        {
            case SPORK_1_MASTERNODE_PAYMENTS_ENFORCEMENT:
            {
                r = SPORK_1_MASTERNODE_PAYMENTS_ENFORCEMENT_DEFAULT;
            }
            break;

            case SPORK_2_INSTANTX:
            {
                r = SPORK_2_INSTANTX_DEFAULT;
            }
            break;

            case SPORK_3_INSTANTX_BLOCK_FILTERING:
            {
                r = SPORK_3_INSTANTX_BLOCK_FILTERING_DEFAULT;
            }
            break;

            case SPORK_4_NOTUSED:
            {
                // NOT USED
            }
            break;

            case SPORK_5_MAX_VALUE:
            {
                r = SPORK_5_MAX_VALUE_DEFAULT;
            }
            break;

            case SPORK_6_REPLAY_BLOCKS:
            {
                r = SPORK_6_REPLAY_BLOCKS_DEFAULT;
            }
            break;

            case SPORK_7_MASTERNODE_SCANNING:
            {
                r = SPORK_7_MASTERNODE_SCANNING;
            }
            break;

            case SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT:
            {
                r = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT_DEFAULT;
            }
            break;

            case SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT:
            {
                r = SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT_DEFAULT;
            }
            break;

            case SPORK_10_MASTERNODE_PAY_UPDATED_NODES:
            {
                r = SPORK_10_MASTERNODE_PAY_UPDATED_NODES_DEFAULT;
            }
            break;

            case SPORK_11_RESET_BUDGET:
            {
                r = SPORK_11_RESET_BUDGET_DEFAULT;
            }
            break;

            case SPORK_12_RECONSIDER_BLOCKS:
            {
                r = SPORK_12_RECONSIDER_BLOCKS_DEFAULT;
            }
            break;

            case SPORK_13_ENABLE_SUPERBLOCKS:
            {
                r = SPORK_13_ENABLE_SUPERBLOCKS_DEFAULT;
            }
            break;
        }

        if(r == -1)
        {
            if (fDebug)
            {
                LogPrint("spork", "%s : OK - Spork %d \n", __FUNCTION__, nSporkID);
            }
        }
    }

    return r;
}


void ExecuteSpork(int nSporkID, int nValue)
{
}

/*void ReprocessBlocks(int nBlocks)
{
    std::map<uint256, int64_t>::iterator it = mapRejectedBlocks.begin();
    while(it != mapRejectedBlocks.end()){
        //use a window twice as large as is usual for the nBlocks we want to reset
        if((*it).second  > GetTime() - (nBlocks*60*5)) {
            BlockMap::iterator mi = mapBlockIndex.find((*it).first);
            if (mi != mapBlockIndex.end() && (*mi).second) {
                LOCK(cs_main);

                CBlockIndex* pindex = (*mi).second;
                
                if (fDebug)
                {
                    LogPrint("spork", "%s : OK - ReprocessBlocks - %s \n", __FUNCTION__, (*it).first.ToString());
                }

                CValidationState state;
                ReconsiderBlock(state, pindex);
            }
        }
        ++it;
    }

    CValidationState state;
    {
        LOCK(cs_main);
        DisconnectBlocksAndReprocess(nBlocks);
    }

    if (state.IsValid()) {
        ActivateBestChain(state);
    }
}*/


bool CSporkManager::CheckSignature(CSporkMessage& spork)
{
    //note: need to investigate why this is failing
    std::string strMessage = boost::lexical_cast<std::string>(spork.nSporkID)
                            + boost::lexical_cast<std::string>(spork.nValue)
                            + boost::lexical_cast<std::string>(spork.nTimeSigned);

    std::string strPubKey = strMainPubKey;
    
    CPubKey pubkey(ParseHex(strPubKey));

    std::string errorMessage = "";

    if(!darkSendSigner.VerifyMessage(pubkey, spork.vchSig, strMessage, errorMessage))
    {
        return false;
    }

    return true;
}


bool CSporkManager::Sign(CSporkMessage& spork)
{
    std::string strMessage = boost::lexical_cast<std::string>(spork.nSporkID)
                            + boost::lexical_cast<std::string>(spork.nValue)
                            + boost::lexical_cast<std::string>(spork.nTimeSigned);

    CKey key2;
    CPubKey pubkey2;

    std::string errorMessage = "";

    if(!darkSendSigner.SetKey(strMasterPrivKey, errorMessage, key2, pubkey2))
    {
        if (fDebug)
        {
            LogPrint("spork", "%s : ERROR - Invalid masternodeprivkey: '%s' \n", __FUNCTION__, errorMessage.c_str());
        }

        return false;
    }

    if(!darkSendSigner.SignMessage(strMessage, errorMessage, spork.vchSig, key2))
    {
        if (fDebug)
        {
            LogPrint("spork", "%s : ERROR - Sign message failed \n", __FUNCTION__);
        }

        return false;
    }

    if(!darkSendSigner.VerifyMessage(pubkey2, spork.vchSig, strMessage, errorMessage))
    {
        if (fDebug)
        {
            LogPrint("spork", "%s : ERROR - Verify message failed \n", __FUNCTION__);
        }

        return false;
    }

    return true;
}


bool CSporkManager::UpdateSpork(int nSporkID, int64_t nValue)
{

    CSporkMessage msg;

    msg.nSporkID = nSporkID;
    msg.nValue = nValue;
    msg.nTimeSigned = GetTime();

    if(Sign(msg))
    {
        Relay(msg);

        mapSporks[msg.GetHash()] = msg;
        mapSporksActive[nSporkID] = msg;

        return true;
    }

    return false;
}


void CSporkManager::Relay(CSporkMessage& msg)
{
    CInv inv(MSG_SPORK, msg.GetHash());

    RelayInventory(inv);
}


bool CSporkManager::SetPrivKey(std::string strPrivKey)
{
    CSporkMessage msg;

    // Test signing successful, proceed
    strMasterPrivKey = strPrivKey;

    Sign(msg);

    if(CheckSignature(msg))
    {
        if (fDebug)
        {
            LogPrint("spork", "%s : OK - Successfully initialized as spork signer \n", __FUNCTION__);
        }
        
        return true;
    }
    else
    {
        return false;
    }
}


int CSporkManager::GetSporkIDByName(std::string strName)
{
    if(strName == "SPORK_1_MASTERNODE_PAYMENTS_ENFORCEMENT")
    {
        return SPORK_1_MASTERNODE_PAYMENTS_ENFORCEMENT;
    }

    if(strName == "SPORK_2_INSTANTX")
    {
        return SPORK_2_INSTANTX;
    }

    if(strName == "SPORK_3_INSTANTX_BLOCK_FILTERING")
    {
        return SPORK_3_INSTANTX_BLOCK_FILTERING;
    }

    if(strName == "SPORK_5_MAX_VALUE")
    {
        return SPORK_5_MAX_VALUE;
    }

    if(strName == "SPORK_6_REPLAY_BLOCKS")
    {
        return SPORK_6_REPLAY_BLOCKS;
    }

    if(strName == "SPORK_7_MASTERNODE_SCANNING")
    {
        return SPORK_7_MASTERNODE_SCANNING;
    }

    if(strName == "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT")
    {
        return SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
    }

    if(strName == "SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT")
    {
        return SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT;
    }

    if(strName == "SPORK_10_MASTERNODE_PAY_UPDATED_NODES")
    {
        return SPORK_10_MASTERNODE_PAY_UPDATED_NODES;
    }

    if(strName == "SPORK_11_RESET_BUDGET")
    {
        return SPORK_11_RESET_BUDGET;
    }
    
    if(strName == "SPORK_12_RECONSIDER_BLOCKS")
    {
        return SPORK_12_RECONSIDER_BLOCKS;
    }

    if(strName == "SPORK_13_ENABLE_SUPERBLOCKS")
    {
        return SPORK_13_ENABLE_SUPERBLOCKS;
    }

    return -1;
}


std::string CSporkManager::GetSporkNameByID(int id)
{
    if(id == SPORK_1_MASTERNODE_PAYMENTS_ENFORCEMENT)
    {
        return "SPORK_1_MASTERNODE_PAYMENTS_ENFORCEMENT";
    }

    if(id == SPORK_2_INSTANTX)
    {
        return "SPORK_2_INSTANTX";
    }

    if(id == SPORK_3_INSTANTX_BLOCK_FILTERING)
    {
        return "SPORK_3_INSTANTX_BLOCK_FILTERING";
    }

    if(id == SPORK_5_MAX_VALUE)
    {
        return "SPORK_5_MAX_VALUE";
    }

    if(id == SPORK_6_REPLAY_BLOCKS)
    {
        return "SPORK_6_REPLAY_BLOCKS";
    }

    if(id == SPORK_7_MASTERNODE_SCANNING)
    {
        return "SPORK_7_MASTERNODE_SCANNING";
    }

    if(id == SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT)
    {
        return "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT";
    }

    if(id == SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT)
    {
        return "SPORK_9_MASTERNODE_BUDGET_ENFORCEMENT";
    }

    if(id == SPORK_10_MASTERNODE_PAY_UPDATED_NODES)
    {
        return "SPORK_10_MASTERNODE_PAY_UPDATED_NODES";
    }

    if(id == SPORK_11_RESET_BUDGET)
    {
        return "SPORK_11_RESET_BUDGET";
    }

    if(id == SPORK_12_RECONSIDER_BLOCKS)
    {
        return "SPORK_12_RECONSIDER_BLOCKS";
    }

    if(id == SPORK_13_ENABLE_SUPERBLOCKS)
    {
        return "SPORK_13_ENABLE_SUPERBLOCKS";
    }

    return "Unknown";
}