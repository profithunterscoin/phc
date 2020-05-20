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


#include "darksend.h"
#include "main.h"
#include "init.h"
#include "util.h"
#include "masternodeman.h"
#include "instantx.h"
#include "ui_interface.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <algorithm>
#include <boost/assign/list_of.hpp>
#include <openssl/rand.h>

/* ONLY NEEDED FOR UNIT TESTING */
#include <iostream>

using namespace std;
using namespace boost;

// The main object for accessing darksend
CDarksendPool darkSendPool;

// A helper object for signing messages from Masternodes
CDarkSendSigner darkSendSigner;

// The current darksends in progress on the network
std::vector<CDarksendQueue> vecDarksendQueue;

// Keep track of the used Masternodes
std::vector<CTxIn> vecMasternodesUsed;

// keep track of the scanning errors I've seen
map<uint256, CDarksendBroadcastTx> mapDarksendBroadcastTxes;

// Keep track of the active Masternode
CActiveMasternode activeMasternode;

// count peers we've requested the list from
int RequestedMasterNodeList = 0;

/* *** BEGIN DARKSEND MAGIC - DASH **********
    Copyright (c) 2014-2015, Dash Developers
        eduffield - evan@dashpay.io
        udjinm6   - udjinm6@dashpay.io
*/


void CDarksendPool::ProcessMessageDarksend(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if(fLiteMode)
    {
        //disable all darksend/Masternode related functionality
        return; 
    }

    if(!IsBlockchainSynced())
    {
        return;
    }

    if (strCommand == "dsa")
    {
        //DarkSend Accept Into Pool

        if (pfrom->nVersion < MIN_POOL_PEER_PROTO_VERSION)
        {
            std::string strError = _("Incompatible version.");

            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsa incompatible version! \n", __FUNCTION__);
            }

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, strError);

            return;
        }

        if(!fMasterNode)
        {
            std::string strError = _("This is not a Masternode.");

            if (fDebug)
            {
                LogPrint("darksend", "%s : dsa not a Masternode! \n", __FUNCTION__);
            }

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, strError);

            return;
        }

        int nDenom;
        CTransaction txCollateral;
        vRecv >> nDenom >> txCollateral;
        std::string error = "";

        CMasternode* pmn = mnodeman.Find(activeMasternode.vin);

        if(pmn == NULL)
        {
            std::string strError = _("Not in the Masternode list.");

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, strError);

            return;
        }

        if(sessionUsers == 0)
        {
            if(pmn->nLastDsq != 0
                && pmn->nLastDsq + mnodeman.CountMasternodesAboveProtocol(MIN_POOL_PEER_PROTO_VERSION)/5 > mnodeman.nDsqCount)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - dsa last dsq too recent, must wait. %s \n", __FUNCTION__, pfrom->addr.ToStringIPPort().c_str());
                }

                std::string strError = _("Last Darksend was too recent.");

                pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, strError);

                return;
            }
        }

        if(!IsCompatibleWithSession(nDenom, txCollateral, error))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsa not compatible with existing transactions! \n", __FUNCTION__);
            }

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

            return;
        }
        else
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsa is compatible, please submit! \n", __FUNCTION__);
            }

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_ACCEPTED, error);

            return;
        }
    }
    else if (strCommand == "dsq")
    {
        //Darksend Queue

        TRY_LOCK(cs_darksend, lockRecv);

        if(!lockRecv)
        {
            return;
        }

        if (pfrom->nVersion < MIN_POOL_PEER_PROTO_VERSION) 
        {
            return;
        }

        CDarksendQueue dsq;
        vRecv >> dsq;

        CService addr;

        if(!dsq.GetAddress(addr))
        {
            return;
        }

        if(!dsq.CheckSignature())
        {
            return;
        }

        if(dsq.IsExpired())
        {
            return;
        }

        CMasternode* pmn = mnodeman.Find(dsq.vin);

        if(pmn == NULL)
        {
            return;
        }

        // if the queue is ready, submit if we can
        if(dsq.ready)
        {
            if(!pSubmittedToMasternode)
            {
                return;
            }

            if((CNetAddr)pSubmittedToMasternode->addr != (CNetAddr)addr)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - dsq message doesn't match current Masternode - %s != %s \n", __FUNCTION__, pSubmittedToMasternode->addr.ToStringIPPort().c_str(), addr.ToStringIPPort().c_str());
                }

                return;
            }

            if(state == POOL_STATUS_QUEUE)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : OK - Darksend queue is ready - %s \n", __FUNCTION__, addr.ToStringIPPort().c_str());
                }

                PrepareDarksendDenominate();
            }
        }
        else
        {
            for(CDarksendQueue q: vecDarksendQueue)
            {
                if(q.vin == dsq.vin)
                {
                    return;
                }
            }

            if (fDebug)
            {
                LogPrint("darksend", "%s : NOTICE - dsq last %d last2 %d count %d \n", pmn->nLastDsq, pmn->nLastDsq + mnodeman.size()/5, mnodeman.nDsqCount);
            }

            //don't allow a few nodes to dominate the queuing process
            if(pmn->nLastDsq != 0 && pmn->nLastDsq + mnodeman.CountMasternodesAboveProtocol(MIN_POOL_PEER_PROTO_VERSION)/5 > mnodeman.nDsqCount)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - dsq Masternode sending too many dsq messages. %s \n", __FUNCTION__, pmn->addr.ToStringIPPort().c_str());
                }

                return;
            }

            mnodeman.nDsqCount++;

            pmn->nLastDsq = mnodeman.nDsqCount;
            pmn->allowFreeTx = true;

            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - dsq new Darksend queue object - %s\n", __FUNCTION__, addr.ToStringIPPort().c_str());
            }

            vecDarksendQueue.push_back(dsq);

            dsq.Relay();
            dsq.time = GetTime();
        }

    }
    else if (strCommand == "dsi")
    {
        //DarkSend vIn

        std::string error = "";
        if (pfrom->nVersion < MIN_POOL_PEER_PROTO_VERSION)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsi incompatible version! \n", __FUNCTION__);
            }

            error = _("Incompatible version.");

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

            return;
        }

        if(!fMasterNode)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsi not a Masternode! \n", __FUNCTION__);
            }

            error = _("This is not a Masternode.");

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

            return;
        }

        std::vector<CTxIn> in;
        std::vector<CTxOut> out;

        int64_t nAmount;

        CTransaction txCollateral;

        vRecv >> in >> nAmount >> txCollateral >> out;

        //do we have enough users in the current session?
        if(!IsSessionReady())
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsi session not complete! \n", __FUNCTION__);
            }

            error = _("Session not complete!");

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);
            
            return;
        }

        //do we have the same denominations as the current session?
        if(!IsCompatibleWithEntries(out))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsi not compatible with existing transactions! \n", __FUNCTION__);
            }

            error = _("Not compatible with existing transactions.");

            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);
            
            return;
        }

        //check it like a transaction
        {
            int64_t nValueIn = 0;
            int64_t nValueOut = 0;
            bool missingTx = false;

            CValidationState state;
            CTransaction tx;

            for(const CTxOut o: out)
            {
                nValueOut += o.nValue;

                tx.vout.push_back(o);

                if(o.scriptPubKey.size() != 25)
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - dsi non-standard pubkey detected! %s \n", __FUNCTION__, o.scriptPubKey.ToString().c_str());
                    }

                    error = _("Non-standard public key detected.");

                    pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

                    return;
                }

                if(!o.scriptPubKey.IsNormalPaymentScript())
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - dsi invalid script! %s \n", __FUNCTION__, o.scriptPubKey.ToString().c_str());
                    }

                    error = _("Invalid script detected.");

                    pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

                    return;
                }
            }

            for(const CTxIn i: in)
            {
                tx.vin.push_back(i);

                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - dsi tx in %s \n", __FUNCTION__, i.ToString().c_str());
                }

                CTransaction tx2;
                uint256 hash;

                if(GetTransaction(i.prevout.hash, tx2, hash))
                {
                    if(tx2.vout.size() > i.prevout.n)
                    {
                        nValueIn += tx2.vout[i.prevout.n].nValue;
                    }
                }
                else
                {
                    missingTx = true;
                }
            }

            if (nValueIn > DARKSEND_POOL_MAX)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - dsi more than Darksend pool max! %s \n", __FUNCTION__, tx.ToString().c_str());
                }

                error = _("Value more than Darksend pool maximum allows.");

                pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

                return;
            }

            if(!missingTx)
            {
                if (nValueIn-nValueOut > nValueIn*.01)
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - dsi fees are too high! %s \n", __FUNCTION__, tx.ToString().c_str());
                    }

                    error = _("Transaction fees are too high.");

                    pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

                    return;
                }
            }
            else
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - dsi missing input tx! %s \n", __FUNCTION__, tx.ToString().c_str());
                }

                error = _("Missing input transaction information.");

                pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

                return;
            }

            if(!AcceptableInputs(mempool, tx, false, NULL, false, true))
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - dsi transaction not valid! \n", __FUNCTION__);
                }

                error = _("Transaction not valid.");

                pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);

                return;
            }
        }

        if(AddEntry(in, nAmount, txCollateral, out, error))
        {
            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_ACCEPTED, error);

            Check();

            RelayStatus(sessionID, GetState(), GetEntriesCount(), MASTERNODE_RESET);
        }
        else
        {
            pfrom->PushMessage("dssu", sessionID, GetState(), GetEntriesCount(), MASTERNODE_REJECTED, error);
        }
    }
    else if (strCommand == "dssu")
    {
        //Darksend status update

        if (pfrom->nVersion < MIN_POOL_PEER_PROTO_VERSION)
        {
            return;
        }

        if(!pSubmittedToMasternode)
        {
            return;
        }

        if((CNetAddr)pSubmittedToMasternode->addr != (CNetAddr)pfrom->addr)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dssu message doesn't match current Masternode - %s != %s \n", __FUNCTION__, pSubmittedToMasternode->addr.ToStringIPPort().c_str(), pfrom->addr.ToStringIPPort().c_str());
            }

            return;
        }

        int sessionIDMessage;
        int state;
        int entriesCount;
        int accepted;

        std::string error;
        vRecv >> sessionIDMessage >> state >> entriesCount >> accepted >> error;

        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - dssu state: %i entriesCount: %i accepted: %i error: %s \n", __FUNCTION__, state, entriesCount, accepted, error.c_str());
        }

        if((accepted != 1 && accepted != 0) && sessionID != sessionIDMessage)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dssu message doesn't match current Darksend session %d %d \n", __FUNCTION__, sessionID, sessionIDMessage);
            }

            return;
        }

        StatusUpdate(state, entriesCount, accepted, error, sessionIDMessage);

    }
    else if (strCommand == "dss")
    {
        //DarkSend Sign Final Tx

        if (pfrom->nVersion < MIN_POOL_PEER_PROTO_VERSION)
        {
            return;
        }

        vector<CTxIn> sigs;
        vRecv >> sigs;

        bool success = false;
        int count = 0;

        for(const CTxIn item: sigs)
        {
            if(AddScriptSig(item)) 
            {
                success = true;
            }

            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - sigs count %d %d\n", __FUNCTION__, (int)sigs.size(), count);
            }

            count++;
        }

        if(success)
        {
            darkSendPool.Check();

            RelayStatus(darkSendPool.sessionID, darkSendPool.GetState(), darkSendPool.GetEntriesCount(), MASTERNODE_RESET);
        }
    }
    else if (strCommand == "dsf")
    {
        //Darksend Final tx

        if (pfrom->nVersion < MIN_POOL_PEER_PROTO_VERSION)
        {
            return;
        }

        if(!pSubmittedToMasternode)
        {
            return;
        }

        if((CNetAddr)pSubmittedToMasternode->addr != (CNetAddr)pfrom->addr)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsc message doesn't match current Masternode - %s != %s \n", __FUNCTION__, pSubmittedToMasternode->addr.ToStringIPPort().c_str(), pfrom->addr.ToStringIPPort().c_str());
            }

            return;
        }

        int sessionIDMessage;

        CTransaction txNew;
        vRecv >> sessionIDMessage >> txNew;

        if(sessionID != sessionIDMessage)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - dsf message doesn't match current darksend session %d %d \n", __FUNCTION__, sessionID, sessionIDMessage);
            }

            return;
        }

        //check to see if input is spent already? (and probably not confirmed)
        SignFinalTransaction(txNew, pfrom);
    }
    else if (strCommand == "dsc")
    {
        //Darksend Complete
        if (pfrom->nVersion < MIN_POOL_PEER_PROTO_VERSION)
        {
            return;
        }

        if(!pSubmittedToMasternode)
        {
            return;
        }

        if((CNetAddr)pSubmittedToMasternode->addr != (CNetAddr)pfrom->addr)
        {
            LogPrint("darksend", "%s : ERROR - dsc message doesn't match current Masternode - %s != %s \n", __FUNCTION__, pSubmittedToMasternode->addr.ToStringIPPort().c_str(), pfrom->addr.ToStringIPPort().c_str());
            
            return;
        }

        int sessionIDMessage;
        bool error;
        int errorID;
        vRecv >> sessionIDMessage >> error >> errorID;

        if(sessionID != sessionIDMessage)
        {
            LogPrint("darksend", "%s : ERROR - dsc message doesn't match current darksend session %d %d \n", __FUNCTION__, darkSendPool.sessionID, sessionIDMessage);

            return;
        }

        darkSendPool.CompletedTransaction(error, errorID);
    }

}


int randomizeList (int i)
{
    return std::rand()%i;
}


void CDarksendPool::Reset()
{
    cachedLastSuccess = 0;
    lastNewBlock = 0;

    txCollateral = CTransaction();

    vecMasternodesUsed.clear();

    UnlockCoins();

    SetNull();
}


void CDarksendPool::SetNull()
{

    // MN side
    sessionUsers = 0;
    vecSessionCollateral.clear();

    // Client side
    entriesCount = 0;
    lastEntryAccepted = 0;
    countEntriesAccepted = 0;
    sessionFoundMasternode = false;

    // Both sides
    state = POOL_STATUS_IDLE;
    sessionID = 0;
    sessionDenom = 0;
    entries.clear();

    finalTransaction.vin.clear();
    finalTransaction.vout.clear();

    lastTimeChanged = GetTimeMillis();

    // -- seed random number generator (used for ordering output lists)
    unsigned int seed = 0;

    RAND_bytes((unsigned char*)&seed, sizeof(seed));

    std::srand(seed);
}


bool CDarksendPool::SetCollateralAddress(std::string strAddress)
{
    CCoinAddress address;

    if (!address.SetString(strAddress))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Invalid DarkSend collateral address \n", __FUNCTION__);
        }

        return false;
    }

    collateralPubKey = GetScriptForDestination(address.Get());

    return true;
}


//
// Unlock coins after Darksend fails or succeeds
//
void CDarksendPool::UnlockCoins()
{
    while(true)
    {
        TRY_LOCK(pwalletMain->cs_wallet, lockWallet);

        if(!lockWallet)
        {
            MilliSleep(50);

            continue;
        }

        for(CTxIn v: lockedCoins)
        {
            pwalletMain->UnlockCoin(v.prevout);
        }

        break;
    }

    lockedCoins.clear();
}


/// from masternode-sync.cpp
bool CDarksendPool::IsBlockchainSynced()
{
    static bool fBlockchainSynced = false;
    static int64_t lastProcess = GetTime();

    // if the last call to this function was more than 60 minutes ago (client was in sleep mode) reset the sync process
    if(GetTime() - lastProcess > 60*60)
    {
        Reset();

        fBlockchainSynced = false;
    }

    lastProcess = GetTime();

    if(fBlockchainSynced)
    {
        return true;
    }

    if (fImporting || fReindex)
    {
        return false;
    }

    TRY_LOCK(cs_main, lockMain);

    if(!lockMain)
    {
        return false;
    }

    CBlockIndex* pindex = pindexBest;

    if(pindex == NULL)
    {
        return false;
    }

    if(pindex->nTime + 60*60 < GetTime())
    {
        return false;
    }

    fBlockchainSynced = true;

    return true;
}


std::string CDarksendPool::GetStatus()
{
    static int showingDarkSendMessage = 0;

    showingDarkSendMessage += 10;

    std::string suffix = "";

    if(pindexBest->nHeight - cachedLastSuccess < minBlockSpacing
        || !IsBlockchainSynced())
    {
        return strAutoDenomResult;
    }

    switch(state)
    {
        case POOL_STATUS_IDLE:
        {
            return _("Darksend is idle.");
        }

        case POOL_STATUS_ACCEPTING_ENTRIES:
        {
            if(entriesCount == 0)
            {
                showingDarkSendMessage = 0;
                
                return strAutoDenomResult;
            }
            else if (lastEntryAccepted == 1)
            {
                if(showingDarkSendMessage % 10 > 8)
                {
                    lastEntryAccepted = 0;
                    showingDarkSendMessage = 0;
                }

                return _("Darksend request complete:") + " " + _("Your transaction was accepted into the pool!");
            }
            else
            {
                std::string suffix = "";
                
                if (showingDarkSendMessage % 70 <= 40)
                {
                    return strprintf(_("%s : NOTICE - Submitted following entries to masternode: %u / %d"), __FUNCTION__, entriesCount, GetMaxPoolTransactions());
                }
                else if(showingDarkSendMessage % 70 <= 50)
                {
                    suffix = ".";
                }
                else if(showingDarkSendMessage % 70 <= 60)
                {
                    suffix = "..";
                }
                else if(showingDarkSendMessage % 70 <= 70)
                {
                    suffix = "...";
                }
                
                return strprintf(_("%s : OK - Submitted to masternode, waiting for more entries ( %u / %d ) %s"), __FUNCTION__, entriesCount, GetMaxPoolTransactions(), suffix);
            }
        }

        case POOL_STATUS_SIGNING:
        {
            if(      showingDarkSendMessage % 70 <= 40)
            {
                return _("Darksend Found enough users, signing ...");
            }
            else if (showingDarkSendMessage % 70 <= 50)
            {
                suffix = ".";
            } 
            else if (showingDarkSendMessage % 70 <= 60)
            {
                suffix = "..";
            }
            else if (showingDarkSendMessage % 70 <= 70)
            {
                suffix = "...";
            } 

            return strprintf(_("%s : OK - Found enough users, signing ( waiting %s )"), __FUNCTION__, suffix);
        }


        case POOL_STATUS_TRANSMISSION:
        {
            return _("Darksend Transmitting final transaction.");
        }

        case POOL_STATUS_FINALIZE_TRANSACTION:
        {
            return _("Darksend Finalizing transaction.");
        }

        case POOL_STATUS_ERROR:
        {
            return _("Darksend request incomplete:") + " " + lastMessage + " " + _("Will retry...");
        }

        case POOL_STATUS_SUCCESS:
        {
            return _("Darksend request complete:") + " " + lastMessage;
        }

        case POOL_STATUS_QUEUE:
        {
            if(     showingDarkSendMessage % 70 <= 30)
            {
                suffix = ".";
            }
            else if(showingDarkSendMessage % 70 <= 50)
            {
                suffix = "..";
            }
            else if(showingDarkSendMessage % 70 <= 70)
            {
                suffix = "...";
            }

            return strprintf(_("%s : OK - Submitted to masternode, waiting in queue %s"), __FUNCTION__, suffix);;
        }

       default:
       {
            return strprintf(_("%s : ERROR - Unknown state: id = %u"), __FUNCTION__, state);
       }
    }
}


//
// Check the Darksend progress and send client updates if a Masternode
//
void CDarksendPool::Check()
{
    if(fMasterNode)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - Entries count %lu \n", __FUNCTION__, entries.size());
        }
    }

    //printf("CDarksendPool::Check() %d - %d - %d\n", state, anonTx.CountEntries(), GetTimeMillis()-lastTimeChanged);

    if(fMasterNode)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - Entries count %lu \n", __FUNCTION__, entries.size());
        }

        // If entries is full, then move on to the next phase
        if(state == POOL_STATUS_ACCEPTING_ENTRIES
            && (int)entries.size() >= GetMaxPoolTransactions())
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : NOTICE - TRYING TRANSACTION \n", __FUNCTION__);
            }

            UpdateState(POOL_STATUS_FINALIZE_TRANSACTION);
        }
    }

    // create the finalized transaction for distribution to the clients
    if(state == POOL_STATUS_FINALIZE_TRANSACTION)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - FINALIZE TRANSACTIONS \n", __FUNCTION__);
        }

        UpdateState(POOL_STATUS_SIGNING);

        if (fMasterNode)
        {
            CTransaction txNew;

            // make our new transaction
            for(unsigned int i = 0; i < entries.size(); i++)
            {
                for(const CTxOut& v: entries[i].vout)
                {
                    txNew.vout.push_back(v);
                }

                for(const CTxDSIn& s: entries[i].sev)
                {
                    txNew.vin.push_back(s);
                }
            }

            // shuffle the outputs for improved anonymity
            std::random_shuffle ( txNew.vin.begin(),  txNew.vin.end(),  randomizeList);
            std::random_shuffle ( txNew.vout.begin(), txNew.vout.end(), randomizeList);

            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - Transaction 1: %s \n", __FUNCTION__, txNew.ToString());
            }

            finalTransaction = txNew;

            // request signatures from clients
            RelayFinalTransaction(sessionID, finalTransaction);
        }
    }

    // If we have all of the signatures, try to compile the transaction
    if(fMasterNode && state == POOL_STATUS_SIGNING && SignaturesComplete())
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - SIGNING \n", __FUNCTION__);
        }

        UpdateState(POOL_STATUS_TRANSMISSION);

        CheckFinalTransaction();
    }

    // reset if we're here for 10 seconds
    if((state == POOL_STATUS_ERROR
        || state == POOL_STATUS_SUCCESS)
        && GetTimeMillis()-lastTimeChanged >= 10000)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Timeout, RESETTING \n", __FUNCTION__);
        }

        UnlockCoins();
        
        SetNull();
        
        if(fMasterNode)
        {
            RelayStatus(sessionID, GetState(), GetEntriesCount(), MASTERNODE_RESET);
        }
    }
}


void CDarksendPool::CheckFinalTransaction()
{
    if (!fMasterNode)
    {
        return; // check and relay final tx only on masternode
    }

    CWalletTx txNew = CWalletTx(pwalletMain, finalTransaction);

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Global Namespace Start
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - Transaction 2: %s \n", __FUNCTION__, txNew.ToString());
        }

        // See if the transaction is valid
        if (!txNew.AcceptToMemoryPool(false, true, true))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Commit Transaction not valid \n", __FUNCTION__);
            }

            SetNull();

            // not much we can do in this case
            UpdateState(POOL_STATUS_ACCEPTING_ENTRIES);

            RelayCompletedTransaction(sessionID, true, _("Transaction not valid, please try again"));

            return;
        }

        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - IS MASTER TRANSMITTING DARKSEND \n", __FUNCTION__);
        }

        // sign a message

        int64_t sigTime = GetAdjustedTime();

        std::string strMessage = txNew.GetHash().ToString() + boost::lexical_cast<std::string>(sigTime);
        std::string strError = "";
        std::vector<unsigned char> vchSig;

        CKey key2;
        CPubKey pubkey2;

        if(!darkSendSigner.SetKey(strMasterNodePrivKey, strError, key2, pubkey2))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Invalid Masternodeprivkey: '%s' \n", __FUNCTION__, strError);
            }

            return;
        }

        if(!darkSendSigner.SignMessage(strMessage, strError, vchSig, key2))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Sign message failed \n", __FUNCTION__);
            }

            return;
        }

        if(!darkSendSigner.VerifyMessage(pubkey2, vchSig, strMessage, strError))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Verify message failed \n", __FUNCTION__);
            }

            return;
        }

        string txHash = txNew.GetHash().ToString().c_str();

        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - txHash %d \n", __FUNCTION__, txHash);
        }

        if(!mapDarksendBroadcastTxes.count(txNew.GetHash()))
        {
            CDarksendBroadcastTx dstx;
            dstx.tx = txNew;
            dstx.vin = activeMasternode.vin;
            dstx.vchSig = vchSig;
            dstx.sigTime = sigTime;

            mapDarksendBroadcastTxes.insert(make_pair(txNew.GetHash(), dstx));
        }

        CInv inv(MSG_DSTX, txNew.GetHash());
        RelayInventory(inv);

        // Tell the clients it was successful
        RelayCompletedTransaction(sessionID, false, _("Transaction created successfully."));

        // Randomly charge clients
        ChargeRandomFees();

        // Reset
        LogPrint("darksend", "%s : OK - COMPLETED RESETTING \n", __FUNCTION__);

        SetNull();

        RelayStatus(sessionID, GetState(), GetEntriesCount(), MASTERNODE_RESET);
    }
    // Global Namespace End
}


//
// Charge clients a fee if they're abusive
//
// Why bother? Darksend uses collateral to ensure abuse to the process is kept to a minimum.
// The submission and signing stages in darksend are completely separate. In the cases where
// a client submits a transaction then refused to sign, there must be a cost. Otherwise they
// would be able to do this over and over again and bring the mixing to a hault.
//
// How does this work? Messages to Masternodes come in via "dsi", these require a valid collateral
// transaction for the client to be able to enter the pool. This transaction is kept by the Masternode
// until the transaction is either complete or fails.
//
void CDarksendPool::ChargeFees()
{
    if(!fMasterNode) 
    {
        return;
    }

    //we don't need to charge collateral for every offence.
    int offences = 0;
    int r = rand()%100;

    if(r > 33)
    {
        return;
    }

    if(state == POOL_STATUS_ACCEPTING_ENTRIES)
    {
        for(const CTransaction& txCollateral: vecSessionCollateral)
        {
            bool found = false;

            for(const CDarkSendEntry& v: entries)
            {
                if(v.collateral == txCollateral)
                {
                    found = true;
                }
            }

            // This queue entry didn't send us the promised transaction
            if(!found)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - Found uncooperative node (didn't send transaction). Found offence. \n", __FUNCTION__);
                }

                offences++;
            }
        }
    }

    if(state == POOL_STATUS_SIGNING)
    {
        // who didn't sign?
        for(const CDarkSendEntry v: entries)
        {
            for(const CTxDSIn s: v.sev)
            {
                if(!s.fHasSig)
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - Found uncooperative node (didn't sign). Found offence \n", __FUNCTION__);
                    }

                    offences++;
                }
            }
        }
    }

    r = rand()%100;
    int target = 0;

    //mostly offending?
    if(offences >= Params().PoolMaxTransactions()-1
        && r > 33)
    {
        return;
    }

    //everyone is an offender? That's not right
    if(offences >= Params().PoolMaxTransactions()) 
    {
        return;
    }

    //charge one of the offenders randomly
    if(offences > 1)
    {
        target = 50;
    }

    //pick random client to charge
    r = rand()%100;

    if(state == POOL_STATUS_ACCEPTING_ENTRIES)
    {
        for(const CTransaction& txCollateral: vecSessionCollateral)
        {
            bool found = false;

            for(const CDarkSendEntry& v: entries)
            {
                if(v.collateral == txCollateral)
                {
                    found = true;
                }
            }

            // This queue entry didn't send us the promised transaction
            if(!found
                && r > target)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : WARNING - Found uncooperative node (didn't send transaction). charging fees. \n", __FUNCTION__);
                }

                CWalletTx wtxCollateral = CWalletTx(pwalletMain, txCollateral);

                LOCK(cs_main);

                // Broadcast
                if (!wtxCollateral.AcceptToMemoryPool(true))
                {
                    if (fDebug)
                    {
                        // This must not fail. The transaction has already been signed and recorded.
                        LogPrint("darksend", "%s : ERROR - Transaction not valid \n", __FUNCTION__);
                    }
                }

                wtxCollateral.RelayWalletTransaction();
                
                return;
            }
        }
    }

    if(state == POOL_STATUS_SIGNING)
    {
        // who didn't sign?
        for(const CDarkSendEntry v: entries)
        {
            for(const CTxDSIn s: v.sev)
            {
                if(!s.fHasSig && r > target)
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : WARNING - Found uncooperative node (didn't sign). charging fees. \n", __FUNCTION__);
                    }

                    CWalletTx wtxCollateral = CWalletTx(pwalletMain, v.collateral);

                    // Broadcast
                    if (!wtxCollateral.AcceptToMemoryPool(false))
                    {
                        if (fDebug)
                        {
                            // This must not fail. The transaction has already been signed and recorded.
                            LogPrint("darksend", "%s : ERROR - Transaction not valid \n", __FUNCTION__);
                        }
                    }
                    wtxCollateral.RelayWalletTransaction();
                    
                    return;
                }
            }
        }
    }
}


// charge the collateral randomly
//  - Darksend is completely free, to pay miners we randomly pay the collateral of users.
void CDarksendPool::ChargeRandomFees()
{
    if(fMasterNode)
    {
        int i = 0;

        for(const CTransaction& txCollateral: vecSessionCollateral)
        {
            int r = rand()%100;

            /*
                Collateral Fee Charges:

                Being that DarkSend has "no fees" we need to have some kind of cost associated
                with using it to stop abuse. Otherwise it could serve as an attack vector and
                allow endless transaction that would bloat PHC and make it unusable. To
                stop these kinds of attacks 1 in 50 successful transactions are charged. This
                adds up to a cost of 0.002PHC per transaction on average.
            */
            if(r <= 10)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : WARNING - Charging random fees. %u \n", __FUNCTION__, i);
                }

                CWalletTx wtxCollateral = CWalletTx(pwalletMain, txCollateral);

                // Broadcast
                if (!wtxCollateral.AcceptToMemoryPool(true))
                {
                    if (fDebug)
                    {
                        // This must not fail. The transaction has already been signed and recorded.
                        LogPrint("darksend", "%s : ERROR - Transaction not valid \n", __FUNCTION__);
                    }
                }
                wtxCollateral.RelayWalletTransaction();
            }
        }
    }
}


//
// Check for various timeouts (queue objects, darksend, etc)
//
void CDarksendPool::CheckTimeout()
{
    if(!fEnableDarksend && !fMasterNode)
    {
        return;
    }

    // catching hanging sessions
    if(!fMasterNode)
    {
        switch(state)
        {
            case POOL_STATUS_TRANSMISSION:
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : NOTICE - Session complete Running Check() \n", __FUNCTION__);
                }

                Check();

                break;
            }

            case POOL_STATUS_ERROR:
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - Pool Running Check() \n", __FUNCTION__);
                }

                Check();

                break;
            }

            case POOL_STATUS_SUCCESS:
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : OK - Pool success Running Check() \n", __FUNCTION__);
                }

                Check();

                break;
            }

        }
    }

    // check Darksend queue objects for timeouts
    int c = 0;

    vector<CDarksendQueue>::iterator it = vecDarksendQueue.begin();
    
    while(it != vecDarksendQueue.end())
    {
        if((*it).IsExpired())
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - Removing expired queue entry: %d \n", __FUNCTION__, c);
            }

            it = vecDarksendQueue.erase(it);
        }
        else
        {
            ++it;
        }

        c++;
    }

    int addLagTime = 0;

    if(!fMasterNode)
    {
        addLagTime = 10000; //if we're the client, give the server a few extra seconds before resetting.
    }

    if(state == POOL_STATUS_ACCEPTING_ENTRIES
        || state == POOL_STATUS_QUEUE)
    {
        c = 0;

        // check for a timeout and reset if needed
        vector<CDarkSendEntry>::iterator it2 = entries.begin();

        while(it2 != entries.end())
        {
            if((*it2).IsExpired())
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : NOTICE - Removing expired entry: %d \n", __FUNCTION__, c);
                }

                it2 = entries.erase(it2);
                if(entries.size() == 0)
                {
                    UnlockCoins();

                    SetNull();
                }
                
                if(fMasterNode)
                {
                    RelayStatus(sessionID, GetState(), GetEntriesCount(), MASTERNODE_RESET);
                }
            }
            else
            {
                ++it2;
            }

            c++;
        }

        if(GetTimeMillis()-lastTimeChanged >= (DARKSEND_QUEUE_TIMEOUT*1000)+addLagTime)
        {
            UnlockCoins();

            SetNull();
        }
    } 
    else if(GetTimeMillis()-lastTimeChanged >= (DARKSEND_QUEUE_TIMEOUT*1000)+addLagTime)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - Session timed out (%ds) resetting \n", __FUNCTION__, DARKSEND_QUEUE_TIMEOUT);
        }

        UnlockCoins();
        
        SetNull();

        UpdateState(POOL_STATUS_ERROR);
        
        lastMessage = _("Session timed out.");
    }

    if(state == POOL_STATUS_SIGNING
        && GetTimeMillis()-lastTimeChanged >= (DARKSEND_SIGNING_TIMEOUT*1000)+addLagTime )
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Session timed out (%ds) restting \n", __FUNCTION__, DARKSEND_SIGNING_TIMEOUT);
        }
        
        ChargeFees();
        
        UnlockCoins();
        
        SetNull();

        UpdateState(POOL_STATUS_ERROR);
        lastMessage = _("Signing timed out.");
    }
}


//
// Check for complete queue
//
void CDarksendPool::CheckForCompleteQueue()
{
    if(!fEnableDarksend && !fMasterNode)
    {
        return;
    }

    /* Check to see if we're ready for submissions from clients */
    //
    // After receiving multiple dsa messages, the queue will switch to "accepting entries"
    // which is the active state right before merging the transaction
    //
    if(state == POOL_STATUS_QUEUE
        && sessionUsers == GetMaxPoolTransactions())
    {
        UpdateState(POOL_STATUS_ACCEPTING_ENTRIES);

        CDarksendQueue dsq;
        dsq.nDenom = sessionDenom;
        dsq.vin = activeMasternode.vin;
        dsq.time = GetTime();
        dsq.ready = true;
        dsq.Sign();
        dsq.Relay();
    }
}


// check to see if the signature is valid
bool CDarksendPool::SignatureValid(const CScript& newSig, const CTxIn& newVin)
{
    CTransaction txNew;
    txNew.vin.clear();
    txNew.vout.clear();

    int found = -1;

    CScript sigPubKey = CScript();

    unsigned int i = 0;

    for(CDarkSendEntry& e: entries)
    {
        for(const CTxOut& out: e.vout)
        {
            txNew.vout.push_back(out);
        }

        for(const CTxDSIn& s: e.sev)
        {
            txNew.vin.push_back(s);

            if(s == newVin)
            {
                found = i;
                sigPubKey = s.prevPubKey;
            }

            i++;
        }
    }

    if(found >= 0)
    { 
        //might have to do this one input at a time?
        int n = found;
        txNew.vin[n].scriptSig = newSig;

        if (fDebug)
        {
            LogPrint("darksend", "%s : NOTICE - Sign with sig %s \n", __FUNCTION__, newSig.ToString().substr(0,24));
        }

        if (!VerifyScript(txNew.vin[n].scriptSig, sigPubKey, txNew, n, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC, 0))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Signing input %u \n", __FUNCTION__, n);
            }

            return false;
        }
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : OK - Signing successfully validated input \n", __FUNCTION__);
    }

    return true;
}


// check to make sure the collateral provided by the client is valid
bool CDarksendPool::IsCollateralValid(const CTransaction& txCollateral)
{
    if(txCollateral.vout.size() < 1)
    {
        return false;
    }

    if(txCollateral.nLockTime != 0)
    {
        return false;
    }

    int64_t nValueIn = 0;
    int64_t nValueOut = 0;
    bool missingTx = false;

    for(const CTxOut o: txCollateral.vout)
    {
        nValueOut += o.nValue;

        if(!o.scriptPubKey.IsNormalPaymentScript())
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Invalid Script: %s \n", __FUNCTION__, txCollateral.ToString());
            }

            return false;
        }
    }

    for(const CTxIn i: txCollateral.vin)
    {
        CTransaction tx2;
        uint256 hash;

        if(GetTransaction(i.prevout.hash, tx2, hash))
        {
            if(tx2.vout.size() > i.prevout.n)
            {
                nValueIn += tx2.vout[i.prevout.n].nValue;
            }
        }
        else
        {
            missingTx = true;
        }
    }

    if(missingTx)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Unknown inputs in collateral transaction: %s \n", __FUNCTION__, txCollateral.ToString());
        }

        return false;
    }

    //collateral transactions are required to pay out DARKSEND_COLLATERAL as a fee to the miners
    if(nValueIn-nValueOut < DARKSEND_COLLATERAL)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Did not include enough fees in transaction %d \n %s \n", __FUNCTION__, nValueOut-nValueIn, txCollateral.ToString());
        }

        return false;
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : NOTICE - %s \n", __FUNCTION__, txCollateral.ToString());
    }

    // Global Namespace Start
    {
        LOCK(cs_main);

        CValidationState state;

        if(!AcceptableInputs(mempool, txCollateral, true, NULL))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Didn't pass IsAcceptable \n", __FUNCTION__);
            }

            return false;
        }
    }
    // Global Namespace End

    return true;
}


//
// Add a clients transaction to the pool
//
bool CDarksendPool::AddEntry(const std::vector<CTxIn>& newInput, const int64_t& nAmount, const CTransaction& txCollateral, const std::vector<CTxOut>& newOutput, std::string& error)
{
    if (!fMasterNode)
    {
        return false;
    }

    for(CTxIn in: newInput)
    {
        if (in.prevout.IsNull() || nAmount < 0)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Input not valid! \n", __FUNCTION__);
            }

            error = _("Input is not valid.");
            sessionUsers--;
            
            return false;
        }
    }

    if (!IsCollateralValid(txCollateral))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Collateral not valid! \n", __FUNCTION__);
        }

        error = _("Collateral is not valid.");
        sessionUsers--;

        return false;
    }

    if((int)entries.size() >= GetMaxPoolTransactions())
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Entries is full! \n", __FUNCTION__);
        }

        error = _("Entries are full.");
        sessionUsers--;

        return false;
    }

    for(CTxIn in: newInput)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Looking for vin: %s \n", __FUNCTION__, in.ToString());
        }

        for(const CDarkSendEntry& v: entries)
        {
            for(const CTxDSIn& s: v.sev)
            {
                if((CTxIn)s == in)
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - Found in vin \n", __FUNCTION__);
                    }

                    error = _("Already have that input.");
                    sessionUsers--;
                    
                    return false;
                }
            }
        }
    }

    CDarkSendEntry v;
    v.Add(newInput, nAmount, txCollateral, newOutput);

    entries.push_back(v);

    if (fDebug)
    {
        LogPrint("darksend", "%s : OK - Adding: %s \n", __FUNCTION__, newInput[0].ToString());
    }

    error = "";

    return true;
}


bool CDarksendPool::AddScriptSig(const CTxIn& newVin)
{
    if (fDebug)
    {
        LogPrint("darksend", "%s : NOTICE - New sig: %s \n", __FUNCTION__, newVin.scriptSig.ToString().substr(0,24));
    }

    for(const CDarkSendEntry& v: entries)
    {
        for(const CTxDSIn& s: v.sev)
        {
            if(s.scriptSig == newVin.scriptSig)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - Already exists \n", __FUNCTION__);
                }

                return false;
            }
        }
    }

    if(!SignatureValid(newVin.scriptSig, newVin))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Invalid Sig: \n", __FUNCTION__);
        }

        return false;
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : NOTICE - Sig: %s \n", __FUNCTION__, newVin.ToString());
    }

    for(CTxIn& vin: finalTransaction.vin)
    {
        if(newVin.prevout == vin.prevout && vin.nSequence == newVin.nSequence)
        {
            vin.scriptSig = newVin.scriptSig;
            vin.prevPubKey = newVin.prevPubKey;

            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - Adding to finalTransaction: %s \n", __FUNCTION__, newVin.scriptSig.ToString().substr(0,24));
            }
        }
    }

    for(unsigned int i = 0; i < entries.size(); i++)
    {
        if(entries[i].AddSig(newVin))
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - Adding: %s \n", __FUNCTION__, newVin.scriptSig.ToString().substr(0,24));
            }

            return true;
        }
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : ERROR - Couldn't set sig! \n", __FUNCTION__);
    }

    return false;
}


// check to make sure everything is signed
bool CDarksendPool::SignaturesComplete()
{
    for(const CDarkSendEntry& v: entries)
    {
        for(const CTxDSIn& s: v.sev)
        {
            if(!s.fHasSig)
            {
                return false;
            }
        }
    }

    return true;
}


//
// Execute a darksend denomination via a Masternode.
// This is only ran from clients
//
void CDarksendPool::SendDarksendDenominate(std::vector<CTxIn>& vin, std::vector<CTxOut>& vout, int64_t amount)
{
    if(fMasterNode)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Darksend from a Masternode is not supported currently. \n", __FUNCTION__);
        }

        return;
    }

    if(txCollateral == CTransaction())
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Darksend collateral not set", __FUNCTION__);
        }

        return;
    }

    // lock the funds we're going to use
    for(CTxIn in: txCollateral.vin)
    {
        lockedCoins.push_back(in);
    }

    for(CTxIn in: vin)
    {
        lockedCoins.push_back(in);
    }

    if (fDebug)
    {
        for(CTxOut o: vout)
        {
            LogPrint("darksend", "%s : OK - Vout: %s \n", __FUNCTION__, o.ToString());
        }
    }

    // we should already be connected to a Masternode
    if(!sessionFoundMasternode)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - No Masternode has been selected yet. \n", __FUNCTION__);
        }

        UnlockCoins();
        
        SetNull();
        
        return;
    }

    if (!CheckDiskSpace())
    {
        UnlockCoins();

        SetNull();

        fEnableDarksend = false;

        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Not enough disk space, disabling Darksend. \n", __FUNCTION__);
        }

        return;
    }

    UpdateState(POOL_STATUS_ACCEPTING_ENTRIES);

    if (fDebug)
    {
       LogPrint("darksend", "%s : NOTICE - Added transaction to pool. \n", __FUNCTION__);
    }

    ClearLastMessage();

    // Global Namespace Start
    {
        //check it against the memory pool to make sure it's valid

        int64_t nValueOut = 0;

        CValidationState state;
        CTransaction tx;

        for(const CTxOut& o: vout)
        {
            nValueOut += o.nValue;
            tx.vout.push_back(o);
        }

        for(const CTxIn& i: vin)
        {
            tx.vin.push_back(i);

            if (fDebug)
            {
                LogPrint("darksend", "%s : NOTICE - dsi tx in: %s \n", __FUNCTION__, i.ToString());
            }
        }

        LogPrint("darksend", "%s : NOTICE - Darkend Submitting tx: %s \n", __FUNCTION__, tx.ToString());

        while(true)
        {
            TRY_LOCK(cs_main, lockMain);

            if(!lockMain)
            {
                MilliSleep(50);

                continue;
            }

            if(!AcceptableInputs(mempool, txCollateral, false, NULL, false, true))
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - dsi transaction not valid! %s \n", __FUNCTION__, tx.ToString());
                }

                UnlockCoins();
                
                SetNull();
                
                return;
            }

            break;
        }
    }
    // Global Namespace End

    // store our entry for later use
    CDarkSendEntry e;
    e.Add(vin, amount, txCollateral, vout);

    entries.push_back(e);

    RelayIn(entries[0].sev, entries[0].amount, txCollateral, entries[0].vout);

    Check();
}


// Incoming message from Masternode updating the progress of darksend
//    newAccepted:  -1 mean's it'n not a "transaction accepted/not accepted" message, just a standard update
//                  0 means transaction was not accepted
//                  1 means transaction was accepted

bool CDarksendPool::StatusUpdate(int newState, int newEntriesCount, int newAccepted, std::string& error, int newSessionID)
{
    if(fMasterNode)
    {
        return false;
    }

    if(state == POOL_STATUS_ERROR
        || state == POOL_STATUS_SUCCESS)
    {
        return false;
    }

    UpdateState(newState);

    entriesCount = newEntriesCount;

    if(error.size() > 0)
    {
        strAutoDenomResult = _("Masternode:") + " " + error;
    }

    if(newAccepted != -1)
    {
        lastEntryAccepted = newAccepted;
        countEntriesAccepted += newAccepted;

        if(newAccepted == 0)
        {
            UpdateState(POOL_STATUS_ERROR);

            lastMessage = error;
        }

        if(newAccepted == 1 && newSessionID != 0)
        {
            sessionID = newSessionID;

            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - Set sessionID to: %d\n", __FUNCTION__, sessionID);
            }

            sessionFoundMasternode = true;
        }
    }

    if(newState == POOL_STATUS_ACCEPTING_ENTRIES)
    {
        if(newAccepted == 1)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - Entry accepted! \n", __FUNCTION__);
            }

            sessionFoundMasternode = true;

            //wait for other users. Masternode will report when ready
            UpdateState(POOL_STATUS_QUEUE);
        }
        else if (newAccepted == 0
            && sessionID == 0
            && !sessionFoundMasternode)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Entry not accepted by Masternode \n", __FUNCTION__);
            }

            UnlockCoins();

            UpdateState(POOL_STATUS_ACCEPTING_ENTRIES);

            DoAutomaticDenominating(); //try another Masternode
        }

        if(sessionFoundMasternode)
        {
            return true;
        } 
    }

    return true;
}


//
// After we receive the finalized transaction from the Masternode, we must
// check it to make sure it's what we want, then sign it if we agree.
// If we refuse to sign, it's possible we'll be charged collateral
//
bool CDarksendPool::SignFinalTransaction(CTransaction& finalTransactionNew, CNode* node)
{
    if(fMasterNode)
    {
        return false;
    }

    finalTransaction = finalTransactionNew;

    if (fDebug)
    {
        LogPrint("darksend", "%s : ERROR - %s \n", __FUNCTION__, finalTransaction.ToString());
    }

    vector<CTxIn> sigs;

    //make sure my inputs/outputs are present, otherwise refuse to sign
    for(const CDarkSendEntry e: entries)
    {
        for(const CTxDSIn s: e.sev)
        {
            /* Sign my transaction and all outputs */
            int mine = -1;

            CScript prevPubKey = CScript();
            CTxIn vin = CTxIn();

            for(unsigned int i = 0; i < finalTransaction.vin.size(); i++)
            {
                if(finalTransaction.vin[i] == s)
                {
                    mine = i;
                    prevPubKey = s.prevPubKey;
                    vin = s;
                }
            }

            if(mine >= 0)
            {
                //might have to do this one input at a time?

                int foundOutputs = 0;

                CAmount nValue1 = 0;
                CAmount nValue2 = 0;

                for(unsigned int i = 0; i < finalTransaction.vout.size(); i++)
                {
                    for(const CTxOut& o: e.vout)
                    {
                        string Ftx = finalTransaction.vout[i].scriptPubKey.ToString().c_str();
                        string Otx = o.scriptPubKey.ToString().c_str();

                        if(Ftx == Otx)
                        {
                            if(fDebug)
                            {
                                LogPrint("darksend", "%s : OK - FoundOutputs = %d \n", __FUNCTION__, foundOutputs);
                            }

                            foundOutputs++;
                            nValue1 += finalTransaction.vout[i].nValue;
                        }
                    }
                }

                for(const CTxOut o: e.vout)
                {
                    nValue2 += o.nValue;
                }

                int targetOuputs = e.vout.size();

                if(foundOutputs < targetOuputs
                    || nValue1 != nValue2)
                {
                    // in this case, something went wrong and we'll refuse to sign. It's possible we'll be charged collateral. But that's
                    // better then signing if the transaction doesn't look like what we wanted.
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : My entries are not correct! Refusing to sign. %d entries %d target. \n", __FUNCTION__, foundOutputs, targetOuputs);
                    }

                    UnlockCoins();

                    SetNull();

                    return false;
                }

                const CKeyStore& keystore = *pwalletMain;

                if (fDebug)
                {
                    LogPrint("darksend", "%s : Signing my input: %i \n", __FUNCTION__, mine);
                }

                if(!SignSignature(keystore, prevPubKey, finalTransaction, mine, int(SIGHASH_ALL|SIGHASH_ANYONECANPAY)))
                {
                    // changes scriptSig
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : Unable to sign my own transaction! \n", __FUNCTION__);
                        // not sure what to do here, it will timeout...?
                    }
                }

                sigs.push_back(finalTransaction.vin[mine]);

                if (fDebug)
                {
                    LogPrint("darksend", "%s : dss %d %d %s\n", __FUNCTION__, mine, (int)sigs.size(), finalTransaction.vin[mine].scriptSig.ToString());
                }
            }

        }

        if (fDebug)
        {
            LogPrint("darksend", "%s : OK - TxNew: \n %s", __FUNCTION__, finalTransaction.ToString());
        }
    }

   // push all of our signatures to the Masternode
   if(sigs.size() > 0 && node != NULL)
   {
       node->PushMessage("dss", sigs);
   }

    return true;
}


void CDarksendPool::NewBlock()
{
    if (fDebug)
    {
        LogPrint("darksend", "%s : Ok - Processing NewBlock \n", __FUNCTION__);
    }

    //we we're processing lots of blocks, we'll just leave
    if(GetTime() - lastNewBlock < 10)
    {
        return;
    }

    lastNewBlock = GetTime();

    darkSendPool.CheckTimeout();

}


// Darksend transaction was completed (failed or successful)
void CDarksendPool::CompletedTransaction(bool error, int errorID)
{
    if(fMasterNode)
    {
        return;
    }

    if(error)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR \n", __FUNCTION__);
        }

        UpdateState(POOL_STATUS_ERROR);

        Check();

        UnlockCoins();

        SetNull();

    }
    else
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : OK \n", __FUNCTION__);
        }

        UpdateState(POOL_STATUS_SUCCESS);

        UnlockCoins();

        SetNull();

        // To avoid race conditions, we'll only let DS run once per block
        cachedLastSuccess = pindexBest->nHeight;
    }

    lastMessage = GetMessageByID(errorID);

}


void CDarksendPool::ClearLastMessage()
{
    lastMessage = "";
}

//
// Passively run Darksend in the background to anonymize funds based on the given configuration.
//
// This does NOT run by default for daemons, only for QT.
//
bool CDarksendPool::DoAutomaticDenominating(bool fDryRun)
{
    if(!fEnableDarksend)
    {
        return false;
    }

    if(fMasterNode)
    {
        return false;
    }

    if(state == POOL_STATUS_ERROR
        || state == POOL_STATUS_SUCCESS)
    {
        return false;
    }

    if(GetEntriesCount() > 0)
    {
        strAutoDenomResult = _("Mixing in progress...");
        
        return false;
    }

    TRY_LOCK(cs_darksend, lockDS);
    
    if(!lockDS)
    {
        strAutoDenomResult = _("Lock is already in place.");

        return false;
    }

    if(!IsBlockchainSynced())
    {
        strAutoDenomResult = _("Can't mix while sync in progress.");

        return false;
    }

    if (!fDryRun && pwalletMain->IsLocked())
    {
        strAutoDenomResult = _("Wallet is locked.");

        return false;
    }

    if(pindexBest->nHeight - cachedLastSuccess < minBlockSpacing)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Last successful Darksend action was too recent \n", __FUNCTION__);
        }

        strAutoDenomResult = _("Last successful Darksend action was too recent.");

        return false;
    }

    if(mnodeman.size() == 0)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - No Masternodes detected \n", __FUNCTION__);
        }

        strAutoDenomResult = _("No Masternodes detected.");

        return false;
    }

    // ** find the coins we'll use
    std::vector<CTxIn> vCoins;
    CAmount nValueMin = CENT;
    CAmount nValueIn = 0;

    CAmount nOnlyDenominatedBalance;
    CAmount nBalanceNeedsDenominated;

    // should not be less than fees in DARKSEND_COLLATERAL + few (lets say 5) smallest denoms
    CAmount nLowestDenom = DARKSEND_COLLATERAL + darkSendDenominations[darkSendDenominations.size() - 1]*5;

    // if there are no DS collateral inputs yet
    if(!pwalletMain->HasCollateralInputs())
    {
        // should have some additional amount for them
        nLowestDenom += DARKSEND_COLLATERAL*4;
    }

    CAmount nBalanceNeedsAnonymized = nAnonymizeAmount*COIN - pwalletMain->GetAnonymizedBalance();

    // if balanceNeedsAnonymized is more than pool max, take the pool max
    if(nBalanceNeedsAnonymized > DARKSEND_POOL_MAX)
    {
        nBalanceNeedsAnonymized = DARKSEND_POOL_MAX;
    }

    // if balanceNeedsAnonymized is more than non-anonymized, take non-anonymized
    CAmount nAnonymizableBalance = pwalletMain->GetAnonymizableBalance();

    if(nBalanceNeedsAnonymized > nAnonymizableBalance)
    {
        nBalanceNeedsAnonymized = nAnonymizableBalance;
    }

    if(nBalanceNeedsAnonymized < nLowestDenom)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - No funds detected in need of denominating \n", __FUNCTION__);
        }

        strAutoDenomResult = _("No funds detected in need of denominating.");

        return false;
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : ERROR - nLowestDenom=%d, nBalanceNeedsAnonymized=%d \n", __FUNCTION__, nLowestDenom, nBalanceNeedsAnonymized);
    }

    // select coins that should be given to the pool
    if (!pwalletMain->SelectCoinsDark(nValueMin, nBalanceNeedsAnonymized, vCoins, nValueIn, 0, nDarksendRounds))
    {
        nValueIn = 0;

        vCoins.clear();

        if (pwalletMain->SelectCoinsDark(nValueMin, 9999999*COIN, vCoins, nValueIn, -2, 0))
        {
            nOnlyDenominatedBalance = pwalletMain->GetDenominatedBalance(true)
                                    + pwalletMain->GetDenominatedBalance() - pwalletMain->GetAnonymizedBalance();

            nBalanceNeedsDenominated = nBalanceNeedsAnonymized - nOnlyDenominatedBalance;

            if(nBalanceNeedsDenominated > nValueIn)
            {
                nBalanceNeedsDenominated = nValueIn;
            }

            if(nBalanceNeedsDenominated < nLowestDenom)
            {
                return false; // most likely we just waiting for denoms to confirm
            }

            if(!fDryRun)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - !fDryRun Returning CreateDenominated(nBalanceNeedsDenominated) \n", __FUNCTION__);
                }

                return CreateDenominated(nBalanceNeedsDenominated);
            }

            if (fDebug)
            {
                LogPrint("darksend", "%s : OK - fDryRun Returning true \n", __FUNCTION__);
            }

            return true;
        }
        else
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Can't denominate no compatible inputs left \n", __FUNCTION__);
            }

            strAutoDenomResult = _("Can't denominate: no compatible inputs left.");
            
            return false;
        }

    }
    else
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - fDryRun Returning true 2 \n", __FUNCTION__);
        }
    }

    if(fDryRun)
    {
        return true;
    }

    nOnlyDenominatedBalance = pwalletMain->GetDenominatedBalance(true)
                            + pwalletMain->GetDenominatedBalance() - pwalletMain->GetAnonymizedBalance();

    nBalanceNeedsDenominated = nBalanceNeedsAnonymized - nOnlyDenominatedBalance;

    //check if we have should create more denominated inputs
    if(nBalanceNeedsDenominated > nOnlyDenominatedBalance)
    {
        return CreateDenominated(nBalanceNeedsDenominated);
    }

    //check if we have the collateral sized inputs
    if(!pwalletMain->HasCollateralInputs())
    {
        return !pwalletMain->HasCollateralInputs(false) && MakeCollateralAmounts();
    }

    std::vector<CTxOut> vOut;

    // initial phase, find a Masternode
    if(!sessionFoundMasternode)
    {
        // Clean if there is anything left from previous session
        UnlockCoins();

        SetNull();

        int nUseQueue = rand()%100;

        UpdateState(POOL_STATUS_ACCEPTING_ENTRIES);

        if(pwalletMain->GetDenominatedBalance(true) > 0)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Found unconfirmed denominated outputs, will wait till they confirm to continue. \n", __FUNCTION__);
            }

            //get denominated unconfirmed inputs
            strAutoDenomResult = _("Found unconfirmed denominated outputs, will wait till they confirm to continue.");
            
            return false;
        }

        //check our collateral
        std::string strReason;

        if(txCollateral == CTransaction())
        {
            if(!pwalletMain->CreateCollateralTransaction(txCollateral, strReason))
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - Darksend create collateral: %s \n", __FUNCTION__, strReason);
                }

                return false;
            }
        }
        else
        {
            if(!IsCollateralValid(txCollateral))
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - Darksend invalid collateral, recreating... \n", __FUNCTION__);
                }

                if(!pwalletMain->CreateCollateralTransaction(txCollateral, strReason))
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - Darksend create collateral: %s \n", __FUNCTION__, strReason);
                    }

                    return false;
                }
            }
        }

        //if we've used 90% of the Masternode list then drop all the oldest first
        int nThreshold = (int)(mnodeman.CountEnabled(MIN_POOL_PEER_PROTO_VERSION) * 0.9);

        if (fDebug)
        {
            LogPrint("darksend", "%s ERROR - Checking vecMasternodesUsed size %d threshold %d \n", __FUNCTION__, (int)vecMasternodesUsed.size(), nThreshold);
        }

        while((int)vecMasternodesUsed.size() > nThreshold)
        {
            vecMasternodesUsed.erase(vecMasternodesUsed.begin());

            if (fDebug)
            {
                LogPrint("darksend", "%s NOTICE - vecMasternodesUsed size %d threshold %d \n", __FUNCTION__, (int)vecMasternodesUsed.size(), nThreshold);
            }
        }

        //don't use the queues all of the time for mixing
        if(nUseQueue > 33)
        {

            // Look through the queues and see if anything matches
            for(CDarksendQueue& dsq: vecDarksendQueue)
            {
                CService addr;

                if(dsq.time == 0)
                {
                    continue;
                } 

                if(!dsq.GetAddress(addr))
                {
                    continue;
                }

                if(dsq.IsExpired())
                {
                    continue;
                }

                int protocolVersion;

                if(!dsq.GetProtocolVersion(protocolVersion))
                {
                    continue;
                }

                if(protocolVersion < MIN_POOL_PEER_PROTO_VERSION)
                {
                    continue;
                }

                //non-denom's are incompatible
                if((dsq.nDenom & (1 << 5)))
                {
                    continue;
                }

                bool fUsed = false;

                //don't reuse Masternodes
                for(CTxIn usedVin: vecMasternodesUsed)
                {
                    if(dsq.vin == usedVin)
                    {
                        fUsed = true;
                    
                        break;
                    }
                }

                if(fUsed)
                {
                    continue;
                }

                std::vector<CTxIn> vTempCoins;
                std::vector<COutput> vTempCoins2;
                
                // Try to match their denominations if possible
                if (!pwalletMain->SelectCoinsByDenominations(dsq.nDenom, nValueMin, nBalanceNeedsAnonymized, vTempCoins, vTempCoins2, nValueIn, 0, nDarksendRounds))
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - Couldn't match denominations %d \n", __FUNCTION__, dsq.nDenom);
                    }

                    continue;
                }

                // connect to Masternode and submit the queue request
                CNode* pnode = ConnectNode((CAddress)addr, NULL, true);

                if(pnode != NULL)
                {
                    CMasternode* pmn = mnodeman.Find(dsq.vin);

                    if(pmn == NULL)
                    {
                        if (fDebug)
                        {
                            LogPrint("darksend", "%s : ERROR - dsq vin %s is not in Masternode list! \n", __FUNCTION__, dsq.vin.ToString());
                        }

                        continue;
                    }

                    pSubmittedToMasternode = pmn;

                    vecMasternodesUsed.push_back(dsq.vin);

                    sessionDenom = dsq.nDenom;

                    pnode->PushMessage("dsa", sessionDenom, txCollateral);
                    
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - Connected (from queue), sending dsa for %d - %s \n", __FUNCTION__, sessionDenom, pnode->addr.ToStringIPPort());
                    }

                    strAutoDenomResult = _("Mixing in progress...");
                    dsq.time = 0; //remove node
                    
                    return true;
                }
                else
                {
                    if (fDebug)
                    {
                        LogPrint("darksend", "%s : ERROR - Connecting \n", __FUNCTION__);
                    }

                    strAutoDenomResult = _("Error connecting to Masternode.");
                    dsq.time = 0; //remove node

                    continue;
                }
            }
        }

        // do not initiate queue if we are a liquidity proveder to avoid useless inter-mixing
        if(nLiquidityProvider)
        {
            return false;
        }

        int i = 0;

        // otherwise, try one randomly
        while(i < 10)
        {
            CMasternode* pmn = mnodeman.FindRandomNotInVec(vecMasternodesUsed, MIN_POOL_PEER_PROTO_VERSION);

            if(pmn == NULL)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - Can't find random masternode! \n", __FUNCTION__);
                }

                strAutoDenomResult = _("Can't find random Masternode.");
                
                return false;
            }

            if(pmn->nLastDsq != 0 && pmn->nLastDsq + mnodeman.CountEnabled(MIN_POOL_PEER_PROTO_VERSION)/5 > mnodeman.nDsqCount)
            {
                i++;

                continue;
            }

            lastTimeChanged = GetTimeMillis();

            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - Attempt %d connection to Masternode %s \n", __FUNCTION__, i, pmn->addr.ToStringIPPort().c_str());
            }

            CNode* pnode = ConnectNode((CAddress)pmn->addr, NULL, true);

            if(pnode != NULL)
            {
                pSubmittedToMasternode = pmn;
                std::vector<CAmount> vecAmounts;

                vecMasternodesUsed.push_back(pmn->vin);

                pwalletMain->ConvertList(vCoins, vecAmounts);

                // try to get a single random denom out of vecAmounts
                while(sessionDenom == 0)
                {
                    sessionDenom = GetDenominationsByAmounts(vecAmounts);
                }

                pnode->PushMessage("dsa", sessionDenom, txCollateral);

                if (fDebug)
                {
                    LogPrint("darksend", "%s : OK - Connected, sending dsa for %d \n", __FUNCTION__, sessionDenom);
                }

                strAutoDenomResult = _("Mixing in progress...");

                return true;

            }
            else
            {
                vecMasternodesUsed.push_back(pmn->vin); // postpone MN we wasn't able to connect to
                
                i++;

                continue;
            }
        }

        strAutoDenomResult = _("No compatible Masternode found.");

        return false;
    }

    strAutoDenomResult = _("Mixing in progress...");

    return false;
}


bool CDarksendPool::PrepareDarksendDenominate()
{
    std::string strError = "";

    // Submit transaction to the pool if we get here
    // Try to use only inputs with the same number of rounds starting from lowest number of rounds possible
    for(int i = 0; i < nDarksendRounds; i++)
    {
        strError = pwalletMain->PrepareDarksendDenominate(i, i+1);

        if (fDebug)
        {
            LogPrint("darksend", "%s : OK - Running darksend denominate for %d rounds. Return '%s' \n", __FUNCTION__, i, strError);
        }

        if(strError == "")
        {
            return true;
        }
    }

    strError = pwalletMain->PrepareDarksendDenominate(0, nDarksendRounds);
    
    if (fDebug)
    {
        LogPrint("darksend", "%s : OK - Running Darksend denominate for all rounds. Return '%s' \n", __FUNCTION__, strError);
    }

    if(strError == "")
    {
        return true;
    }

    // Should never actually get here but just in case
    strAutoDenomResult = strError;
    
    if (fDebug)
    {
        LogPrint("darksend", "%s : ERROR - Running denominate, %s \n", __FUNCTION__, strError);
    }

    return false;
}


bool CDarksendPool::SendRandomPaymentToSelf()
{
    int64_t nBalance = pwalletMain->GetBalance();
    int64_t nPayment = (nBalance*0.35) + (rand() % nBalance);

    if(nPayment > nBalance)
    {
        nPayment = nBalance-(0.1*COIN);
    }

    // make our change address
    CReserveKey reservekey(pwalletMain);

    CScript scriptChange;
    CPubKey vchPubKey;

    if (reservekey.GetReservedKey(vchPubKey) == 0)
    {
        // should never fail, as we just unlocked
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - reservekey.GetReservedKey(vchPubKey) = 0 \n", __FUNCTION__);
        }

        return false;
    } 

    scriptChange = GetScriptForDestination(vchPubKey.GetID());

    CWalletTx wtx;
    
    int64_t nFeeRet = 0;
    
    std::string strFail = "";
    vector< pair<CScript, int64_t> > vecSend;

    // ****** Add fees ************ /
    vecSend.push_back(make_pair(scriptChange, nPayment));

    CCoinControl *coinControl=NULL;
    
    int32_t nChangePos;
    
    bool success = pwalletMain->CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePos, strFail, coinControl, ONLY_DENOMINATED);
    
    if(!success)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - %s\n", __FUNCTION__, strFail);
        }

        return false;
    }

    pwalletMain->CommitTransaction(wtx, reservekey);

    if (fDebug)
    {
       LogPrint("darksend", "%s : OK - Success: tx %s\n", __FUNCTION__, wtx.GetHash().GetHex());
    }

    return true;
}


// Split up large inputs or create fee sized inputs
bool CDarksendPool::MakeCollateralAmounts()
{
    CWalletTx wtx;

    int64_t nFeeRet = 0;

    std::string strFail = "";

    vector< pair<CScript, int64_t> > vecSend;

    CCoinControl *coinControl = NULL;

    // make our collateral address
    CReserveKey reservekeyCollateral(pwalletMain);

    // make our change address
    CReserveKey reservekeyChange(pwalletMain);

    CScript scriptCollateral;
    CPubKey vchPubKey;

    if (reservekeyCollateral.GetReservedKey(vchPubKey) == 0)
    {
        // should never fail, as we just unlocked
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - reservekeyCollateral.GetReservedKey(vchPubKey) = 0 \n", __FUNCTION__);
        }

        return false;
    }
    
    scriptCollateral = GetScriptForDestination(vchPubKey.GetID());

    vecSend.push_back(make_pair(scriptCollateral, DARKSEND_COLLATERAL*4));

    int32_t nChangePos;

    // try to use non-denominated and not mn-like funds
    bool success = pwalletMain->CreateTransaction(vecSend, wtx, reservekeyChange, nFeeRet, nChangePos, strFail, coinControl, ONLY_NONDENOMINATED_NOT10000IFMN);
    
    if(!success)
    {
        // if we failed (most likeky not enough funds), try to use denominated instead -
        // MN-like funds should not be touched in any case and we can't mix denominated without collaterals anyway
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - ONLY_NONDENOMINATED_NOT1000IFMN %s \n", __FUNCTION__, strFail);
        }

        success = pwalletMain->CreateTransaction(vecSend, wtx, reservekeyChange, nFeeRet, nChangePos, strFail, coinControl, ONLY_NOT10000IFMN);
        
        if(!success)
        {
            if (fDebug)
            {
                LogPrint("darksend", "%s : ERROR - ONLY_NOT1000IFMN Error - %s \n", __FUNCTION__, strFail);
            }

            reservekeyCollateral.ReturnKey();
            
            return false;
        }
    }

    reservekeyCollateral.KeepKey();

    if (fDebug)
    {
        LogPrint("darksend", "%s : ERROR - tx %s \n", __FUNCTION__, wtx.GetHash().GetHex());
    }

    // use the same cachedLastSuccess as for DS mixinx to prevent race
    if(!pwalletMain->CommitTransaction(wtx, reservekeyChange))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - CommitTransaction failed! \n", __FUNCTION__);
        }

        return false;
    }

    cachedLastSuccess = pindexBest->nHeight;

    return true;
}


// Create denominations
bool CDarksendPool::CreateDenominated(int64_t nTotalValue)
{
    CWalletTx wtx;
    
    int64_t nFeeRet = 0;

    std::string strFail = "";

    vector< pair<CScript, int64_t> > vecSend;

    int64_t nValueLeft = nTotalValue;

    // make our collateral address
    CReserveKey reservekeyCollateral(pwalletMain);

    // make our change address
    CReserveKey reservekeyChange(pwalletMain);

    // make our denom addresses
    CReserveKey reservekeyDenom(pwalletMain);

    CScript scriptCollateral;

    CPubKey vchPubKey;

    if (reservekeyCollateral.GetReservedKey(vchPubKey) == 0)
    {
        // should never fail, as we just unlocked

        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - reservekeyCollateral.GetReservedKey(vchPubKey) = 0 \n", __FUNCTION__);
        }

        return false;
    } 

    scriptCollateral = GetScriptForDestination(vchPubKey.GetID());

    // ****** Add collateral outputs ************ /
    if(!pwalletMain->HasCollateralInputs())
    {
        vecSend.push_back(make_pair(scriptCollateral, DARKSEND_COLLATERAL*4));

        nValueLeft -= DARKSEND_COLLATERAL*4;
    }

    // ****** Add denoms ************ /
    for(int64_t v: boost::adaptors::reverse(darkSendDenominations))
    {
        int nOutputs = 0;

        // add each output up to 10 times until it can't be added again
        while(nValueLeft - v >= DARKSEND_COLLATERAL && nOutputs <= 10)
        {
            CScript scriptDenom;
            CPubKey vchPubKey;

            //use a unique change address
            if (reservekeyDenom.GetReservedKey(vchPubKey) == 0)
            {
                if (fDebug)
                {
                    LogPrint("darksend", "%s : ERROR - reservekeyDenom.GetReservedKey(vchPubKey) = 0 \n", __FUNCTION__);
                }

                // should never fail, as we just unlocked
                return false;
            } 

            scriptDenom = GetScriptForDestination(vchPubKey.GetID());

            // TODO: do not keep reservekeyDenom here
            reservekeyDenom.KeepKey();

            vecSend.push_back(make_pair(scriptDenom, v));

            //increment outputs and subtract denomination amount
            nOutputs++;
            nValueLeft -= v;

            if (fDebug)
            {
                LogPrint("darksend", "%s : NOTICE - CreateDenominated1 %d \n", __FUNCTION__, nValueLeft);
            }
        }

        if(nValueLeft == 0)
        {
            break;
        }
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : NOTICE - CreateDenominated2 %d \n", __FUNCTION__, nValueLeft);
    }

    // if we have anything left over, it will be automatically send back as change - there is no need to send it manually

    CCoinControl *coinControl = NULL;
    
    int32_t nChangePos;
    bool success = pwalletMain->CreateTransaction(vecSend, wtx, reservekeyChange, nFeeRet, nChangePos, strFail, coinControl, ONLY_NONDENOMINATED_NOT10000IFMN);
    
    if(!success)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - CreateDenominated: %s \n", __FUNCTION__, strFail);
        }

        // TODO: return reservekeyDenom here
        reservekeyCollateral.ReturnKey();

        return false;
    }

    // TODO: keep reservekeyDenom here
    reservekeyCollateral.KeepKey();

    // use the same cachedLastSuccess as for DS mixinx to prevent race
    if(pwalletMain->CommitTransaction(wtx, reservekeyChange))
    {
        cachedLastSuccess = pindexBest->nHeight;
    }
    else
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - CreateDenominated CommitTransaction failed! \n", __FUNCTION__);
        }
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : OK - CreateDenominated: tx %s \n", __FUNCTION__, wtx.GetHash().GetHex());
    }

    return true;
}


bool CDarksendPool::IsCompatibleWithEntries(std::vector<CTxOut>& vout)
{
    if(GetDenominations(vout) == 0)
    {
        return false;
    }

    for(const CDarkSendEntry v: entries)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s :  IsCompatibleWithEntries %d %d \n", __FUNCTION__, GetDenominations(vout), GetDenominations(v.vout));
        }

        if (fDebug)
        {
            for(CTxOut o1: vout)
            {
                LogPrint("darksend", "%s : NOTICE - vout 1 - %s \n", __FUNCTION__, o1.ToString());
            }

            for(CTxOut o2: v.vout)
            {
                LogPrint("darksend", "%s : NOTICE - vout 2 - %s \n", __FUNCTION__, o2.ToString());
            }
        }

        if(GetDenominations(vout) != GetDenominations(v.vout))
        {
            return false;
        }
    }

    return true;
}


bool CDarksendPool::IsCompatibleWithSession(int64_t nDenom, CTransaction txCollateral,  std::string& strReason)
{
    if(nDenom == 0)
    {
        return false;
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : NOTICE - SessionDenom %d sessionUsers %d \n", __FUNCTION__, sessionDenom, sessionUsers);
    }

    if (!unitTest && !IsCollateralValid(txCollateral))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - collateral not valid! \n", __FUNCTION__);
        }

        strReason = _("Collateral not valid.");
        
        return false;
    }

    if(sessionUsers < 0)
    {
        sessionUsers = 0;
    }

    if(sessionUsers == 0)
    {
        sessionID = 1 + (rand() % 999999);
        sessionDenom = nDenom;
        sessionUsers++;
        lastTimeChanged = GetTimeMillis();

        if(!unitTest)
        {
            //broadcast that I'm accepting entries, only if it's the first entry through
            CDarksendQueue dsq;
            dsq.nDenom = nDenom;
            dsq.vin = activeMasternode.vin;
            dsq.time = GetTime();
            dsq.Sign();
            dsq.Relay();
        }

        UpdateState(POOL_STATUS_QUEUE);
        
        vecSessionCollateral.push_back(txCollateral);

        return true;
    }

    if((state != POOL_STATUS_ACCEPTING_ENTRIES
        && state != POOL_STATUS_QUEUE)
        || sessionUsers >= GetMaxPoolTransactions())
    {
        if((state != POOL_STATUS_ACCEPTING_ENTRIES
            && state != POOL_STATUS_QUEUE))
        {
            strReason = _("Incompatible mode.");
        }

        if(sessionUsers >= GetMaxPoolTransactions())
        {
            strReason = _("Masternode queue is full.");
        }
        
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Incompatible mode, return false %d %d \n", __FUNCTION__, state != POOL_STATUS_ACCEPTING_ENTRIES, sessionUsers >= GetMaxPoolTransactions());
        }

        return false;
    }

    if(nDenom != sessionDenom)
    {
        strReason = _("No matching denominations found for mixing.");

        return false;
    }

    if (fDebug)
    {
        LogPrint("darksend", "%s : OK - Compatible \n", __FUNCTION__);
    }

    sessionUsers++;
    lastTimeChanged = GetTimeMillis();

    vecSessionCollateral.push_back(txCollateral);

    return true;
}


//create a nice string to show the denominations
void CDarksendPool::GetDenominationsToString(int nDenom, std::string& strDenom)
{
    // Function returns as follows:
    //
    // bit 0 - 100PHC+1 ( bit on if present )
    // bit 1 - 10PHC+1
    // bit 2 - 1PHC+1
    // bit 3 - .1PHC+1
    // bit 3 - non-denom

    strDenom = "";

    if(nDenom & (1 << 0))
    {
        if(strDenom.size() > 0)
        {
            strDenom += "+";
        }

        strDenom += "1000";
    }

    if(nDenom & (1 << 1))
    {
        if(strDenom.size() > 0)
        {
            strDenom += "+";
        }

        strDenom += "100";
    }

    if(nDenom & (1 << 2))
    {
        if(strDenom.size() > 0)
        {
            strDenom += "+";
        }

        strDenom += "10";
    }

    if(nDenom & (1 << 3))
    {
        if(strDenom.size() > 0)
        {
            strDenom += "+";
        }

        strDenom += "1";
    }

    if(nDenom & (1 << 4))
    {
        if(strDenom.size() > 0)
        {
            strDenom += "+";
        }

        strDenom += "0.1";
    }
}


int CDarksendPool::GetDenominations(const std::vector<CTxDSOut>& vout)
{
    std::vector<CTxOut> vout2;

    for(CTxDSOut out: vout)
    {
        vout2.push_back(out);
    }

    return GetDenominations(vout2);
}


// return a bitshifted integer representing the denominations in this list
int CDarksendPool::GetDenominations(const std::vector<CTxOut>& vout, bool fSingleRandomDenom)
{
    std::vector<pair<int64_t, int> > denomUsed;

    // make a list of denominations, with zero uses
    for(int64_t d: darkSendDenominations)
    {
        denomUsed.push_back(make_pair(d, 0));
    }

    // look for denominations and update uses to 1
    for(CTxOut out: vout)
    {
        bool found = false;

        for(PAIRTYPE(int64_t, int)& s: denomUsed)
        {
            if (out.nValue == s.first)
            {
                s.second = 1;
                found = true;
            }
        }

        if(!found)
        {
            return 0;
        }
    }

    int denom = 0;
    int c = 0;

    // if the denomination is used, shift the bit on.
    // then move to the next
    for(PAIRTYPE(int64_t, int)& s: denomUsed)
    {
        int bit = (fSingleRandomDenom ? rand()%2 : 1) * s.second;

        denom |= bit << c++;

        if (fSingleRandomDenom
            && bit)
        {
            break; // use just one random denomination
        }
    }

    // Function returns as follows:
    //
    // bit 0 - 100PHC+1 ( bit on if present )
    // bit 1 - 10PHC+1
    // bit 2 - 1PHC+1
    // bit 3 - .1PHC+1

    return denom;
}


int CDarksendPool::GetDenominationsByAmounts(std::vector<int64_t>& vecAmount)
{
    CScript e = CScript();
    std::vector<CTxOut> vout1;

    // Make outputs by looping through denominations, from small to large
    for(int64_t v: boost::adaptors::reverse(vecAmount))
    {
        CTxOut o(v, e);

        vout1.push_back(o);
    }

    return GetDenominations(vout1, true);
}


int CDarksendPool::GetDenominationsByAmount(int64_t nAmount, int nDenomTarget)
{
    CScript e = CScript();
    int64_t nValueLeft = nAmount;

    std::vector<CTxOut> vout1;

    // Make outputs by looping through denominations, from small to large
    for(int64_t v: boost::adaptors::reverse(darkSendDenominations))
    {
        if(nDenomTarget != 0)
        {
            bool fAccepted = false;

            if((nDenomTarget & (1 << 0))
                && v == ((1000*COIN)       +1000000))
            {
                fAccepted = true;
            }
            else if((nDenomTarget & (1 << 1))
                && v == ((100*COIN)   +100000))
            {
                fAccepted = true;
            }
            else if((nDenomTarget & (1 << 2))
                && v == ((10*COIN)    +10000))
            {
                fAccepted = true;
            }
            else if((nDenomTarget & (1 << 3))
                && v == ((1*COIN)     +1000))
            {
                fAccepted = true;
            }
            else if((nDenomTarget & (1 << 4))
                && v == ((.1*COIN)    +100))
            {
                fAccepted = true;
            }

            if(!fAccepted)
            {
                continue;
            }
        }

        int nOutputs = 0;

        // add each output up to 10 times until it can't be added again
        while(nValueLeft - v >= 0 && nOutputs <= 10)
        {
            CTxOut o(v, e);

            vout1.push_back(o);
            
            nValueLeft -= v;
            nOutputs++;
        }

        if (fDebug)
        {
            LogPrint("darksend", "%s : OK - %d nOutputs %d \n", __FUNCTION__, v, nOutputs);
        }
    }

    return GetDenominations(vout1);
}


std::string CDarksendPool::GetMessageByID(int messageID)
{
    switch (messageID)
    {
        case ERR_ALREADY_HAVE:
        {
            return _("Already have that input.");
        }
        break;

        case ERR_DENOM:
        {
            return _("No matching denominations found for mixing.");
        }
        break;

        case ERR_ENTRIES_FULL:
        {
            return _("Entries are full.");
        }
        break;

        case ERR_EXISTING_TX:
        {
            return _("Not compatible with existing transactions.");
        }
        break;

        case ERR_FEES:
        {
            return _("Transaction fees are too high.");
        }
        break;

        case ERR_INVALID_COLLATERAL:
        {
            return _("Collateral not valid.");
        }
        break;

        case ERR_INVALID_INPUT:
        {
            return _("Input is not valid.");
        }
        break;

        case ERR_INVALID_SCRIPT:
        {
            return _("Invalid script detected.");
        }
        break;

        case ERR_INVALID_TX:
        {
            return _("Transaction not valid.");
        }
        break;

        case ERR_MAXIMUM:
        {
            return _("Value more than Darksend pool maximum allows.");
        }
        break;

        case ERR_MN_LIST:
        {
            return _("Not in the Masternode list.");
        }
        break;

        case ERR_MODE:
        {
            return _("Incompatible mode.");
        }
        break;

        case ERR_NON_STANDARD_PUBKEY:
        {
            return _("Non-standard public key detected.");
        }
        break;

        case ERR_NOT_A_MN:
        {
            return _("This is not a Masternode.");
        }
        break;

        case ERR_QUEUE_FULL:
        {
            return _("Masternode queue is full.");
        }
        break;

        case ERR_RECENT:
        {
            return _("Last Darksend was too recent.");
        }
        break;

        case ERR_SESSION: 
        {
            return _("Session not complete!");
        }
        break;

        case ERR_MISSING_TX:
        {
            return _("Missing input transaction information.");
        }
        break;

        case ERR_VERSION:
        {
            return _("Incompatible version.");
        }
        break;

        case MSG_SUCCESS:
        {
            return _("Transaction created successfully.");
        }
        break;

        case MSG_ENTRIES_ADDED:
        {
            return _("Your entries added successfully.");
        }
        break;

        case MSG_NOERR:
        {
            return "";
        }
        break;

        default:
        {
            return "";
        }
        break;

        return "";

    }
}


bool CDarkSendSigner::IsVinAssociatedWithPubkey(CTxIn& vin, CPubKey& pubkey)
{
    CScript payee2;
    payee2 = GetScriptForDestination(pubkey.GetID());

    CTransaction txVin;
    uint256 hash;

    //if(GetTransaction(vin.prevout.hash, txVin, hash, true)){
    if(GetTransaction(vin.prevout.hash, txVin, hash))
    {
        for(CTxOut out: txVin.vout)
        {
            if(out.nValue == GetMNCollateral(pindexBest->nHeight)*COIN)
            {
                if(out.scriptPubKey == payee2)
                {
                    return true;
                }
            }
        }
    }

    return false;
}


bool CDarkSendSigner::SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey)
{
    CPHCcoinSecret vchSecret;

    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood)
    {
        errorMessage = _("Invalid private key.");

        return false;
    }

    key = vchSecret.GetKey();
    pubkey = key.GetPubKey();

    return true;
}


bool CDarkSendSigner::SignMessage(std::string strMessage, std::string& errorMessage, vector<unsigned char>& vchSig, CKey key)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    if (!key.SignCompact(ss.GetHash(), vchSig))
    {
        errorMessage = _("Signing failed.");

        return false;
    }

    return true;
}


bool CDarkSendSigner::VerifyMessage(CPubKey pubkey, vector<unsigned char>& vchSig, std::string strMessage, std::string& errorMessage)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey2;

    if (!pubkey2.RecoverCompact(ss.GetHash(), vchSig))
    {
        errorMessage = _("Error recovering public key.");

        return false;
    }

    if (fDebug && (pubkey2.GetID() != pubkey.GetID()))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Keys don't match: %s %s \n", __FUNCTION__, pubkey2.GetID().ToString(), pubkey.GetID().ToString());
        }
    }

    return (pubkey2.GetID() == pubkey.GetID());
}


bool CDarksendQueue::Sign()
{
    if(!fMasterNode)
    {
        return false;
    }

    std::string strMessage = vin.ToString()
                            + boost::lexical_cast<std::string>(nDenom)
                            + boost::lexical_cast<std::string>(time)
                            + boost::lexical_cast<std::string>(ready);

    CKey key2;
    CPubKey pubkey2;
    std::string errorMessage = "";

    if(!darkSendSigner.SetKey(strMasterNodePrivKey, errorMessage, key2, pubkey2))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR: Invalid Masternodeprivkey: '%s' \n", __FUNCTION__, errorMessage);
        }

        return false;
    }

    if(!darkSendSigner.SignMessage(strMessage, errorMessage, vchSig, key2))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Sign message failed \n", __FUNCTION__);
        }

        return false;
    }

    if(!darkSendSigner.VerifyMessage(pubkey2, vchSig, strMessage, errorMessage))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Verify message failed \n", __FUNCTION__);
        }

        return false;
    }

    return true;
}


bool CDarksendQueue::Relay()
{
    std::vector<CNode*> vNodesCopy;

    // Global Namespace Start
    {
        LOCK(cs_vNodes);

        vNodesCopy = vNodes;

        for(CNode* pnode: vNodesCopy)
        {
            pnode->AddRef();
        }
    }
    // Global Namespace End

    // always relay to everyone
    for(CNode* pnode: vNodesCopy)
    {
        pnode->PushMessage("dsq", (*this));
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

    return true;
}


bool CDarksendQueue::CheckSignature()
{
    CMasternode* pmn = mnodeman.Find(vin);

    if(pmn != NULL)
    {
        std::string strMessage = vin.ToString()
                                + boost::lexical_cast<std::string>(nDenom)
                                + boost::lexical_cast<std::string>(time)
                                + boost::lexical_cast<std::string>(ready);

        std::string errorMessage = "";

        if(!darkSendSigner.VerifyMessage(pmn->pubkey2, vchSig, strMessage, errorMessage))
        {
            return error("%s : ERROR - Got bad Masternode address signature %s", __FUNCTION__, vin.ToString().c_str());
        }

        return true;
    }

    return false;
}


void CDarksendPool::RelayFinalTransaction(const int sessionID, const CTransaction& txNew)
{
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        pnode->PushMessage("dsf", sessionID, txNew);
    }
}


void CDarksendPool::RelayIn(const std::vector<CTxDSIn>& vin, const int64_t& nAmount, const CTransaction& txCollateral, const std::vector<CTxDSOut>& vout)
{
    if(!pSubmittedToMasternode)
    {
        return;
    }

    std::vector<CTxIn> vin2;
    std::vector<CTxOut> vout2;

    for(CTxDSIn in: vin)
    {
        vin2.push_back(in);
    }

    for(CTxDSOut out: vout)
    {
        vout2.push_back(out);
    }

    CNode* pnode = FindNode(pSubmittedToMasternode->addr);

    if(pnode != NULL)
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - RelayIn found master, relaying message %s \n", __FUNCTION__, pnode->addr.ToStringIPPort());
        }

        pnode->PushMessage("dsi", vin2, nAmount, txCollateral, vout2);
    }
}


void CDarksendPool::RelayStatus(const int sessionID, const int newState, const int newEntriesCount, const int newAccepted, const std::string error)
{
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        pnode->PushMessage("dssu", sessionID, newState, newEntriesCount, newAccepted, error);
    }
}


void CDarksendPool::RelayCompletedTransaction(const int sessionID, const bool error, const std::string errorMessage)
{
    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        pnode->PushMessage("dsc", sessionID, error, errorMessage);
    }
}


//TODO: Rename/move to core
void ThreadCheckDarkSendPool()
{
    if(fLiteMode)
    {
        //disable all Darksend/Masternode related functionality
        return; 
    }

    if (IsInitialBlockDownload())
    {
        return;
    }

    // Make this thread recognisable as the wallet flushing thread
    RenameThread("PHC-darksend");

    unsigned int c = 0;

    while (true)
    {
        MilliSleep(100);

        // try to sync from all available nodes, one step at a time
        //masternodeSync.Process();

        if(darkSendPool.IsBlockchainSynced())
        {
            c++;

            // check if we should activate or ping every few minutes,
            // start right after sync is considered to be done
            if(c % MASTERNODE_PING_SECONDS == 1)
            {
                activeMasternode.ManageStatus();
            }

            if(c % 60 == 0)
            {
                mnodeman.CheckAndRemove();
                mnodeman.ProcessMasternodeConnections();
                masternodePayments.CleanPaymentList();

                CleanTransactionLocksList();
            }

            //if(c % MASTERNODES_DUMP_SECONDS == 0) DumpMasternodes();

            darkSendPool.CheckTimeout();
            darkSendPool.CheckForCompleteQueue();

            if(darkSendPool.GetState() == POOL_STATUS_IDLE
                && c % 15 == 0)
            {
                darkSendPool.DoAutomaticDenominating();
            }
        }
    }
}
