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


#include "masternode-payments.h"
#include "masternodeman.h"
#include "darksend.h"
#include "util.h"
#include "sync.h"
#include "spork.h"
#include "addrman.h"
#include <boost/lexical_cast.hpp>
#include <boost/range/adaptor/reversed.hpp>

CCriticalSection cs_masternodepayments;

/** Object for who's going to get paid on which blocks */
CMasternodePayments masternodePayments;

// keep track of Masternode votes I've seen
map<uint256, CMasternodePaymentWinner> mapSeenMasternodeVotes;


int CMasternodePayments::GetMinMasternodePaymentsProto()
{
    return MIN_MASTERNODE_PAYMENT_PROTO_VERSION_1;
}


void ProcessMessageMasternodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if(!darkSendPool.IsBlockchainSynced())
    {
        return;
    }

    if (strCommand == "mnget")
    {
        //Masternode Payments Request Sync

        if(pfrom->HasFulfilledRequest("mnget"))
        {
            if (fDebug)
            {
                LogPrint("masternode", "%s : ERROR - Mnget command flooding, peer already asked me for the list \n", __FUNCTION__);
            }

            Misbehaving(pfrom->GetId(), 20);

            return;
        }

        pfrom->FulfilledRequest("mnget");

        masternodePayments.Sync(pfrom);

        if (fDebug)
        {
            LogPrint("masternode", "%s : OK - Sent Masternode winners to: %s \n", __FUNCTION__, pfrom->addr.ToString().c_str());
        }
    }
    else if (strCommand == "mnw")
    {
        //Masternode Payments Declare Winner

        LOCK(cs_masternodepayments);

        //this is required in litemode
        CMasternodePaymentWinner winner;
        vRecv >> winner;

        if(pindexBest == NULL)
        {
            return;
        }

        CTxDestination address1;

        ExtractDestination(winner.payee, address1);

        CCoinAddress address2(address1);

        uint256 hash = winner.GetHash();

        if(mapSeenMasternodeVotes.count(hash))
        {
            if(fDebug)
            {
                LogPrint("masternode", "%s : ERROR - Seen vote %s Addr %s Height %d bestHeight %d \n", __FUNCTION__, hash.ToString().c_str(), address2.ToString().c_str(), winner.nBlockHeight, pindexBest->nHeight);
            }

            return;
        }

        if(winner.nBlockHeight < pindexBest->nHeight - 10
            || winner.nBlockHeight > pindexBest->nHeight+20)
        {
            if (fDebug)
            {
                LogPrint("masternode", "%s : ERROR - Winner out of range %s Addr %s Height %d bestHeight %d \n", __FUNCTION__, winner.vin.ToString().c_str(), address2.ToString().c_str(), winner.nBlockHeight, pindexBest->nHeight);
            }

            return;
        }

        if(winner.vin.nSequence != std::numeric_limits<unsigned int>::max())
        {
            if (fDebug)
            {
                LogPrint("masternode", "%s : ERROR - Invalid nSequence \n");
            }

            Misbehaving(pfrom->GetId(), 100);

            return;
        }

        if (fDebug)
        {
            LogPrint("masternode", "%s : NOTICE - Winning vote - Vin %s Addr %s Height %d bestHeight %d \n", __FUNCTION__, winner.vin.ToString().c_str(), address2.ToString().c_str(), winner.nBlockHeight, pindexBest->nHeight);
        }

        if(!masternodePayments.CheckSignature(winner))
        {
            if (fDebug)
            {
                LogPrint("masternode", "%s : ERROR - Invalid signature \n", __FUNCTION__);
            }

            Misbehaving(pfrom->GetId(), 100);

            return;
        }

        mapSeenMasternodeVotes.insert(make_pair(hash, winner));

        if(masternodePayments.AddWinningMasternode(winner))
        {
            masternodePayments.Relay(winner);
        }
    }
}


bool CMasternodePayments::CheckSignature(CMasternodePaymentWinner& winner)
{
    //note: need to investigate why this is failing
    std::string strMessage = winner.vin.ToString().c_str()
                                + boost::lexical_cast<std::string>(winner.nBlockHeight)
                                + winner.payee.ToString();

    std::string strPubKey = strMainPubKey ;

    CPubKey pubkey(ParseHex(strPubKey));

    std::string errorMessage = "";

    if(!darkSendSigner.VerifyMessage(pubkey, winner.vchSig, strMessage, errorMessage))
    {
        return false;
    }

    return true;
}


bool CMasternodePayments::Sign(CMasternodePaymentWinner& winner)
{
    std::string strMessage = winner.vin.ToString().c_str()
                + boost::lexical_cast<std::string>(winner.nBlockHeight)
                + winner.payee.ToString();
    
    CKey key2;
    CPubKey pubkey2;
    
    std::string errorMessage = "";

    if(!darkSendSigner.SetKey(strMasterPrivKey, errorMessage, key2, pubkey2))
    {
        if (fDebug)
        {
            LogPrint("masternode", "%s : ERROR - Invalid Masternodeprivkey: '%s' \n", __FUNCTION__, errorMessage.c_str());
        }

        return false;
    }

    if(!darkSendSigner.SignMessage(strMessage, errorMessage, winner.vchSig, key2))
    {
        if (fDebug)
        {
            LogPrint("masternode", "%s : ERROR - Sign message failed \n", __FUNCTION__);
        }

        return false;
    }

    if(!darkSendSigner.VerifyMessage(pubkey2, winner.vchSig, strMessage, errorMessage))
    {
        if (fDebug)
        {
            LogPrint("masternode", "%s : ERROR - Verify message failed \n", __FUNCTION__);
        }

        return false;
    }

    return true;
}


uint64_t CMasternodePayments::CalculateScore(uint256 blockHash, CTxIn& vin)
{
    uint256 n1 = blockHash;
    uint256 n2 = Hash(BEGIN(n1), END(n1));
    uint256 n3 = Hash(BEGIN(vin.prevout.hash), END(vin.prevout.hash));
    uint256 n4 = n3 > n2 ? (n3 - n2) : (n2 - n3);

    //printf(" -- CMasternodePayments CalculateScore() n2 = %d \n", n2.Get64());
    //printf(" -- CMasternodePayments CalculateScore() n3 = %d \n", n3.Get64());
    //printf(" -- CMasternodePayments CalculateScore() n4 = %d \n", n4.Get64());

    return n4.Get64();
}


bool CMasternodePayments::GetBlockPayee(int nBlockHeight, CScript& payee, CTxIn& vin)
{
    for(CMasternodePaymentWinner& winner: vWinning)
    {
        if(winner.nBlockHeight == nBlockHeight)
        {
            payee = winner.payee;
            vin = winner.vin;

            return true;
        }
    }

    return false;
}


bool CMasternodePayments::GetWinningMasternode(int nBlockHeight, CTxIn& vinOut)
{
    for(CMasternodePaymentWinner& winner: vWinning)
    {
        if(winner.nBlockHeight == nBlockHeight)
        {
            vinOut = winner.vin;

            return true;
        }
    }

    return false;
}


bool CMasternodePayments::AddWinningMasternode(CMasternodePaymentWinner& winnerIn)
{
    uint256 blockHash = 0;

    if(!GetBlockHash(blockHash, winnerIn.nBlockHeight-576))
    {
        return false;
    }

    winnerIn.score = CalculateScore(blockHash, winnerIn.vin);

    bool foundBlock = false;

    for(CMasternodePaymentWinner& winner: vWinning)
    {
        if(winner.nBlockHeight == winnerIn.nBlockHeight)
        {
            foundBlock = true;

            if(winner.score < winnerIn.score)
            {
                winner.score = winnerIn.score;
                winner.vin = winnerIn.vin;
                winner.payee = winnerIn.payee;
                winner.vchSig = winnerIn.vchSig;

                mapSeenMasternodeVotes.insert(make_pair(winnerIn.GetHash(), winnerIn));

                return true;
            }
        }
    }

    // if it's not in the vector
    if(!foundBlock)
    {
        vWinning.push_back(winnerIn);

        mapSeenMasternodeVotes.insert(make_pair(winnerIn.GetHash(), winnerIn));

        return true;
    }

    return false;
}


void CMasternodePayments::CleanPaymentList()
{
    LOCK(cs_masternodepayments);

    if(pindexBest == NULL)
    {
        return;
    }

    int nLimit = std::max(((int)mnodeman.size())*((int)1.25), 1000);

    vector<CMasternodePaymentWinner>::iterator it;

    for(it = vWinning.begin(); it<vWinning.end(); it++)
    {
        if(pindexBest->nHeight - (*it).nBlockHeight > nLimit)
        {
            if(fDebug)
            {
                LogPrint("masternode", "%s : OK - Removing old Masternode payment - block %d \n", __FUNCTION__, (*it).nBlockHeight);
            }

            vWinning.erase(it);
            
            break;
        }
    }
}


bool CMasternodePayments::ProcessBlock(int nBlockHeight)
{
    LOCK(cs_masternodepayments);

    if(nBlockHeight <= nLastBlockHeight)
    {
        return false;
    }

    if(!enabled)
    {
        return false;
    }

    CMasternodePaymentWinner newWinner;

    int nMinimumAge = mnodeman.CountEnabled();

    CScript payeeSource;

    uint256 hash;

    if(!GetBlockHash(hash, nBlockHeight-10))
    {
        return false;
    }

    unsigned int nHash;
    
    memcpy(&nHash, &hash, 2);

    if (fDebug)
    {
        LogPrint("masternode", "%s : NOTICE - ProcessBlock Start nHeight %d - vin %s. \n", __FUNCTION__, nBlockHeight, activeMasternode.vin.ToString().c_str());
    }

    std::vector<CTxIn> vecLastPayments;
    
    for(CMasternodePaymentWinner& winner: boost::adaptors::reverse(vWinning))
    {
        //if we already have the same vin - we have one full payment cycle, break
        if(vecLastPayments.size() > (unsigned int)nMinimumAge)
        {
            break;
        }

        vecLastPayments.push_back(winner.vin);
    }

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    CMasternode *pmn = mnodeman.FindOldestNotInVec(vecLastPayments, nMinimumAge);

    if(pmn != NULL)
    {
        if (fDebug)
        {
            LogPrint("masternode", "%s : WARNING - Found by FindOldestNotInVec \n", __FUNCTION__);
        }

        newWinner.score = 0;
        newWinner.nBlockHeight = nBlockHeight;
        newWinner.vin = pmn->vin;

        if(pmn->rewardPercentage > 0
            && (nHash % 100) <= (unsigned int)pmn->rewardPercentage)
        {
            newWinner.payee = pmn->rewardAddress;
        }
        else
        {
            newWinner.payee = GetScriptForDestination(pmn->pubkey.GetID());
        }

        payeeSource = GetScriptForDestination(pmn->pubkey.GetID());
    }

    //if we can't find new MN to get paid, pick first active MN counting back from the end of vecLastPayments list
    if(newWinner.nBlockHeight == 0
        && nMinimumAge > 0)
    {
        if (fDebug)
        {
            LogPrint("masternode", "%s : NOTICE - Find by reverse \n", __FUNCTION__);
        }

        for(CTxIn& vinLP: boost::adaptors::reverse(vecLastPayments))
        {
            CMasternode* pmn = mnodeman.Find(vinLP);

            if(pmn != NULL)
            {
                pmn->Check();

                if(!pmn->IsEnabled())
                {
                    continue;
                }

                newWinner.score = 0;
                newWinner.nBlockHeight = nBlockHeight;
                newWinner.vin = pmn->vin;

                if(pmn->rewardPercentage > 0
                    && (nHash % 100) <= (unsigned int)pmn->rewardPercentage)
                {
                    newWinner.payee = pmn->rewardAddress;
                }
                else
                {
                    newWinner.payee = GetScriptForDestination(pmn->pubkey.GetID());
                }

                payeeSource = GetScriptForDestination(pmn->pubkey.GetID());

                break; // we found active MN
            }
        }
    }

    if(newWinner.nBlockHeight == 0) 
    {
        return false;
    }

    CTxDestination address1;

    ExtractDestination(newWinner.payee, address1);

    CCoinAddress address2(address1);

    CTxDestination address3;

    ExtractDestination(payeeSource, address3);

    CCoinAddress address4(address3);

    if (fDebug)
    {
        LogPrint("masternode", "%s : NOTICE - Winner payee %s nHeight %d vin source %s. \n", __FUNCTION__, address2.ToString().c_str(), newWinner.nBlockHeight, address4.ToString().c_str());
    }

    if(Sign(newWinner))
    {
        if(AddWinningMasternode(newWinner))
        {
            Relay(newWinner);
            
            nLastBlockHeight = nBlockHeight;

            return true;
        }
    }

    return false;
}


void CMasternodePayments::Relay(CMasternodePaymentWinner& winner)
{
    CInv inv(MSG_MASTERNODE_WINNER, winner.GetHash());

    vector<CInv> vInv;

    vInv.push_back(inv);

    LOCK(cs_vNodes);

    for(CNode* pnode: vNodes)
    {
        pnode->PushMessage("inv", vInv);
    }
}


void CMasternodePayments::Sync(CNode* node)
{
    LOCK(cs_masternodepayments);

    for(CMasternodePaymentWinner& winner: vWinning)
    {
        if(winner.nBlockHeight >= pindexBest->nHeight-10
            && winner.nBlockHeight <= pindexBest->nHeight + 20)
        {
            node->PushMessage("mnw", winner);
        }
    }

}


bool CMasternodePayments::SetPrivKey(std::string strPrivKey)
{
    CMasternodePaymentWinner winner;

    // Test signing successful, proceed
    strMasterPrivKey = strPrivKey;

    Sign(winner);

    if(CheckSignature(winner))
    {
        if (fDebug)
        {
            LogPrint("masternode", "%s : OK - Successfully initialized as Masternode payments private key \n", __FUNCTION__);
        }

        enabled = true;

        return true;
    }
    else
    {
        if (fDebug)
        {
            LogPrint("masternode", "%s : ERROR - Can't initialize as Masternode payments private key \n", __FUNCTION__);
        }

        return false;
    }
}
