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


#include "darksend-relay.h"


CDarkSendRelay::CDarkSendRelay()
{
    vinMasternode = CTxIn();
    nBlockHeight = 0;
    nRelayType = 0;
    in = CTxIn();
    out = CTxOut();
}


CDarkSendRelay::CDarkSendRelay(CTxIn& vinMasternodeIn, vector<unsigned char>& vchSigIn, int nBlockHeightIn, int nRelayTypeIn, CTxIn& in2, CTxOut& out2)
{
    vinMasternode = vinMasternodeIn;
    vchSig = vchSigIn;
    nBlockHeight = nBlockHeightIn;
    nRelayType = nRelayTypeIn;
    in = in2;
    out = out2;
}


std::string CDarkSendRelay::ToString()
{
    std::ostringstream info;

    info << "vin: " << vinMasternode.ToString() <<
        " nBlockHeight: " << (int)nBlockHeight <<
        " nRelayType: "  << (int)nRelayType <<
        " in " << in.ToString() <<
        " out " << out.ToString();
        
    return info.str();   
}


bool CDarkSendRelay::Sign(std::string strSharedKey)
{
    std::string strMessage = in.ToString()
                            + out.ToString();

    CKey key2;
    CPubKey pubkey2;
    
    std::string errorMessage = "";

    if(!darkSendSigner.SetKey(strSharedKey, errorMessage, key2, pubkey2))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Invalid shared key: '%s' \n", __FUNCTION__, errorMessage.c_str());
        }

        return false;
    }

    if(!darkSendSigner.SignMessage(strMessage, errorMessage, vchSig2, key2))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Sign message failed \n", __FUNCTION__);
        }

        return false;
    }

    if(!darkSendSigner.VerifyMessage(pubkey2, vchSig2, strMessage, errorMessage))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Verify message failed \n", __FUNCTION__);
        }

        return false;
    }

    return true;
}


bool CDarkSendRelay::VerifyMessage(std::string strSharedKey)
{
    std::string strMessage = in.ToString()
                            + out.ToString();

    CKey key2;
    CPubKey pubkey2;

    std::string errorMessage = "";

    if(!darkSendSigner.SetKey(strSharedKey, errorMessage, key2, pubkey2))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Invalid shared key: '%s' \n", __FUNCTION__, errorMessage.c_str());
        }

        return false;
    }

    if(!darkSendSigner.VerifyMessage(pubkey2, vchSig2, strMessage, errorMessage))
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - Verify message failed \n", __FUNCTION__);
        }
        
        return false;
    }

    return true;
}


void CDarkSendRelay::Relay()
{
    int nCount = std::min(mnodeman.CountEnabled(), 20);
    int nRank1 = (rand() % nCount)+1; 
    int nRank2 = (rand() % nCount)+1; 

    //keep picking another second number till we get one that doesn't match
    while(nRank1 == nRank2)
    {
        nRank2 = (rand() % nCount)+1;
    }

    //printf("rank 1 - rank2 %d %d \n", nRank1, nRank2);

    //relay this message through 2 separate nodes for redundancy
    RelayThroughNode(nRank1);
    RelayThroughNode(nRank2);
}


void CDarkSendRelay::RelayThroughNode(int nRank)
{
    CMasternode* pmn = mnodeman.GetMasternodeByRank(nRank, nBlockHeight, MIN_POOL_PEER_PROTO_VERSION);

    if(pmn != NULL)
    {
        //printf("RelayThroughNode %s\n", pmn->addr.ToStringIPPort().c_str());

        if(ConnectNode((CAddress)pmn->addr, NULL, true))
        {
            //printf("Connected\n");
            CNode* pNode = FindNode(pmn->addr);

            if(pNode)
            {
                //printf("Found\n");
                pNode->PushMessage("dsr", (*this));
                
                return;
            }
        }
    }
    else
    {
        if (fDebug)
        {
            LogPrint("darksend", "%s : ERROR - RelayThroughNode NULL \n", __FUNCTION__);
        }
    }
}
