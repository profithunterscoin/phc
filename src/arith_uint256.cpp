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

//
// Alert system
//

#include "alert.h"

#include "chainparams.h"
#include "pubkey.h"
#include "net.h"
#include "ui_interface.h"
#include "util.h"

#include <stdint.h>
#include <algorithm>
#include <map>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>

using namespace std;

map<uint256, CAlert> mapAlerts;
CCriticalSection cs_mapAlerts;

void CUnsignedAlert::SetNull()
{
    nVersion = 1;
    nRelayUntil = 0;
    nExpiration = 0;
    nID = 0;
    nCancel = 0;
    nMinVer = 0;
    nMaxVer = 0;
    nPriority = 0;

    setSubVer.clear();
    setCancel.clear();
    strComment.clear();
    strStatusBar.clear();
    strReserved.clear();
}


std::string CUnsignedAlert::ToString() const
{
    std::string strSetCancel;

    for(int n: setCancel)
    {
        strSetCancel += strprintf("%d ", n);
    }

    std::string strSetSubVer;

    for(std::string str: setSubVer)
    {
        strSetSubVer += "\"" + str + "\" ";
    }

    return strprintf(
        "CAlert(\n"
        "    nVersion     = %d\n"
        "    nRelayUntil  = %d\n"
        "    nExpiration  = %d\n"
        "    nID          = %d\n"
        "    nCancel      = %d\n"
        "    setCancel    = %s\n"
        "    nMinVer      = %d\n"
        "    nMaxVer      = %d\n"
        "    setSubVer    = %s\n"
        "    nPriority    = %d\n"
        "    strComment   = \"%s\"\n"
        "    strStatusBar = \"%s\"\n"
        ")\n",
        nVersion,
        nRelayUntil,
        nExpiration,
        nID,
        nCancel,
        strSetCancel,
        nMinVer,
        nMaxVer,
        strSetSubVer,
        nPriority,
        strComment,
        strStatusBar);
}


void CAlert::SetNull()
{
    CUnsignedAlert::SetNull();

    vchMsg.clear();
    vchSig.clear();
}


bool CAlert::IsNull() const
{
    return (nExpiration == 0);
}


uint256 CAlert::GetHash() const
{
    return Hash(this->vchMsg.begin(), this->vchMsg.end());
}


bool CAlert::IsInEffect() const
{
    return (GetAdjustedTime() < nExpiration);
}


bool CAlert::Cancels(const CAlert& alert) const
{
    if (!IsInEffect())
    {
        return false; // this was a no-op before 31403
    }

    return (alert.nID <= nCancel || setCancel.count(alert.nID));
}


bool CAlert::AppliesTo(int nVersion, std::string strSubVerIn) const
{
    // TODO: rework for client-version-embedded-in-strSubVer ?
    return (IsInEffect() && nMinVer <= nVersion && nVersion <= nMaxVer && (setSubVer.empty() || setSubVer.count(strSubVerIn)));
}


bool CAlert::AppliesToMe() const
{
    return AppliesTo(PROTOCOL_VERSION, FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, std::vector<std::string>()));
}


bool CAlert::RelayTo(CNode* pnode) const
{
    if (!IsInEffect())
    {
        return false;
    }

    // don't relay to nodes which haven't sent their version message
    if (pnode->nVersion == 0)
    {
        return false;
    }

    // returns true if wasn't already contained in the set
    if (pnode->setKnown.insert(GetHash()).second)
    {
        if (AppliesTo(pnode->nVersion, pnode->strSubVer) || AppliesToMe() || GetAdjustedTime() < nRelayUntil)
        {
            pnode->PushMessage("alert", *this);

            return true;
        }
    }

    return false;
}


bool CAlert::CheckSignature() const
{
    CPubKey key(Params().AlertKey());

    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
    {
        return error("%s : ERROR - Verify signature failed", __FUNCTION__);
    }

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);

    sMsg >> *(CUnsignedAlert*)this;

    return true;
}


CAlert CAlert::getAlertByHash(const uint256 &hash)
{
    CAlert retval;
    
    // Global Namespace Start
    {
        LOCK(cs_mapAlerts);
        
        map<uint256, CAlert>::iterator mi = mapAlerts.find(hash);

        if(mi != mapAlerts.end())
        {
            retval = mi->second;
        }
    }
    // Global Namespace End

    return retval;
}


bool CAlert::ProcessAlert(bool fThread)
{
    if (!CheckSignature())
    {
        return false;
    }

    if (!IsInEffect())
    {
        return false;
    }

    // alert.nID=max is reserved for if the alert key is
    // compromised. It must have a pre-defined message,
    // must never expire, must apply to all versions,
    // and must cancel all previous
    // alerts or it will be ignored (so an attacker can't
    // send an "everything is OK, don't panic" version that
    // cannot be overridden):
    int maxInt = std::numeric_limits<int>::max();

    if (nID == maxInt)
    {
        if (!(nExpiration == maxInt
            && nCancel == (maxInt-1)
            && nMinVer == 0
            && nMaxVer == maxInt
            && setSubVer.empty()
            && nPriority == maxInt
            && strStatusBar == "URGENT: Alert key compromised, upgrade required"
            ))
        {
            return false;
        }
    }

    // Global Namespace Start
    {
        LOCK(cs_mapAlerts);

        // Cancel previous alerts
        for (map<uint256, CAlert>::iterator mi = mapAlerts.begin(); mi != mapAlerts.end();)
        {
            const CAlert& alert = (*mi).second;
            
            if (Cancels(alert))
            {
                if (fDebug)
                {
                    LogPrint("alert", "%s : OK - Cancelling alert %d \n", __FUNCTION__, alert.nID);
                }

                uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);
                mapAlerts.erase(mi++);
            }
            else if (!alert.IsInEffect())
            {
                if (fDebug)
                {
                    LogPrint("alert", "%s : NOTICE - expiring alert %d \n", __FUNCTION__, alert.nID);
                }

                uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);
                mapAlerts.erase(mi++);
            }
            else
            {
                mi++;
            }
        }

        // Check if this alert has been cancelled
        for(PAIRTYPE(const uint256, CAlert)& item: mapAlerts)
        {
            const CAlert& alert = item.second;

            if (alert.Cancels(*this))
            {
                if (fDebug)
                {
                    LogPrint("alert", "%s : ERROR - Alert already cancelled by %d \n", __FUNCTION__, alert.nID);
                }

                return false;
            }
        }

        // Add to mapAlerts
        mapAlerts.insert(make_pair(GetHash(), *this));

        // Notify UI and -alertnotify if it applies to me
        if(AppliesToMe())
        {
            uiInterface.NotifyAlertChanged(GetHash(), CT_NEW);

            std::string strCmd = GetArg("-alertnotify", "");

            if (!strCmd.empty())
            {
                // Alert text should be plain ascii coming from a trusted source, but to
                // be safe we first strip anything not in safeChars, then add single quotes around
                // the whole string before passing it to the shell:
                std::string singleQuote("'");
                std::string safeStatus = SanitizeString(strStatusBar);

                safeStatus = singleQuote+safeStatus+singleQuote;
                boost::replace_all(strCmd, "%s", safeStatus);

                if (fThread)
                {
                    // thread runs free
                    boost::thread t(runCommand, strCmd);
                }
                else
                {
                    runCommand(strCmd);
                }
            }
        }
    }
    // Global Namespace End

    if (fDebug)
    {
        LogPrint("alert", "%s : OK - Accepted alert %d, AppliesToMe()=%d \n", __FUNCTION__, nID, AppliesToMe());
    }

    return true;
}
