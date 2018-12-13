// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018 Profit Hunters Coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "net.h"
#include "masternodeconfig.h"
#include "util.h"
#include <base58.h>

CMasternodeConfig masternodeConfig;


void CMasternodeConfig::add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex, std::string rewardAddress, std::string rewardPercent)
{
    CMasternodeEntry cme(alias, ip, privKey, txHash, outputIndex, rewardAddress, rewardPercent);

    entries.push_back(cme);
}


bool CMasternodeConfig::read(boost::filesystem::path path)
{
    boost::filesystem::ifstream streamConfig(GetMasternodeConfigFile());

    if (!streamConfig.good())
    {
        return true; // No masternode.conf file is OK
    }

    for(std::string line; std::getline(streamConfig, line);)
    {
        if(line.empty())
        {
            continue;
        }

        std::istringstream iss(line);
        std::string alias, ip, privKey, txHash, outputIndex, reward, rewardAddress, rewardPercent;
        
        if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex >> reward))
        {
            rewardAddress = "";
            rewardPercent = "";
            
            iss.str(line);
            iss.clear();
            
            if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex))
            {
                if (fDebug)
                {
                    LogPrint("masternode", "% -- : Could not parse masternode.conf line: %s\n", __func__, line.c_str());
                }

                streamConfig.close();
            
                return false;
            }
        }
        else
        {
            size_t pos = reward.find_first_of(":");
            
            if(pos == string::npos)
            {
                // no ":" found
                rewardPercent = "100";
                rewardAddress = reward;
            }
            else
            {
                rewardPercent = reward.substr(pos + 1);
                rewardAddress = reward.substr(0, pos);
            }
            
            CBitcoinAddress address(rewardAddress);
            
            if (!address.IsValid())
            {
                if (fDebug)
                {
                    LogPrint("masternode", "% -- : Invalid TX address in masternode.conf line: %s\n", __func__, line.c_str());
                }

                streamConfig.close();
                
                return false;
            }
        }

        add(alias, ip, privKey, txHash, outputIndex, rewardAddress, rewardPercent);
    }

    streamConfig.close();
    
    return true;
}