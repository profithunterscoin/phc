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


#ifndef BITCOIN_CHAIN_PARAMS_H
#define BITCOIN_CHAIN_PARAMS_H

#include "bignum.h"
#include "uint256.h"
#include "util.h"

#include <vector>

using namespace std;

#define MESSAGE_START_SIZE 4
typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

class CAddress;
class CBlock;

struct CDNSSeedData
{
    string name, host;

    CDNSSeedData(const string &strName, const string &strHost) : name(strName), host(strHost)
    {}
};


/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
    public:

        enum Network
        {
            MAIN,
            TESTNET,
            REGTEST,
            MAX_NETWORK_TYPES
        };

        enum Base58Type
        {
            PUBKEY_ADDRESS,
            SCRIPT_ADDRESS,
            SECRET_KEY,
            STEALTH_ADDRESS,
            EXT_PUBLIC_KEY,
            EXT_SECRET_KEY,
            MAX_BASE58_TYPES
        };

        const uint256& HashGenesisBlock() const
        {
            return hashGenesisBlock;
        }
        
        const MessageStartChars& MessageStart() const
        {
            return pchMessageStart;
        }
        
        const vector<unsigned char>& AlertKey() const
        {
            return vAlertPubKey;
        }

        const CBigNum& ProofOfWorkLimit() const
        {
            return bnProofOfWorkLimit;
        }

        const vector<CDNSSeedData>& DNSSeeds() const
        {
            return vSeeds;
        }
        
        const std::vector<unsigned char> &Base58Prefix(Base58Type type) const
        {
            return base58Prefixes[type];
        }

        virtual const vector<CAddress>& FixedSeeds() const = 0;

        virtual const CBlock& GenesisBlock() const = 0;

        virtual bool RequireRPCPassword() const
        {
            return true;
        }
        
        const string& DataDir() const 
        {
            return strDataDir;
        }
        
        virtual Network NetworkID() const = 0;

        int RPCPort() const
        {
            return nRPCPort;
        }
        
        int LastPOWBlock() const
        {
            return nLastPOWBlock;
        }
        
        int POSStartBlock() const
        { 
            return nPOSStartBlock;
        }
        
        int PoolMaxTransactions() const
        {
            return nPoolMaxTransactions; 
        }
        
        int SubsidyHalvingInterval() const
        {
            return nSubsidyHalvingInterval;
        }
        
        int GetDefaultPort() const
        {
            return nDefaultPort;
        }

        std::string DarksendPoolDummyAddress() const
        {
            return strDarksendPoolDummyAddress;
        }

        std::string DevRewardAddress() const
        {
            return strDevRewardAddress;
        }

        int GetHardFork_1() const
        {
            return nHardFork_1;
        }

        int GetHardFork_2() const
        {
            return nHardFork_2;
        }

        //std::string SporkKey() const { return strSporkKey; }
        //std::string MasternodePaymentPubKey() const { return strMasternodePaymentsPubKey; }

    protected:

        CChainParams() {};

        uint256 hashGenesisBlock;
        MessageStartChars pchMessageStart;

        // Raw pub key bytes for the broadcast alert signing key.
        vector<unsigned char> vAlertPubKey;

        int nDefaultPort;
        int nRPCPort;
        
        CBigNum bnProofOfWorkLimit;

        int nSubsidyHalvingInterval;

        string strDataDir;
        vector<CDNSSeedData> vSeeds;
        std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];

        int nLastPOWBlock;
        int nPOSStartBlock;
        int nPoolMaxTransactions;

        int nHardFork_1;
        int nHardFork_2;

        std::string strDarksendPoolDummyAddress;
        std::string strDevRewardAddress;

        //std::string strSporkKey;
        //std::string strMasternodePaymentsPubKey;
};


/**
 * Return the currently selected parameters. This won't change after app startup
 * outside of the unit tests.
 */
const CChainParams &Params();


/** Sets the params returned by Params() to those for the given network. */
void SelectParams(CChainParams::Network network);


/**
 * Looks for -regtest or -testnet and then calls SelectParams as appropriate.
 * Returns false if an invalid combination is given.
 */
bool SelectParamsFromCommandLine();


inline bool TestNet()
{
    // Note: it's deliberate that this returns "false" for regression test mode.
    return Params().NetworkID() == CChainParams::TESTNET;
}

#endif
