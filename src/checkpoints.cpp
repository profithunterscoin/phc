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


#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/range/adaptor/reversed.hpp>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"


static const int nCheckpointSpan = 5000;


// namespace dynamic checkpoints



namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //

    // MainNet
    static MapCheckpoints mapCheckpoints = boost::assign::map_list_of
		(0, uint256("0000b587d86da35102be091d9d303851d53130a70375a2ae6b8827ca18feb00d"))
        (5431, uint256("0ea876e7fb2834cacaf7767ad111cbca0bb94f3026bd1c8a264df68d4b4b6f70"))
        (11674, uint256("95cf94609fc418fa377db5399527dd862d83d95d8d0f6a18c37366ce2f886de8"))
        (46866, uint256("e44fb7680767b77778b4bbb06ecfa5c560f70e847065037637e75218df601f59"))
        (59557, uint256("f9006b868e12f990ff5b8732bd126aaeef260617a4b384a4e55a0bc97076210d"))
        (105260, uint256("f4dc914767a9bdd700fc7ee05782a2a06320ef875c602127852423e7a6104b10"))
        (169254, uint256("866ed020ac69c2e10bf7d80b2d99b44251d549cf008fdea0e37eb1447ebefb0d"))
        (760365, uint256("bf7cad650868c964204139b1ebd15e55b685ec0e43d8fa6b4bc7d912caeedcf4"))
        (1244657, uint256("59d0e34db2bcf82bad84a17a84eb90097311871104069595bf0b429a11fc5c5a"))
    ;

    // TestNet
    static MapCheckpoints mapCheckpointsTestnet = boost::assign::map_list_of
    	(0, uint256("0000ce8f49c8c59ed8a4c50cdacddc1f84b1be04e52232989887c99aad3e8e4e"))
    ;   

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);

        if (i == checkpoints.end())
        {
            return true;
        }

        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        if (checkpoints.empty())
        {
            return 0;
        }

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        for(const MapCheckpoints::value_type& i: boost::adaptors::reverse(checkpoints))
        {
            const uint256& hash = i.second;

            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);

            if (t != mapBlockIndex.end())
            {
                return t->second;
            }
        }

        return NULL;
    }

    // Automatically select a suitable sync-checkpoint 
    const CBlockIndex* AutoSelectSyncCheckpoint()
    {
        if (pindexBest)
        {
            const CBlockIndex *pindex = pindexBest;

            // Search backward for a block within max span and maturity window
            while (pindex->pprev && pindex->nHeight + nCheckpointSpan > pindexBest->nHeight)
            {
                pindex = pindex->pprev;
            }
            
            return pindex;
        }

        return NULL;
    }

    // Check against synchronized checkpoint
    bool CheckSync(int nHeight)
    {
        const CBlockIndex* pindexSync = AutoSelectSyncCheckpoint();

        if (nHeight <= pindexSync->nHeight)
        {
            return false;
        }

        return true;
    }
}


namespace DynamicCheckpoints
{
    Checkpoint::Checkpoint()
    {
        height = 0;
        hash = 0;
        timestamp = 0;
        synced = false;
        fromnode = "";
    }

    Checkpoint::Checkpoint(int64_t heightin, const uint256& hashin)
    {
        height = heightin;
        hash = hashin;
        timestamp = 0;
        synced = false;
        fromnode = "";
    }

    Checkpoint::Checkpoint(int64_t heightin, const uint256& hashin, int64_t timestampin)
    {
        height = heightin;
        hash = hashin;
        timestamp = timestampin;
        synced = false;
        fromnode = "";
    }

    Checkpoint::Checkpoint(int64_t heightin, const uint256& hashin, int64_t timestampin, bool syncedin)
    {
        height = heightin;
        hash = hashin;
        timestamp = timestampin;
        synced = syncedin;
        fromnode = "";
    }

    Checkpoint::Checkpoint(int64_t heightin, const uint256& hashin, int64_t timestampin, bool syncedin, std::string fromnodein)
    {
        height = heightin;
        hash = hashin;
        timestamp = timestampin;
        synced = syncedin;
        fromnode = fromnodein;
    }
}
