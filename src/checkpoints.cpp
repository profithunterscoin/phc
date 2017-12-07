// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"


static const int nCheckpointSpan = 5000;

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
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
		(0, uint256("0x0000ff2cca8cca6a2242df9a131655b19ef8f35eaca6b4c013fec7b675d8a19f"))
		(2, uint256("0x52e5b1a6ed4103023d4d8ec352575cb47388d271a7948ce5bf2d0e0be569a049"))
		(69, uint256("0x9b94945adca1518990da7c201f7bfe63fbacd438a453079cf77b364508f98133"))
		(259, uint256("0x852726dd7da534cfc7cb7c1de5eefd21c261bda08540c2478d9fd1cfc9b5435d"))
		(784, uint256("0xeaa1f55b46e467e80953b40a8993f38c76116d1b7b8d0758bad3ef6c786855a3"))
		(1152, uint256("0xd8f496dc9ae64014168a919556a247fbc1db3986e592e701de1ce5a214339bd4"))
		(1354, uint256("0x3b9227fa4649e8511bef9a812a9b355bf58427dc6976bc28455517051913a212"))
		(1684, uint256("0x8e4a7280c6f5177e15c3909b83d7a76cc7cd2a0e7ba63244583b4e82274fda5d"))
		(1745, uint256("0x0facb534fc87818b02ccbb9c92225974831a8b54ff21f04c409edd80d67d0916"))
		(2000, uint256("0x1d4784cf403506129f8022a886ed6904ebf4c251820fadd9a76a74debae51886"))
		(2094, uint256("0x5c774f43e8d23b579fa4c459589baafa96b96e3e37d7fd1b405b668544143294"))
		(2491, uint256("0xd3259d8ecb82562f95847be2f0a3e8c65155aeecbbb802399521f61c48bbb3ff"))
		(2946, uint256("0xae452339f4244137a7ece8b39f7414a38e7becd4c869e2f47d1ac8b6bcbb51b0"))
		(3675, uint256("0xc25e1aec9d320e1a3ea09ce24125a7d0996626d1a5e113061f6919c48ea61307"))
		(4012, uint256("0x75c1870c3a52c058278731d98cee8e4357430e9743c032fac18fe3fe7cb710ff"))
		(4682, uint256("0x09ce1fe4bcf315468a9ed6f04ad93ab53993309fdf35804673e819775130395b"))
		(4915, uint256("0x0296eedbafa0b8cdbe0087a9d498259a63ccbda5d92e1a8cbe9cc73bd732d80b"))
		(5216, uint256("0x46fa6ce91bb76e1cb262337179dfeffb81eb2d25c72259ef2b7bf8e0c736b722"))
		(5746, uint256("0x7fdac27b46a13704fd8e6bd932572994028e7d9027038d270ae4f6e07d0b94db"))
		(6945, uint256("0x04251f52b654a77e5a2d64f40c97610ce09733a657a01e0d034c6136c4c28ac7"))
		(7296, uint256("0xda75f41443a11937c00a24787396549e46244ddbae68561507b650a1e57d4573"))
	    (8547, uint256("0x04fcda6e911766a91fb008f52808e241ce1ebc40853b22fac8ac499f941aa3d5"))
		(9983, uint256("0xfd40e7656f00d85a5f362506769fdddd24b48dfd23856e9082e74e161b6f8721"))
		(10574, uint256("0x0d840457e7bd741a56701fcb5602fc4b3d14ebb59cb784e0ed1f9fb37fd240c0"))
		(11911, uint256("0xcef963562df55663f09d69d22faef1042ab51329bff876abc10580af8805fc89"))
		(12563, uint256("0x09999452b73077118412f83a390d087b73330282adbcd3bca144573f9bf46b83"))
		(14923, uint256("0x47a9ab27a9be09544dfcefc4756da9607ddb21187bc99c86f05fe492e0e2d1bc"))
		(15344, uint256("0xd083a0a97b75b8d1729513ae06b617b294b91644c3c111324abc0b68bdaabb08"))
		(16286, uint256("0xb8c6bed43a82e9a5e54ebbf04a1a7b989dd6b56f8ea86e8ec73ebd04fbb46ad7"))
    ;

    // TestNet has no checkpoints
    static MapCheckpoints mapCheckpointsTestnet;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        if (checkpoints.empty())
            return 0;
        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    // Automatically select a suitable sync-checkpoint 
    const CBlockIndex* AutoSelectSyncCheckpoint()
    {
        const CBlockIndex *pindex = pindexBest;
        // Search backward for a block within max span and maturity window
        while (pindex->pprev && pindex->nHeight + nCheckpointSpan > pindexBest->nHeight)
            pindex = pindex->pprev;
        return pindex;
    }

    // Check against synchronized checkpoint
    bool CheckSync(int nHeight)
    {
        const CBlockIndex* pindexSync = AutoSelectSyncCheckpoint();
        if (nHeight <= pindexSync->nHeight){
            return false;
        }
        return true;
    }
}
