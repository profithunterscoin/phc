// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018 Profit Hunters Coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef BITCOIN_CHECKPOINT_H
#define  BITCOIN_CHECKPOINT_H

#include <map>
#include "uint256.h"
#include "util.h"

class uint256;
class CBlockIndex;

/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{

    // Returns true if block passes checkpoint checks
    bool CheckHardened(int nHeight, const uint256& hash);

    bool CheckSync(int nHeight);

    // Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate();

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex);

    const CBlockIndex* AutoSelectSyncCheckpoint();

}

namespace DynamicCheckpoints
{
    // Dynamic Checkpoints 1.0.0
    // (C) 2019 - Profit Hunters Coin

    class Checkpoint
    {
        public:

            Checkpoint();
            Checkpoint(int64_t height);
            Checkpoint(int64_t height, const uint256& hash);
            Checkpoint(int64_t height, const uint256& hash, int64_t timestamp);
            Checkpoint(int64_t height, const uint256& hash, int64_t timestamp, bool synced);
            Checkpoint(int64_t height, const uint256& hash, int64_t timestamp, bool synced, std::string fromNode);

            IMPLEMENT_SERIALIZE
            (
                READWRITE(height);
                READWRITE(hash);
                READWRITE(timestamp);
                READWRITE(synced);
                READWRITE(fromNode);
            )

            int64_t height;
            uint256 hash;
            int64_t timestamp;
            bool synced;
            std::string fromNode;

    };
}

#endif
