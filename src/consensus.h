// Copyright (c) 2018 Profit Hunters Coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


//////////////////////////////////////////////////////////////////////////////
//
// Consensus
//

#include "main.h"

class CBlockHeader;

namespace Consensus
{
    // Consensus Class 1.0.1 (Satoshi's Vision 2.0) (C) 2019 Profit Hunters Coin

    class CCoinDistributionIndex
    {
        // CoinDistributionIndex 1.0 (C) 2019 Profit Hunters Coin

        public:

            CCoinDistributionIndex();
            CCoinDistributionIndex(int nHeight);
            CCoinDistributionIndex(int nHeight, int64_t nTimestamp);
            CCoinDistributionIndex(int nHeight, int64_t nTimestamp, std::string nAddrname);
            CCoinDistributionIndex(int nHeight, int64_t nTimestamp, std::string nAddrname, CBlockHeader nBlockheader);
            CCoinDistributionIndex(int nHeight, int64_t nTimestamp, std::string nAddrname, CBlockHeader nBlockheader, bool nProofofwork);

            IMPLEMENT_SERIALIZE
            (
                READWRITE(height);
                READWRITE(timestamp);
                READWRITE(addrname);
                READWRITE(blockheader);
                READWRITE(proofofwork);
            )

            int height;
            int64_t timestamp; // Timestamp for when added to Index
            std::string addrname;
            CBlockHeader blockheader; //int32_t nVersion; uint256 hashPrevBlock; uint256 hashMerkleRoot; uint32_t nTime; uint32_t nBits; uint32_t nNonce;
            bool proofofwork;
            int entropybit;
            int64_t maxtransactiontime;
    };

    class PeerBlockIndex
    {
        public:

            static vector<std::pair<int, CCoinDistributionIndex>> map;  //PeerBlockIndex::map  (BlockNumber_History, CCoinDistributionIndex)

            static int Blocks_HistoryTotal;
            static int Current_Position;
            static int Max_Size;

            static int AddPosition();
            static int NewPosition();
            static int SetPosition(int nPos);
            static int GetPosition();

            static int AddBlockNumber();
            static int GetBlockNumber();

            static int GetHeight();
            static int SetHeight(int nHeight);

            static int64_t GetTimestamp();
            static int64_t SetTimestamp(int64_t nTimestamp);

            static std::string GetAddrname();
            static std::string SetAddrname(std::string nAddrname);

            static CBlockHeader GetHeader();
            static CBlockHeader SetHeader(CBlockHeader nBlockHeader);

            static bool GetProofOfWork();
            static bool SetProofOfWork(bool nProofofWork);

            static int GetEntropyBit();
            static int SetEntropyBit(int nEntrobit);

            static int64_t GetMaxTransactionTime();
            static int64_t SetMaxTransactionTime(int64_t nTime);

            static int GetNodeCount(std::string nAddrname);           

    };

    class DynamicCoinDistribution
    {
        // CoinDistributionIndex 1.0 (C) 2019 Profit Hunters Coin

        public:

            static vector<std::string> Nodes_List;

            static bool AddNode(std::string AddrName);

            static vector<pair<int, std::string>> mapPeerBlockHistory;

            static bool FindPeerBlockHistory(std::string AddrName);
            static bool NewPeerBlockHistory(std::string AddrName);
            static int IncrementPeerBlockHistoryCount(std::string AddrName);
            static int SetPeerBlockHistoryCount(std::string AddrName, int nBlockCount);
            static int GetPeerBlockHistoryCount(std::string AddrName);
            
            static int Min_Cycle;

            static int Min_StakePercent;
            static int Max_StakePercent;

            static int Min_DistributionPercent;
            static int Max_DistributionPercent;

            static bool Adjust(int nHeight);
            static bool ASIC_Choker(std::string addrname, CBlock* pblock);
    };

    class ChainBuddy
    {
        // Chain Buddy 1.0 (Satoshi's Vision 2.0) (C) 2019 Profit Hunters Coin
        // Find the best Dynamic Checkpoint among peers
        // Most valid chain decided by the network, not block height+1 or elevated proof of work

        public:

                static bool Enabled; // ChainShield Enabled = TRUE/FALSE

                static DynamicCheckpoints::Checkpoint BestCheckpoint; // Best Chain
                        
                static vector<std::pair<int, DynamicCheckpoints::Checkpoint>> ConsensusCheckpointMap; // History

                static bool FindHash(uint256 hash);

                static bool AddHashCheckpoint(CNode *pnode);

                static int GetNodeCount(uint256 hash);

                static bool IncrementCheckpointNodeCount(CNode *pnode);

                static bool FindConsensus();

                static bool WalletHasConsensus();

                static bool NodeHasConsensus(CNode* pnode);

    };


    class ChainShield
    {
        // ChainShield 1.0.0 (C) 2019 Profit Hunters Coin
        // Peer to peer Satoshi's Consensus to prevent local wallet from getting stuck on a forked chain
        // Forces local blockchain rollback and resync to organize most valid chain
        // Requirements: Dynamic Checkpoints 1.0.0
        // Recommended: Implemented with Bitcoin Firewall X.X.X & Blockshield & ASIC Choker

        public:

            static bool Enabled; // ChainShield Enabled = TRUE/FALSE

            static int ChainShieldCache; // Last Block Height protected

            static bool DisableNewBlocks; // Disable PoW/PoS/Masternode block creation

            static bool Rollback_Runaway; // Rollback chain when runnaway fork detected

            static bool Protect();

    };
}

