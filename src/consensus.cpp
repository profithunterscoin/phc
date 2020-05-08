// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


//////////////////////////////////////////////////////////////////////////////
//
// Consensus
//

#include "consensus.h"
#include "util.h"

namespace Consensus
{
    /** -------------------------- 
        CCoinDistributionIndex
    **/

    CCoinDistributionIndex::CCoinDistributionIndex()
    {
        height = 0;
        timestamp = 0;
        addrname = "";
        proofofwork = false;
    }

    CCoinDistributionIndex::CCoinDistributionIndex(int nHeight)
    {
        height = nHeight;
        timestamp = 0;
        addrname = "";
        proofofwork = false;
    }

    CCoinDistributionIndex::CCoinDistributionIndex(int nHeight, int64_t nTimestamp)
    {
        height = nHeight;
        timestamp = nTimestamp;
        addrname = "";
        proofofwork = false;
    }

    CCoinDistributionIndex::CCoinDistributionIndex(int nHeight, int64_t nTimestamp, std::string nAddrname)
    {
        height = nHeight;
        timestamp = nTimestamp;
        addrname = nAddrname;
        proofofwork = false;
    }

    CCoinDistributionIndex::CCoinDistributionIndex(int nHeight, int64_t nTimestamp, std::string nAddrname, CBlockHeader nBlockheader)
    {
        height = nHeight;
        timestamp = nTimestamp;
        addrname = nAddrname;
        blockheader = nBlockheader;
        proofofwork = false;
    }

    CCoinDistributionIndex::CCoinDistributionIndex(int nHeight, int64_t nTimestamp, std::string nAddrname, CBlockHeader nBlockheader, bool nProofofwork)
    {
        height = nHeight;
        timestamp = nTimestamp;
        addrname = nAddrname;
        blockheader = nBlockheader;
    }

    /** -------------------------- **/

    /** -------------------------- 
        PeerBlockIndex
    **/

    int PeerBlockIndex::Blocks_HistoryTotal = 0;
    int PeerBlockIndex::Current_Position = 0;
    int PeerBlockIndex::Max_Size = 100;
    vector<pair<int, CCoinDistributionIndex>> PeerBlockIndex::map;

    /* FUNCTION: AddPosition */
    int PeerBlockIndex::AddPosition()
    {
        PeerBlockIndex::Current_Position++;

        if (PeerBlockIndex::Current_Position > Max_Size)
        {
            PeerBlockIndex::Current_Position = 0;
        }

        return PeerBlockIndex::Current_Position;
    }

    /* FUNCTION: NewPosition */
    int PeerBlockIndex::NewPosition()
    {
        CCoinDistributionIndex TempCoinDistributionIndex;

        PeerBlockIndex::map.push_back(make_pair(PeerBlockIndex::Blocks_HistoryTotal, TempCoinDistributionIndex));

        PeerBlockIndex::AddBlockNumber();

        return PeerBlockIndex::Current_Position;
    }

    /* FUNCTION: SetPosition */
    int PeerBlockIndex::SetPosition(int nPos)
    {
        PeerBlockIndex::Current_Position = nPos;

        if (PeerBlockIndex::Current_Position > Max_Size)
        {
            PeerBlockIndex::Current_Position = 0;
        }

        return PeerBlockIndex::Current_Position;
    }

    /* FUNCTION: GetPosition */
    int PeerBlockIndex::GetPosition()
    {
        return PeerBlockIndex::Current_Position;
    }

    /* FUNCTION: GetBlockNumber */
    int PeerBlockIndex::GetBlockNumber()
    {   
        if (PeerBlockIndex::Current_Position > 0)
        {
            return PeerBlockIndex::map[PeerBlockIndex::Current_Position].first;
        }

        return 0;
    }

    /* FUNCTION: AddBlockNumber */
    int PeerBlockIndex::AddBlockNumber()
    {
        PeerBlockIndex::Blocks_HistoryTotal++;

        PeerBlockIndex::map[PeerBlockIndex::Current_Position].first = PeerBlockIndex::Blocks_HistoryTotal;

        return PeerBlockIndex::map[PeerBlockIndex::Current_Position].first;
    }

    /* FUNCTION: GetHeight */
    int PeerBlockIndex::GetHeight()
    {
        if (PeerBlockIndex::Current_Position > 0)
        {
            return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.height;
        }

        return 0;
    }

    /* FUNCTION: SetHeight */
    int PeerBlockIndex::SetHeight(int nHeight)
    {
        PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.height = nHeight;

        return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.height;
    }

    /* FUNCTION: GetTimestamp */
    int64_t PeerBlockIndex::GetTimestamp()
    {
        if (PeerBlockIndex::Current_Position > 0)
        {
            return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.timestamp;
        }

        return 0;
    }

    /* FUNCTION: SetTimestamp */
    int64_t PeerBlockIndex::SetTimestamp(int64_t nTimestamp)
    {
        PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.timestamp = nTimestamp;

        return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.timestamp;
    }

    /* FUNCTION: GetAddrname */
    std::string PeerBlockIndex::GetAddrname()
    {
        if (PeerBlockIndex::Current_Position > 0)
        {
            return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.addrname;
        }

        return "";
    }

    /* FUNCTION: SetAddrname */
    std::string PeerBlockIndex::SetAddrname(std::string nAddrname)
    {
        PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.addrname = nAddrname;

        return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.addrname;
    }

    /* FUNCTION: GetHeader */
    CBlockHeader PeerBlockIndex::GetHeader()
    {
        CBlockHeader TempHeader;

        if (PeerBlockIndex::Current_Position > 0)
        {
            TempHeader = PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.blockheader;
        }

        return TempHeader;
    }

    /* FUNCTION: SetHeader */
    CBlockHeader PeerBlockIndex::SetHeader(CBlockHeader nBlockHeader)
    {
        PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.blockheader = nBlockHeader;

        return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.blockheader;
    }

    /* FUNCTION: GetProofOfWork */
    bool PeerBlockIndex::GetProofOfWork()
    {
        if (PeerBlockIndex::Current_Position > 0)
        {
            return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.proofofwork;
        }

        return false;
    }

    /* FUNCTION: SetProofOfWork */
    bool PeerBlockIndex::SetProofOfWork(bool nProofofWork)
    {
        PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.proofofwork = nProofofWork;

        return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.proofofwork;
    }

    /* FUNCTION: GetEntropyBit */
    int PeerBlockIndex::GetEntropyBit()
    {
        if (PeerBlockIndex::Current_Position > 0)
        {
            return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.entropybit;
        }

        return 0;
    }

    /* FUNCTION: SetEntropyBit */
    int PeerBlockIndex::SetEntropyBit(int nEntrobit)
    {
        PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.entropybit = nEntrobit;

        return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.entropybit;;
    }

    /* FUNCTION: GetMaxTransactionTime */
    int64_t PeerBlockIndex::GetMaxTransactionTime()
    {
        if (PeerBlockIndex::Current_Position > 0)
        {

            return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.maxtransactiontime;
        }

        return 0;
    }

    /* FUNCTION: SetMaxTransactionTime */
    int64_t PeerBlockIndex::SetMaxTransactionTime(int64_t nTime)
    {
        PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.maxtransactiontime = nTime;

        return PeerBlockIndex::map[PeerBlockIndex::Current_Position].second.maxtransactiontime;
    }

        /* FUNCTION: GetNodeCount */
    int PeerBlockIndex::GetNodeCount(std::string nAddrname)
    {
        int NodeCount = 0;

        // count occurances of each node in map
        for (int item = 0; item < (signed)PeerBlockIndex::map.size() - 1; item++)
        {
            if (StripPortFromAddrName(PeerBlockIndex::map[item].second.addrname) == StripPortFromAddrName(nAddrname))
            {
                NodeCount = NodeCount + 1;
            }
        }

        return NodeCount;
    }

    /** -------------------------- **/


    /** -------------------------- 
        Dynamic Distribution
    **/

    int DynamicCoinDistribution::Min_Cycle = 10;
    int DynamicCoinDistribution::Min_StakePercent = 5;
    int DynamicCoinDistribution::Max_StakePercent = 10;
    int DynamicCoinDistribution::Min_DistributionPercent = 5;
    int DynamicCoinDistribution::Max_DistributionPercent = 10;

    vector<std::string> DynamicCoinDistribution::Nodes_List;

    vector<pair<int, std::string>> DynamicCoinDistribution::mapPeerBlockHistory;

    /* FUNCTION: AddNode */
    bool DynamicCoinDistribution::AddNode(std::string AddrName)
    {
        std::vector<std::string>::iterator it = std::find(Nodes_List.begin(), Nodes_List.end(), AddrName);
        
        if (it != Nodes_List.end())
        {
            return false;
        }
        else
        {
            Nodes_List.push_back(AddrName);

            return true;
        }

        return false;
    }

    /* FUNCTION: FindPeerBlockHistory */
    bool DynamicCoinDistribution::FindPeerBlockHistory(std::string AddrName)
    {
        int Items = (signed)mapPeerBlockHistory.size() - 1;

        for (int item = 0; item < Items; item++)
        {
            if (mapPeerBlockHistory[item].second == AddrName)
            {
                return true;
            }
        }

        return false;
    }

    /* FUNCTION: NewPeerBlockHistory */
    bool DynamicCoinDistribution::NewPeerBlockHistory(std::string AddrName)
    {
        if (FindPeerBlockHistory(AddrName) == false)
        {
            mapPeerBlockHistory.push_back(make_pair(1, AddrName));

            return true;
        }

        return false;
    }

    /* FUNCTION: IncrementPeerBlockCount */
    int DynamicCoinDistribution::IncrementPeerBlockHistoryCount(std::string AddrName)
    {
        if (FindPeerBlockHistory(AddrName) == true)
        {
            int Items = (signed)mapPeerBlockHistory.size() - 1;

            for (int item = 0; item < Items; item++)
            {
                if (mapPeerBlockHistory[item].second == AddrName)
                {
                    mapPeerBlockHistory[item].first = mapPeerBlockHistory[item].first + 1;

                    return mapPeerBlockHistory[item].first;
                }
            }
        }

        return 0;
    }

    /* FUNCTION: SetPeerBlockCount */
    int DynamicCoinDistribution::SetPeerBlockHistoryCount(std::string AddrName, int nBlockCount)
    {
        if (FindPeerBlockHistory(AddrName) == true)
        {
            int Items = (signed)mapPeerBlockHistory.size() - 1;

            for (int item = 0; item < Items; item++)
            {
                if (mapPeerBlockHistory[item].second == AddrName)
                {
                    mapPeerBlockHistory[item].first = nBlockCount;

                    return mapPeerBlockHistory[item].first;
                }
            }
        }

        return 0;
    }

    /* FUNCTION: GetPeerBlockCount */
    int DynamicCoinDistribution::GetPeerBlockHistoryCount(std::string AddrName)
    {
        if (FindPeerBlockHistory(AddrName) == true)
        {
            int Items = (signed)mapPeerBlockHistory.size() - 1;

            for (int item = 0; item < Items; item++)
            {
                if (mapPeerBlockHistory[item].second == AddrName)
                {
                    return mapPeerBlockHistory[item].first;
                }
            }
        }

        return 0;
    }

    /* FUNCTION: Adjust */
    bool DynamicCoinDistribution::Adjust(int nHeight)
    {
        DynamicCoinDistribution::Nodes_List.clear();

        int PoSCount;
        PoSCount = 0;
        
        int PoSPercent;
        PoSPercent = 0;

        int Items = (signed)PeerBlockIndex::map.size() - 1;

        for (int item = 0; item < Items; item++)
        {
            // get all possible unique nodes
            AddNode(StripPortFromAddrName(PeerBlockIndex::map[item].second.addrname));

            // bypass POS checks until Staking is Active
            if (nHeight > Params().POSStartBlock())
            {
                // Count PoS Blocks,
                if (PeerBlockIndex::map[item].second.proofofwork == false)
                {
                    PoSCount = PoSCount + 1;
                }
            }
        }

        // bypass POS checks until Staking is Active
        if (nHeight > Params().POSStartBlock())
        {
            PoSPercent = (PoSCount / Items) * 100;

            // Adjust Cycle for Min_StakePercent
            if (PoSPercent <  DynamicCoinDistribution::Min_StakePercent)
            {
                DynamicCoinDistribution::Min_Cycle = DynamicCoinDistribution::Min_Cycle / 2;

                if (fDebug)
                {
                    LogPrint("asicchoker", "%s : NOTICE - Min_Cycle Changed: %d \n", __FUNCTION__, DynamicCoinDistribution::Min_Cycle);
                }
            }

            // Adjust Cycle for Max_StakePercent
            if (PoSPercent >  DynamicCoinDistribution::Max_StakePercent)
            {
                DynamicCoinDistribution::Min_Cycle = DynamicCoinDistribution::Min_Cycle * 2;

                if (fDebug)
                {
                    LogPrint("asicchoker", "%s : NOTICE - Min_Cycle Changed: %d \n", __FUNCTION__, DynamicCoinDistribution::Min_Cycle);
                }
            }

            // Limit to Min_Cycle to Max Items of PeerBlockIndex
            if (DynamicCoinDistribution::Min_Cycle > Items)
            {
                DynamicCoinDistribution::Min_Cycle = Items;
            }
        }

        if (fDebug)
        {
            LogPrint("asicchoker", "%s : NOTICE - PoS Percent %d \n", __FUNCTION__, PoSPercent);
        }

        vector<pair<int, std::string>> mapPeerBlockHistory;

        // create map of node occurances in PeerBlockIndex
        for (int node = 0; node < (signed)Nodes_List.size() - 1; node++)
        {
            if (FindPeerBlockHistory(Nodes_List[node]) == false)
            {
                NewPeerBlockHistory(Nodes_List[node]);

                SetPeerBlockHistoryCount(Nodes_List[node], PeerBlockIndex::GetNodeCount(Nodes_List[node]));
            }
            else
            {
                SetPeerBlockHistoryCount(Nodes_List[node], PeerBlockIndex::GetNodeCount(Nodes_List[node]));
            }
        }

        //std::string LowestNode;
        int LowestNodeBlockCount = 0;
        int LowestNodeBlockPercent = 0;

        //std::string HighestNode;
        int HighestNodeBlockCount = 0;
        int HighestNodeBlockPercent = 0;

        // Find Most occuring Node & Count  & Least occuring Node & Count
        for (int node = 0; node < (signed)mapPeerBlockHistory.size() - 1; node++)
        {
            // First Low Node
            if (LowestNodeBlockCount == 0)
            {
                LowestNodeBlockCount = mapPeerBlockHistory[node].first;
                LowestNodeBlockPercent = (LowestNodeBlockCount / (signed)mapPeerBlockHistory.size() - 1) * 100;
                //LowestNode = mapPeerBlockHistory[node].second;
            }

            // Currently the lowest node
            if (mapPeerBlockHistory[node].first < LowestNodeBlockCount)
            {
                LowestNodeBlockCount = mapPeerBlockHistory[node].first;
                LowestNodeBlockPercent = (LowestNodeBlockCount / (signed)mapPeerBlockHistory.size() - 1) * 100;
                //LowestNode = mapPeerBlockHistory[node].second;
            }

            // Currently the highest node
            if (mapPeerBlockHistory[node].first > HighestNodeBlockCount)
            {
                HighestNodeBlockCount = mapPeerBlockHistory[node].first;
                HighestNodeBlockPercent = (HighestNodeBlockCount / (signed)mapPeerBlockHistory.size() - 1) * 100;
                //HighestNode; = mapPeerBlockHistory[node].second;
            }
        }

        if (fDebug)
        {
            LogPrint("asicchoker", "%s : NOTICE - LowestNodeBlockCount: %d (%d) HighestNodeBlockCount: %d (%d) \n", __FUNCTION__, LowestNodeBlockCount, LowestNodeBlockPercent, HighestNodeBlockCount, HighestNodeBlockPercent);
        }

        // Adjust Cycle for too low of Distribution (Increase Minimum Cycle by / 2)
        if (LowestNodeBlockPercent <= DynamicCoinDistribution::Min_DistributionPercent)
        {
            DynamicCoinDistribution::Min_Cycle = DynamicCoinDistribution::Min_Cycle / 2;

            if (fDebug)
            {
                LogPrint("asicchoker", "%s : NOTICE - Min_Cycle Changed: %d \n", __FUNCTION__, DynamicCoinDistribution::Min_Cycle);
            }
        }

        // Adjust Cycle for too high of Distribution (Decrease Maximum Cycle by * 2)
        if (HighestNodeBlockPercent >= DynamicCoinDistribution::Max_DistributionPercent)
        {
            DynamicCoinDistribution::Min_Cycle = DynamicCoinDistribution::Min_Cycle * 2;

            if (fDebug)
            {
                LogPrint("asicchoker", "%s : NOTICE - Min_Cycle Changed: %d \n", __FUNCTION__, DynamicCoinDistribution::Min_Cycle);
            }
        }

        return true;
    }

    /* FUNCTION: ASIC_Choker */
    bool DynamicCoinDistribution::ASIC_Choker(std::string addrname, CBlock* pblock)
    {
        // Version 1.0.2 (C) 2019 Profit Hunters Coin in collaboration with Crypostle
        // Prevents consecutive blocks from the same node (decentralized coin distribution regardless of hash-power)

        if (fReindex
            || fImporting
            || IsInitialBlockDownload()
            || !TestNet())
        {
            // Bypass for Reindexing and Importing Bootstrap
            return false; 
        }

        if (!pblock)
        {
            return false;
        }

        if (addrname == "")
        {
            addrname = "Unknown";
        }

        // Block #1 (Default)
        int ActivationHeight = 1;

        int nHeight = 0;

        // PIP6 - ASIC Choker Activation
        ActivationHeight = Params().PIP6_Height();

        uint256 hash = pblock->GetHash();

        // Find if this block is already in the index
        if (mapBlockIndex.count(hash))
        {
            nHeight = mapBlockIndex[hash]->nHeight;
        }
        else
        {
            nHeight = nBestHeight;
        }

        // bypass Until Hard Fork 2
        if (nHeight < ActivationHeight)
        {
            return false;
        }

        CBlockHeader TempHeader;
        TempHeader.nVersion = pblock->GetVersion();
        TempHeader.nTime = pblock->GetBlockTime();
        TempHeader.hashPrevBlock = pblock->GetHashPrevBlock();
        TempHeader.hashMerkleRoot = pblock->GetHashMerkleRoot();
        TempHeader.nBits = pblock->GetBits();
        TempHeader.nNonce = pblock->GetNonce();

        PeerBlockIndex::NewPosition();
        PeerBlockIndex::SetHeight(nHeight);
        PeerBlockIndex::SetTimestamp(GetTime());
        PeerBlockIndex::SetAddrname(StripPortFromAddrName(addrname));
        PeerBlockIndex::SetHeader(TempHeader);
        PeerBlockIndex::SetProofOfWork(pblock->IsProofOfWork());
        PeerBlockIndex::SetEntropyBit(pblock->GetStakeEntropyBit());
        PeerBlockIndex::SetMaxTransactionTime(pblock->GetMaxTransactionTime());
        PeerBlockIndex::AddPosition();

        // bypass POS checks until Staking is Active
        if (nHeight > Params().POSStartBlock())
        {
            int PoSCount = 0;
            for (int item = 0; item < DynamicCoinDistribution::Min_Cycle; item++)
            {
                if (PeerBlockIndex::map[item].second.proofofwork == false)
                {
                    PoSCount = PoSCount + 1;
                }
            }

            // Min_Cycle for Proof of Work vs Proof of Stake
            if (PeerBlockIndex::Blocks_HistoryTotal >= DynamicCoinDistribution::Min_Cycle)
            {
                int NodeCompare;
                NodeCompare = PeerBlockIndex::Max_Size * (DynamicCoinDistribution::Max_StakePercent / 100);

                if (PoSCount < NodeCompare)
                {
                    if (pblock->IsProofOfWork() == false)
                    {
                        if (fDebug)
                        {
                            LogPrint("asicchoker", "%s : ERROR - REJECTED Block: %d PoS Count: %d PoS Compare: %d \n", __FUNCTION__, nHeight, PoSCount, NodeCompare);
                        }
                        
                        // reject New PoW block from peer (wait until more Staking Blocks are generated)
                        return true;
                    }
                }
            }
        }

        int NodeCount = 0;
        int IndexMax = (signed)PeerBlockIndex::map.size() - 1;
        int NodesTotal = IndexMax;

        // Prevent Overflow of Cycle
        if (DynamicCoinDistribution::Min_Cycle < IndexMax)
        {
            NodesTotal = DynamicCoinDistribution::Min_Cycle;
        }

        // PoW block must not be from same pfrom within Max Size blocks
        for (int item = 0; item < NodesTotal; item++)
        {
            if (StripPortFromAddrName(PeerBlockIndex::map[item].second.addrname) == StripPortFromAddrName(addrname))
            {
                NodeCount = NodeCount + 1;
            }
        }
        
        // Min_Cycle for Same Node
        if (PeerBlockIndex::Blocks_HistoryTotal >= DynamicCoinDistribution::Min_Cycle)
        {
            int NodeCompare;
            NodeCompare = PeerBlockIndex::Max_Size * (DynamicCoinDistribution::Max_DistributionPercent / 100);

            if (NodeCount < NodeCompare)
            {
                if (fDebug)
                {
                    LogPrint("asicchoker", "%s : ERROR - REJECTED Block: %d Node Count: %d Node Compare: %d \n", __FUNCTION__, nHeight, NodeCount, NodeCompare);
                }

                // reject too many NEW blocks from peer within cycle
                return true;
            }
        
        }

        if (PeerBlockIndex::Blocks_HistoryTotal > 3)
        {
            // Last 2 blocks must be from different node
            if (PeerBlockIndex::map[NodesTotal].second.addrname == PeerBlockIndex::map[NodesTotal - 1].second.addrname)
            {
                if (fDebug)
                {
                    LogPrint("asicchoker", "%s : ERROR - REJECTED Block: %d Node: %s \n", __FUNCTION__, nHeight, PeerBlockIndex::map[NodesTotal].second.addrname);
                }

                // reject consecutive new blocks
                return true;
            }
        }

        DynamicCoinDistribution::Adjust(nHeight);

        return false;
    }
    /** -------------------------- **/

    
    /** -------------------------- 
        ChainBuddy
    **/

    // ChainBuddy Status
    bool ChainBuddy::Enabled = true;

    // Best Chain
    DynamicCheckpoints::Checkpoint ChainBuddy::BestCheckpoint;

    // History        
    vector<std::pair<int, DynamicCheckpoints::Checkpoint>> ChainBuddy::ConsensusCheckpointMap;

    bool ChainBuddy::FindHash(uint256 hash)
    {
        if (ChainBuddy::Enabled == false)
        {
            return false;
        }
        
        if (ConsensusCheckpointMap.size() > 0)
        {
            for (int item = 0; item <= (signed)ConsensusCheckpointMap.size() - 1; ++item)
            {
                if (ConsensusCheckpointMap[item].second.hash == hash)
                {
                    return true;
                }
            }
        }

        return false;
    }


    bool ChainBuddy::AddHashCheckpoint(CNode *pnode)
    {
        if (ChainBuddy::Enabled == false)
        {
            return false;
        }

        bool found = ChainBuddy::FindHash(pnode->dCheckpointRecv.hash);

        if (found == false)
        {
            if (ChainBuddy::ConsensusCheckpointMap.size() > 49)
            {
                ConsensusCheckpointMap.erase(ConsensusCheckpointMap.begin());
            }

            DynamicCheckpoints::Checkpoint TempCheckpoint;
            TempCheckpoint.height = pnode->dCheckpointRecv.height;
            TempCheckpoint.hash = pnode->dCheckpointRecv.hash;
            TempCheckpoint.timestamp = pnode->dCheckpointRecv.timestamp;

            if (pnode->addrName != "")
            {
                TempCheckpoint.fromnode = pnode->addrName;
            }
            else
            {
                TempCheckpoint.fromnode = "Unknown";
            }

            ConsensusCheckpointMap.push_back(make_pair(1, TempCheckpoint));

            return true;
        }

        return false;
    }


    int ChainBuddy::GetNodeCount(uint256 hash)
    {
        if (ChainBuddy::Enabled == false)
        {
            return 0;
        }
        
        if (ConsensusCheckpointMap.size() > 0)
        {
            for (int item = 0; item <= (signed)ConsensusCheckpointMap.size() - 1; ++item)
            {
                if (ConsensusCheckpointMap[item].second.hash == hash)
                {
                    return ConsensusCheckpointMap[item].first;
                }
            }
        }

        return 0;
    }


    bool ChainBuddy::IncrementCheckpointNodeCount(CNode *pnode)
    {
        std::string TempAddrName;

        if (ChainBuddy::Enabled == false)
        {
            return false;
        }

        if (pnode->addrName != "")
        {
            TempAddrName = pnode->addrName;
        }
        else
        {
            TempAddrName = "Unknown";
        }

        if (ConsensusCheckpointMap.size() > 0)
        {
            for (int item = 0; item <= (signed)ConsensusCheckpointMap.size() - 1; ++item)
            {
                if (ConsensusCheckpointMap[item].second.hash == pnode->dCheckpointRecv.hash)
                {
                    size_t found;
                    found = 0;

                    if (TempAddrName != "")
                    {
                        found = ConsensusCheckpointMap[item].second.fromnode.find(TempAddrName); 
                    }
                    
                    if (found == std::string::npos
                        || found == 0)
                    {
                        ConsensusCheckpointMap[item].first = ConsensusCheckpointMap[item].first + 1;

                        if (TempAddrName != "")
                        {
                            std::string starter = "";
                            
                            if (ConsensusCheckpointMap[item].second.fromnode.size() > 0)
                            {
                                starter = ", ";
                            }

                            ConsensusCheckpointMap[item].second.fromnode.append(starter + TempAddrName);
                        }

                        return true;
                    }
                }
            }
        }

        return false;
    }


    bool ChainBuddy::FindConsensus()
    {
        if (!TestNet())
        {
            ChainBuddy::Enabled = false;
            
            // Skip on mainnet until testing is completed
            return false;
        }

        if (ChainBuddy::Enabled == false)
        {
            return false;
        }

        if (ConsensusCheckpointMap.size() == 0)
        {
            return false;
        }

        int MaxHeight = 0;
        int MaxNodes = 0;

        int ItemSelected = 0;

        for (int item = 0; item <= (signed)ConsensusCheckpointMap.size() - 1; ++item)
        {
            bool trigger;
            trigger = false;

            // Find Checkpoint with highest amount of node confirmations
            if (ConsensusCheckpointMap[item].second.height > MaxHeight)
            {
                MaxHeight = ConsensusCheckpointMap[item].second.height;
                trigger = true;
            }

            if (ConsensusCheckpointMap[item].first > MaxNodes)
            {
                MaxNodes = ConsensusCheckpointMap[item].first;
                trigger = true;
            }

            if (trigger == true)
            {
                ItemSelected = item;
            }

        }

        //cout << "MapSize:" << ConsensusCheckpointMap.size() << " Item:" << ItemSelected << endl;

        // Decide consensus among peers and most valid checkpoint then pdate BestCheckpoint
        if (ItemSelected > 0)
        {
            if (ConsensusCheckpointMap[ItemSelected].second.height < pindexBest->nHeight + 1)
            {
                BestCheckpoint.height = ConsensusCheckpointMap[ItemSelected].second.height;
                BestCheckpoint.hash = ConsensusCheckpointMap[ItemSelected].second.hash;
                BestCheckpoint.timestamp = ConsensusCheckpointMap[ItemSelected].second.timestamp;
                BestCheckpoint.fromnode = ConsensusCheckpointMap[ItemSelected].second.fromnode;

                return true;
            }
        }

        if (fDebug)
        {
            LogPrint("chainbuddy", "%s ERROR - ConsensusCheckpoint failed: Block Count: %d NOT LOWER Than Count Compare: %d \n",
                __FUNCTION__, ConsensusCheckpointMap[ItemSelected].second.height, pindexBest->nHeight + 1);
        }          

        return false;
    }

    bool ChainBuddy::WalletHasConsensus()
    {
        if (!TestNet())
        {
            ChainBuddy::Enabled = false;

            // Skip on mainnet until testing is completed
            return false; 
        }

        if (ChainBuddy::Enabled == false)
        {
            return false;
        }

        ChainBuddy::FindConsensus();

        int TempHeight;
        TempHeight = pindexBest->nHeight - BestCheckpoint.height;

        if (TempHeight > 5)
        {
            if (TempHeight > 5)
            {
                ChainShield::DisableNewBlocks = true;

                if (fDebug)
                {
                    LogPrint("chainbuddy", "%s ERROR - ConsensusCheckpoint failed: Block Count: %d NOT HIGHER THAN 5 \n",
                        __FUNCTION__, TempHeight);
                } 

                // Local wallet is out of sync from network consensus
                return false;
            }
        }

        // find last known common ansesessor checkpoint
        if (mapBlockIndex.find(BestCheckpoint.hash) != mapBlockIndex.end()
            && mapBlockIndex[BestCheckpoint.hash]->nHeight == (int)BestCheckpoint.height)
        {
            ChainShield::DisableNewBlocks = false;

            return true;
        }

        ChainShield::DisableNewBlocks = true;

        if (fDebug)
        {
            LogPrint("chainbuddy", "%s ERROR - ConsensusCheckpoint failed: Block Count: %d NOT Equal to: %d \n",
                __FUNCTION__, mapBlockIndex[BestCheckpoint.hash]->nHeight, (int)BestCheckpoint.height);
        } 

        return false;
    }


    // TO-DO also add CheckPointHistory vector to pnode
    /*
    bool ChainBuddy::NodeHasConsensus(CNode* pnode)
    {
        if (pnode->dCheckpointRecv.hash == BestCheckpoint.hash
            && pnode->dCheckpointRecv.height == BestCheckpoint.height
            && pnode->dCheckpointRecv.timestamp == BestCheckpoint.timestamp)
        {
            return true;
        }

        return false;
    }
    */

    /** --------------------------  **/


    /** -------------------------- 
        ChainShield
    **/

    // ChainShield Status
    bool ChainShield::Enabled = false;

    // Last Block Height protected
    int ChainShield::ChainShieldCache = 0;

    // Disable PoW/PoS/Masternode block creation (becomes true upon FindConsensus()=false)
    bool ChainShield::DisableNewBlocks = false;

    // Rollback when local wallet is too far ahead of network
    bool ChainShield::Rollback_Runaway = true;

    bool ChainShield::Protect()
    {
        if (!TestNet())
        {
            ChainShield::Enabled = false;
            ChainShield::DisableNewBlocks = false;
            ChainShield::Rollback_Runaway = false;
            
            // Skip on mainnet until testing is completed
            return false;
        }

        if (ChainShield::Enabled == false)
        {
            // Skip until enabled
            return false;
        }

        //  Only execute every 1 blocks
        if (ChainShield::ChainShieldCache > 0 && ChainShield::ChainShieldCache + 1 < pindexBest->nHeight)
        {
            // Skip and wait for more blocks
            return false;
        }

        if (ChainShield::ChainShieldCache > pindexBest->nHeight)
        {
            return false;
        }

        ChainShield::ChainShieldCache = pindexBest->nHeight;

        int Agreed = 0;
        int Disagreed = 0;

        int MaxHeight = 0;
        int MaxHeightNodes = 0;

        LOCK(cs_vNodes);

        // Find if nodes are synced (agreed to local wallet checkpoint or not)
        for(CNode* pnode: vNodes)
        {
            if (pnode->fSuccessfullyConnected)
            {
                if (pnode->dCheckpointRecv.height == pnode->dCheckpointSent.height
                    && pnode->dCheckpointRecv.hash == pnode->dCheckpointSent.hash)
                {
                    // Local Wallet and Node have consensus (increment temp counter)
                    Agreed++;

                    if (MaxHeight > pnode->dCheckpointSent.height)
                    {
                        MaxHeight = pnode->dCheckpointSent.height;
                        MaxHeightNodes++;
                    }

                    // Find if this hash is in current ChainBuddy::BestCheckpoint
                    if (ChainBuddy::FindHash(pnode->dCheckpointRecv.hash) == true)
                    {
                        if (ChainBuddy::IncrementCheckpointNodeCount(pnode) == false)
                        {
                            if (fDebug)
                            {
                                LogPrint("chainshield", "%s : WARNING - IncrementCheckpoint Failed %d. \n", __FUNCTION__, pnode->dCheckpointRecv.height);
                            }
                        }
                    }
                    else
                    {
                        if (pnode->dCheckpointRecv.height > pindexBest->nHeight - 5)
                        {
                            if (ChainBuddy::AddHashCheckpoint(pnode) == false)
                            {
                                if (fDebug)
                                {
                                    LogPrint("chainshield", "%s : WARNING - AddHashCheckpoint Failed %d. \n", __FUNCTION__, pnode->dCheckpointRecv.height);
                                }
                            }
                        }
                    }
                }
                else
                {
                    // use quick nodes with little to no sync lag that's off by more than 1 block & no more than 500 milliseconds
                    if (pnode->dCheckpointSent.timestamp - pnode->dCheckpointRecv.timestamp < 500
                        && pnode->dCheckpointSent.height - pnode->dCheckpointRecv.height > 1)
                    {
                        // Local Wallet and Node DO NOT have consensus
                        Disagreed++;

                        if (MaxHeight > pnode->dCheckpointSent.height)
                        {
                            MaxHeight = pnode->dCheckpointSent.height;
                            MaxHeightNodes++;
                        }
                    }
                }
            }
        }

        bool trigger;

        if (ChainBuddy::WalletHasConsensus() == true)
        {
            // No Shielding Required
            return false;
        }
        else
        {
            // Local wallet is out of sync, try to auto-correct
            trigger = true;
        }

        // compare both Agreed and Disagreed temp counters and attempt to repair local wallet if no consensus is found among peers
        if (Disagreed > Agreed)
        {
            // Peers are not in consensus try to auto-correct if they're below current blockchain height
            trigger = true; 
        }

        if (pindexBest->nHeight < ChainShield::ChainShieldCache)
        {
            // Skip
            trigger = false; 
        }

        if (pindexBest->nHeight < MaxHeight && MaxHeight > 0)
        {
            // Skip
            trigger = false; 
        }

        if (ChainBuddy::BestCheckpoint.height == 0)
        {
            // skip if no bestcheckpoint is selected yet
            trigger = false;
        }

        if (ChainBuddy::BestCheckpoint.height < pindexBest->nHeight
            && ChainShield::ChainShieldCache == pindexBest->nHeight)
        {
            // skip if no bestcheckpoint if checkpoint is too old
            trigger = false;
        }

        if (ChainShield::Rollback_Runaway == false)
        {
            // skip if because user disabled it
            trigger = false;
        }

        // Forked wallet auto-correction
        if (trigger == true)
        {
            if (fDebug)
            {
                LogPrint("chainshield", "%s : NOTICE - Fork Detected (Runaway Exception), Rolling back 5 blocks, force resync %d \n", __FUNCTION__, pindexBest->nHeight);
            }

            CChain::RollbackChain(2);

            MilliSleep(10000);

            CNode* blank_filter = 0;

            CChain::ForceSync(blank_filter, uint256(0));

            // Shielding forced to protect local blockchain database
            return true;
        }

        // No Shielding Required
        return false; 
    }

    /** --------------------------  **/

}
