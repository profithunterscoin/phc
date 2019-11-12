// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2019 Profit Hunters Coin developers

// Authored by Google, Inc. Learn more: http://code.google.com/p/leveldb/
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#include <map>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <memenv/memenv.h>

#include "kernel.h"
#include "checkpoints.h"
#include "txdb.h"
#include "util.h"
#include "main.h"
#include "chainparams.h"

using namespace std;
using namespace boost;


leveldb::DB *txdb; // global pointer for LevelDB object instance


static leveldb::Options GetOptions()
{
    leveldb::Options options;

    int nCacheSizeMB = GetArg("-dbcache", 10);

    options.block_cache = leveldb::NewLRUCache(nCacheSizeMB * 1048576);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    return options;
}


void init_blockindex(leveldb::Options& options, bool fRemoveOld = false)
{
    // First time init.
    filesystem::path directory = GetDataDir(true) / "txleveldb";

    if (fRemoveOld)
    {
        filesystem::remove_all(directory); // remove directory

        unsigned int nFile = 1;

        while (true)
        {
            filesystem::path strBlockFile = GetDataDir(true) / strprintf("blk%04u.dat", nFile);

            // Break if no such file
            if( !filesystem::exists( strBlockFile ) )
            {
                break;
            }

            filesystem::remove(strBlockFile);

            nFile++;
        }
    }

    filesystem::create_directory(directory);
    
    if (fDebug)
    {
        LogPrint("leveldb", "%s : Opening LevelDB in %s\n", __FUNCTION__, directory.string());
    }

    leveldb::Status status = leveldb::DB::Open(options, directory.string(), &txdb);
    
    if (!status.ok())
    {
        throw runtime_error(strprintf("init_blockindex(): error opening database environment %s", status.ToString()));
    }
}


// CDB subclasses are created and destroyed VERY OFTEN. That's why
// we shouldn't treat this as a free operations.
CTxDB::CTxDB(const char* pszMode)
{
    if (pszMode == 0)
    {
        if (fDebug)
        {
            LogPrint("leveldb", "%s : pszMode == 0 (assert-1)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-1)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return;
    }
    
    activeBatch = NULL;
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));

    if (txdb)
    {
        pdb = txdb;
    
        return;
    }

    bool fCreate = strchr(pszMode, 'c');

    options = GetOptions();
    options.create_if_missing = true;
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    init_blockindex(options); // Init directory

    pdb = txdb;

    if (Exists(string("version")))
    {
        ReadVersion(nVersion);
        
        if (fDebug)
        {
            LogPrint("leveldb", "%s : Transaction index version is %d\n", __FUNCTION__, nVersion);
        }

        if (nVersion < DATABASE_VERSION)
        {
            if (fDebug)
            {
                LogPrint("leveldb", "%s : Required index version is %d, removing old database\n", __FUNCTION__, DATABASE_VERSION);
            }

            // Leveldb instance destruction
            delete txdb;
            
            txdb = pdb = NULL;
            
            delete activeBatch;
            
            activeBatch = NULL;

            init_blockindex(options, true); // Remove directory and create new database
            
            pdb = txdb;
            bool fTmp = fReadOnly;
            fReadOnly = false;
            
            WriteVersion(DATABASE_VERSION); // Save transaction index version
            
            fReadOnly = fTmp;
        }
    }
    else if (fCreate)
    {
        bool fTmp = fReadOnly;
        fReadOnly = false;
        
        WriteVersion(DATABASE_VERSION);
        
        fReadOnly = fTmp;
    }

    if (fDebug)
    {
        LogPrint("leveldb", "%s : Opened LevelDB successfully\n", __FUNCTION__);
    }
}


void CTxDB::Close()
{
    delete txdb;
    txdb = pdb = NULL;
    
    delete options.filter_policy;
    
    options.filter_policy = NULL;
    delete options.block_cache;
    
    options.block_cache = NULL;
    delete activeBatch;
    
    activeBatch = NULL;
}


bool CTxDB::TxnBegin()
{
    if (activeBatch != 0)
    {
        if (fDebug)
        {
            LogPrint("leveldb", "%s : activeBatch != 0 (assert-2)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-2)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }
    
    activeBatch = new leveldb::WriteBatch();
    
    return true;
}


bool CTxDB::TxnCommit()
{
    if (activeBatch == 0)
    {
        if (fDebug)
        {
            LogPrint("leveldb", "%s : activeBatch == false (assert-3)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-3)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }

    leveldb::Status status = pdb->Write(leveldb::WriteOptions(), activeBatch);
    
    delete activeBatch;
    
    activeBatch = NULL;
    
    if (!status.ok())
    {
        if (fDebug)
        {
            LogPrint("leveldb", "%s : LevelDB batch commit failure: %s\n", __FUNCTION__, status.ToString());
        }

        return false;
    }
    
    return true;
}


class CBatchScanner : public leveldb::WriteBatch::Handler
{
    public:

        std::string needle;
    
        bool *deleted;
    
        std::string *foundValue;
    
        bool foundEntry;

        CBatchScanner() : foundEntry(false) {}

        virtual void Put(const leveldb::Slice& key, const leveldb::Slice& value)
        {
            if (key.ToString() == needle)
            {
                foundEntry = true;
                *deleted = false;
                *foundValue = value.ToString();
            }
        }

        virtual void Delete(const leveldb::Slice& key)
        {
            if (key.ToString() == needle)
            {
                foundEntry = true;
                *deleted = true;
            }
        }
};


// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
bool CTxDB::ScanBatch(const CDataStream &key, string *value, bool *deleted) const
{
    if (activeBatch == 0)
    {
        if (fDebug)
        {
            LogPrint("leveldb", "%s : activeBatch == 0 (assert-4)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-4)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }
    
    *deleted = false;
    
    CBatchScanner scanner;
    
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    
    leveldb::Status status = activeBatch->Iterate(&scanner);
    
    if (!status.ok())
    {
        throw runtime_error(status.ToString());
    }
    
    return scanner.foundEntry;
}

bool CTxDB::WriteAddrIndex(uint160 addrHash, uint256 txHash)
{
    std::vector<uint256> txHashes;
    
    if(!ReadAddrIndex(addrHash, txHashes))
    {
	    txHashes.push_back(txHash);

        return Write(make_pair(string("adr"), addrHash), txHashes);
    }
    else
    {
        if(std::find(txHashes.begin(), txHashes.end(), txHash) == txHashes.end()) 
        {
                txHashes.push_back(txHash);

                return Write(make_pair(string("adr"), addrHash), txHashes);
        }
        else
        {
            return true; // already have this tx hash
        }
    }
}


bool CTxDB::ReadAddrIndex(uint160 addrHash, std::vector<uint256>& txHashes)
{
    return Read(make_pair(string("adr"), addrHash), txHashes);
}


bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex& txindex)
{
    txindex.SetNull();
    
    return Read(make_pair(string("tx"), hash), txindex);
}


bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
    return Write(make_pair(string("tx"), hash), txindex);
}


bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    // Add to tx index
    uint256 hash = tx.GetHash();
    
    CTxIndex txindex(pos, tx.vout.size());
    
    return Write(make_pair(string("tx"), hash), txindex);
}


bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}


bool CTxDB::ContainsTx(uint256 hash)
{
    return Exists(make_pair(string("tx"), hash));
}


bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
    tx.SetNull();

    if (!ReadTxIndex(hash, txindex))
    {
        return false;
    }
    
    return (tx.ReadFromDisk(txindex.pos));
}


bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
    CTxIndex txindex;

    return ReadDiskTx(hash, tx, txindex);
}


bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}


bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    
    return ReadDiskTx(outpoint.hash, tx, txindex);
}


bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}


bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}


bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}


bool CTxDB::ReadBestInvalidTrust(CBigNum& bnBestInvalidTrust)
{
    return Read(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}


bool CTxDB::WriteBestInvalidTrust(CBigNum bnBestInvalidTrust)
{
    return Write(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}


static CBlockIndex *InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
    {
        return NULL;
    }

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);

    if (mi != mapBlockIndex.end())
    {
        return (*mi).second;
    }

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    
    if (!pindexNew)
    {
        throw runtime_error("CBlockIndex *InsertBlockIndex -- new CBlockIndex failed");
    }
    
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}


bool CTxDB::LoadBlockIndex()
{
    if (mapBlockIndex.size() > 0)
    {
        // Already loaded once in this session. It can happen during migration
        // from BDB.
        return true;
    }

    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into mapBlockIndex.
    leveldb::Iterator *iterator = pdb->NewIterator(leveldb::ReadOptions());
    
    // Seek to start key.
    CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
    ssStartKey << make_pair(string("blockindex"), uint256(0));
    iterator->Seek(ssStartKey.str());
    
    // Now read each entry.
    while (iterator->Valid())
    {
        boost::this_thread::interruption_point();
        
        // Unpack keys and values.
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);

        ssKey.write(iterator->key().data(), iterator->key().size());

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);

        ssValue.write(iterator->value().data(), iterator->value().size());

        string strType;

        ssKey >> strType;
        
        // Did we reach the end of the data to read?
        if (strType != "blockindex")
        {
            break;
        }
        
        CDiskBlockIndex diskindex;
        ssValue >> diskindex;

        uint256 blockHash = diskindex.GetBlockHash();

        // Construct block index object
        CBlockIndex* pindexNew          = InsertBlockIndex(blockHash);
        pindexNew->pprev                = InsertBlockIndex(diskindex.hashPrev);
        pindexNew->pnext                = InsertBlockIndex(diskindex.hashNext);
        pindexNew->nFile                = diskindex.nFile;
        pindexNew->nBlockPos            = diskindex.nBlockPos;
        pindexNew->nHeight              = diskindex.nHeight;
#ifndef LOWMEM
        pindexNew->nPOWMint             = diskindex.nPOWMint;
        pindexNew->nMoneySupply         = diskindex.nMoneySupply;
        pindexNew->nPOSMint             = diskindex.nPOSMint;
#endif
        pindexNew->nFlags               = diskindex.nFlags;
        pindexNew->nStakeModifier       = diskindex.nStakeModifier;
#ifndef LOWMEM
        pindexNew->bnStakeModifierV2    = diskindex.bnStakeModifierV2;
#endif
        pindexNew->prevoutStake         = diskindex.prevoutStake;
        pindexNew->nStakeTime           = diskindex.nStakeTime;
        pindexNew->hashProof            = diskindex.hashProof;
        pindexNew->nVersion             = diskindex.nVersion;
        pindexNew->hashMerkleRoot       = diskindex.hashMerkleRoot;
        pindexNew->nTime                = diskindex.nTime;
        pindexNew->nBits                = diskindex.nBits;
        pindexNew->nNonce               = diskindex.nNonce;

        // Watch for genesis block
        if (pindexGenesisBlock == NULL && blockHash == Params().HashGenesisBlock())
        {
            pindexGenesisBlock = pindexNew;
        }

        if (!pindexNew->CheckIndex())
        {
            delete iterator;
        
            return error("%s : CheckIndex failed at %d", __FUNCTION__, pindexNew->nHeight);
        }

        // NovaCoin: build setStakeSeen
        if (pindexNew->IsProofOfStake())
        {
            setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
        }

        iterator->Next();
    }

    delete iterator;

    boost::this_thread::interruption_point();

    // Calculate nChainTrust
    vector<pair<int, CBlockIndex*> > vSortedByHeight;

    vSortedByHeight.reserve(mapBlockIndex.size());

    for(const PAIRTYPE(uint256, CBlockIndex*)& item: mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;

        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    
    sort(vSortedByHeight.begin(), vSortedByHeight.end());

    for(const PAIRTYPE(int, CBlockIndex*)& item: vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;

        pindex->nChainTrust = (pindex->pprev ? pindex->pprev->nChainTrust : 0) + pindex->GetBlockTrust();
    }

    // Load hashBestChain pointer to end of best chain
    if (!ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == NULL)
        {
            return true;
        }

        return error("%s : hashBestChain not loaded", __FUNCTION__);
    }

    if (!mapBlockIndex.count(hashBestChain))
    {
        return error("%s : hashBestChain not found in the block index", __FUNCTION__);
    }
    
    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->nHeight;
    nBestChainTrust = pindexBest->nChainTrust;

    if (fDebug)
    {
        LogPrint("leveldb", "%s : hashBestChain=%s  height=%d  trust=%s  date=%s\n", __FUNCTION__, hashBestChain.ToString(), nBestHeight, CBigNum(nBestChainTrust).ToString(), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()));
    }

    // Load bnBestInvalidTrust, OK if it doesn't exist
    CBigNum bnBestInvalidTrust;
    
    ReadBestInvalidTrust(bnBestInvalidTrust);
    
    nBestInvalidTrust = bnBestInvalidTrust.getuint256();

    // Verify blocks in the best chain
    int nCheckLevel = GetArg("-checklevel", 1);
    int nCheckDepth = GetArg( "-checkblocks", 500);
    
    if (nCheckDepth == 0)
    {
        nCheckDepth = 1000000000; // suffices until the year 19000
    }
    
    if (nCheckDepth > nBestHeight)
    {
        nCheckDepth = nBestHeight;
    }
    
    if (fDebug)
    {
        LogPrint("leveldb", "%s : Verifying last %i blocks at level %i\n", __FUNCTION__, nCheckDepth, nCheckLevel);
    }

    CBlockIndex* pindexFork = NULL;
    
    map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
    
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        
        if (pindex->nHeight < nBestHeight-nCheckDepth)
        {
            break; 
        }
       
        CBlock block;

        if (!block.ReadFromDisk(pindex))
        {
            return error("%s : block.ReadFromDisk failed", __FUNCTION__);
        }
        
        // check level 1: verify block validity
        // check level 7: verify block signature too
        if (nCheckLevel>0 && !block.CheckBlock(true, true, (nCheckLevel>6)))
        {
            if (fDebug)
            {
                LogPrint("leveldb", "%s : *** found bad block at %d, hash=%s\n", __FUNCTION__, pindex->nHeight, pindex->GetBlockHash().ToString());
            }

            pindexFork = pindex->pprev;
        }
        
        // check level 2: verify transaction index validity
        if (nCheckLevel>1)
        {
            pair<unsigned int, unsigned int> pos = make_pair(pindex->nFile, pindex->nBlockPos);
            
            mapBlockPos[pos] = pindex;
            
            for(const CTransaction &tx: block.vtx)
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                
                if (ReadTxIndex(hashTx, txindex))
                {
                    // check level 3: checker transaction hashes
                    if (nCheckLevel>2 || pindex->nFile != txindex.pos.nFile || pindex->nBlockPos != txindex.pos.nBlockPos)
                    {
                        // either an error or a duplicate transaction
                        CTransaction txFound;

                        if (!txFound.ReadFromDisk(txindex.pos))
                        {
                            if (fDebug)
                            {
                                LogPrint("leveldb", "%s : *** cannot read mislocated transaction %s\n", __FUNCTION__, hashTx.ToString());
                            }

                            pindexFork = pindex->pprev;
                        }
                        else
                        {
                            if (txFound.GetHash() != hashTx) // not a duplicate tx
                            {
                                if (fDebug)
                                {
                                    LogPrint("leveldb", "%s : *** invalid tx position for %s\n", __FUNCTION__, hashTx.ToString());
                                }

                                pindexFork = pindex->pprev;
                            }
                        }
                    }

                    // check level 4: check whether spent txouts were spent within the main chain
                    unsigned int nOutput = 0;
                    
                    if (nCheckLevel>3)
                    {
                        for(const CDiskTxPos &txpos: txindex.vSpent)
                        {
                            if (!txpos.IsNull())
                            {
                                pair<unsigned int, unsigned int> posFind = make_pair(txpos.nFile, txpos.nBlockPos);
                                
                                if (!mapBlockPos.count(posFind))
                                {
                                    if (fDebug)
                                    {
                                        LogPrint("leveldb", "%s : *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", __FUNCTION__, pindex->nHeight, pindex->GetBlockHash().ToString(), hashTx.ToString());
                                    }

                                    pindexFork = pindex->pprev;
                                }

                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                if (nCheckLevel>5)
                                {
                                    CTransaction txSpend;
                                    
                                    if (!txSpend.ReadFromDisk(txpos))
                                    {
                                        if (fDebug)
                                        {
                                            LogPrint("leveldb", "%s : *** cannot read spending transaction of %s:%i from disk\n", __FUNCTION__, hashTx.ToString(), nOutput);
                                        }

                                        pindexFork = pindex->pprev;
                                    }
                                    else if (!txSpend.CheckTransaction())
                                    {
                                        if (fDebug)
                                        {
                                            LogPrint("leveldb", "%s : *** spending transaction of %s:%i is invalid\n", __FUNCTION__, hashTx.ToString(), nOutput);
                                        }

                                        pindexFork = pindex->pprev;
                                    }
                                    else
                                    {
                                        bool fFound = false;
                                        
                                        for(const CTxIn &txin: txSpend.vin)
                                        {
                                            if (txin.prevout.hash == hashTx && txin.prevout.n == nOutput)
                                            {
                                                fFound = true;
                                            }
                                        }
                                        
                                        if (!fFound)
                                        {
                                            if (fDebug)
                                            {
                                                LogPrint("leveldb", "%s : *** spending transaction of %s:%i does not spend it\n", __FUNCTION__, hashTx.ToString(), nOutput);
                                            }

                                            pindexFork = pindex->pprev;
                                        }
                                    }
                                }
                            }

                            nOutput++;
                        }
                    }
                }

                // check level 5: check whether all prevouts are marked spent
                if (nCheckLevel>4)
                {
                     for(const CTxIn &txin: tx.vin)
                     {
                        CTxIndex txindex;

                        if (ReadTxIndex(txin.prevout.hash, txindex))
                        {
                            if (txindex.vSpent.size()-1 < txin.prevout.n || txindex.vSpent[txin.prevout.n].IsNull())
                            {
                                LogPrint("leveldb", "%s : *** found unspent prevout %s:%i in %s\n", __FUNCTION__, txin.prevout.hash.ToString(), txin.prevout.n, hashTx.ToString());
                                
                                pindexFork = pindex->pprev;
                            }
                        }
                     }
                }
            }
        }
    }

    if (pindexFork)
    {
        boost::this_thread::interruption_point();
        
        // Reorg back to the fork
        if (fDebug)
        {
            LogPrint("leveldb", "%s : *** moving best chain pointer back to block %d\n", __FUNCTION__, pindexFork->nHeight);
        }

        CBlock block;
        
        if (!block.ReadFromDisk(pindexFork))
        {
            return error("%s : block.ReadFromDisk failed", __FUNCTION__);
        }
        
        CTxDB txdb;

        block.SetBestChain(txdb, pindexFork);
    }

    return true;
}
