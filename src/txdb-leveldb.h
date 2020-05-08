// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Authored by Google, Inc. Learn more: http://code.google.com/p/leveldb/
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#ifndef BITCOIN_LEVELDB_H
#define BITCOIN_LEVELDB_H

#include "main.h"

#include <map>
#include <string>
#include <vector>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

// Class that provides access to a LevelDB. Note that this class is frequently
// instantiated on the stack and then destroyed again, so instantiation has to
// be very cheap. Unfortunately that means, a CTxDB instance is actually just a
// wrapper around some global state.
//
// A LevelDB is a key/value store that is optimized for fast usage on hard
// disks. It prefers long read/writes to seeks and is based on a series of
// sorted key/value mapping files that are stacked on top of each other, with
// newer files overriding older files. A background thread compacts them
// together when too many files stack up.
//

class CTxDB
{
    public:

        CTxDB(const char* pszMode="r+");
        
        ~CTxDB()
        {
            // Note that this is not the same as Close() because it deletes only
            // data scoped to this TxDB object.
            delete activeBatch;
        }

        // Destroys the underlying shared global state accessed by this TxDB.
        void Close();

    private:

        leveldb::DB *pdb;  // Points to the global instance.

        // A batch stores up writes and deletes for atomic application. When this
        // field is non-NULL, writes/deletes go there instead of directly to disk.
        leveldb::WriteBatch *activeBatch;
        leveldb::Options options;

        bool fReadOnly;
        
        int nVersion;

    protected:

        // Returns true and sets (value,false) if activeBatch contains the given key
        // or leaves value alone and sets deleted = true if activeBatch contains a
        // delete for it.
        bool ScanBatch(const CDataStream &key, std::string *value, bool *deleted) const;

        template<typename K, typename T> bool Read(const K& key, T& value)
        {
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            ssKey.reserve(1000);
            ssKey << key;
            std::string strValue;

            bool readFromDb = true;

            if (activeBatch)
            {
                // First we must search for it in the currently pending set of
                // changes to the db. If not found in the batch, go on to read disk.
                bool deleted = false;

                readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
                
                if (deleted)
                {
                    return false;
                }
            }

            if (readFromDb)
            {
                leveldb::Status status = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
                
                if (!status.ok())
                {
                    if (status.IsNotFound())
                    {
                        return false;
                    }

                    if (fDebug)
                    {
                        // Some unexpected error.
                        LogPrint("leveldb", "%s : ERROR - LevelDB read failure: %s\n", __FUNCTION__, status.ToString());
                    }

                    return false;
                }
            }

            // Unserialize value
            try
            {    
                CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
                ssValue >> value;
            }
            catch (std::exception &e)
            {
                return false;
            }

            return true;
        }

        template<typename K, typename T> bool Write(const K& key, const T& value)
        {
            if (fReadOnly == true)
            {
                if (fDebug)
                {
                    LogPrint("leveldb", "%s : ERROR - fReadOnly = true Write called on database in read-only mode \n", __FUNCTION__);
                }

                return false;
            }

            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            ssKey.reserve(1000);
            ssKey << key;

            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            ssValue.reserve(10000);
            ssValue << value;

            if (activeBatch)
            {
                activeBatch->Put(ssKey.str(), ssValue.str());
                
                return true;
            }

            leveldb::Status status = pdb->Put(leveldb::WriteOptions(), ssKey.str(), ssValue.str());
            
            if (!status.ok())
            {
                if (fDebug)
                {
                    LogPrint("leveldb", "%s : ERROR - LevelDB write failure: %s \n", __FUNCTION__, status.ToString());
                }

                return false;
            }
            
            return true;
        }

        template<typename K> bool Erase(const K& key)
        {
            if (!pdb)
            {
                return false;
            }

            if (fReadOnly == true)
            {
                if (fDebug)
                {
                    LogPrint("leveldb", "%s : ERROR - fReadOnly = true Erase called on database in read-only mode \n", __FUNCTION__);
                }

                return false;
            }

            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            ssKey.reserve(1000);
            ssKey << key;

            if (activeBatch)
            {
                activeBatch->Delete(ssKey.str());

                return true;
            }

            leveldb::Status status = pdb->Delete(leveldb::WriteOptions(), ssKey.str());
            
            return (status.ok()
                    || status.IsNotFound());
        }

        template<typename K> bool Exists(const K& key)
        {
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            ssKey.reserve(1000);
            ssKey << key;
            std::string unused;

            if (activeBatch)
            {
                bool deleted;

                if (ScanBatch(ssKey, &unused, &deleted) && !deleted)
                {
                    return true;
                }
            }


            leveldb::Status status = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);

            return status.IsNotFound() == false;
        }


    public:

        bool TxnBegin();
        bool TxnCommit();
        bool TxnAbort()

        // Global Namespace Start
        {
            delete activeBatch;

            activeBatch = NULL;

            return true;
        }
        // Global Namespace End

        bool ReadVersion(int& nVersion)
        {
            nVersion = 0;

            return Read(std::string("version"), nVersion);
        }

        bool WriteVersion(int nVersion)
        {
            return Write(std::string("version"), nVersion);
        }

        bool ReadAddrIndex(uint160 addrHash, std::vector<uint256>& txHashes);
        bool WriteAddrIndex(uint160 addrHash, uint256 txHash);
        
        bool ReadTxIndex(uint256 hash, CTxIndex& txindex);
        bool UpdateTxIndex(uint256 hash, const CTxIndex& txindex);
        bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
        bool EraseTxIndex(const CTransaction& tx);
        bool ContainsTx(uint256 hash);
        
        bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
        bool ReadDiskTx(uint256 hash, CTransaction& tx);
        bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
        bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
        
        bool WriteBlockIndex(const CDiskBlockIndex& blockindex);

        bool ReadHashBestChain(uint256& hashBestChain);
        bool WriteHashBestChain(uint256 hashBestChain);

        bool ReadBestInvalidTrust(CBigNum& bnBestInvalidTrust);
        bool WriteBestInvalidTrust(CBigNum bnBestInvalidTrust);

        bool LoadBlockIndex();

    private:

        bool LoadBlockIndexGuts();
};


#endif // BITCOIN_DB_H
