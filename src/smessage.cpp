// Copyright (c) 2014-2015 The ShadowCoin developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


/*
Notes:
    Running with -debug could leave to and from address hashes and public keys in the log.


    parameters:
        -nosmsg             Disable secure messaging (fNoSmsg)
        -debugsmsg          Show extra debug messages (fDebugSmsg)
        -smsgscanchain      Scan the block chain for public key addresses on startup


    Wallet Locked
        A copy of each incoming message is stored in bucket files ending in _wl.dat
        wl (wallet locked) bucket files are deleted if they expire, like normal buckets
        When the wallet is unlocked all the messages in wl files are scanned.


    Address Whitelist
        Owned Addresses are stored in smsgAddresses vector
        Saved to smsg.ini
        Modify options using the smsglocalkeys rpc command or edit the smsg.ini file (with client closed)
    
    
    TODO:
        For buckets older than current, only need to store no. messages and hash in memory

*/


#include "smessage.h"

#include <stdint.h>
#include <time.h>
#include <map>
#include <stdexcept>
#include <sstream>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/predicate.hpp>


#include "base58.h"
#include "db.h"
#include "init.h" // pwalletMain
#include "txdb.h"
#include "sync.h"
#include "ecwrapper.h"

#include "lz4/lz4.c"

#include "xxhash/xxhash.h"
#include "xxhash/xxhash.c"


boost::thread_group threadGroupSmsg;

boost::signals2::signal<void (SecMsgStored& inboxHdr)>  NotifySecMsgInboxChanged;
boost::signals2::signal<void (SecMsgStored& outboxHdr)> NotifySecMsgOutboxChanged;
boost::signals2::signal<void ()> NotifySecMsgWalletUnlocked;

bool fSecMsgEnabled = false;

std::map<int64_t, SecMsgBucket> smsgBuckets;
std::vector<SecMsgAddress>      smsgAddresses;

SecMsgOptions                   smsgOptions;

CCriticalSection cs_smsg;
CCriticalSection cs_smsgDB;
CCriticalSection cs_smsgThreads;

leveldb::DB *smsgDB = NULL;

namespace fs = boost::filesystem;


bool SecMsgCrypter::SetKey(const std::vector<uint8_t>& vchNewKey, uint8_t* chNewIV)
{
    if (vchNewKey.size() < sizeof(chKey))
    {
        return false;
    }

    return SetKey(&vchNewKey[0], chNewIV);
}


bool SecMsgCrypter::SetKey(const uint8_t* chNewKey, uint8_t* chNewIV)
{
    // -- for EVP_aes_256_cbc() key must be 256 bit, iv must be 128 bit.
    memcpy(&chKey[0], chNewKey, sizeof(chKey));
    memcpy(chIV, chNewIV, sizeof(chIV));

    fKeySet = true;
    
    return true;
}


bool SecMsgCrypter::Encrypt(uint8_t* chPlaintext, uint32_t nPlain, std::vector<uint8_t> &vchCiphertext)
{
    if (!fKeySet)
    {
        return false;
    }

    // -- max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE - 1 bytes
    int nLen = nPlain;
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    vchCiphertext = std::vector<uint8_t> (nCLen);
    bool fOk = true;

#if OPENSSL_VERSION_NUMBER < 0x10100000L 
// OPENSSL 1.0

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if (fOk)
    {
        fOk = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, &chKey[0], &chIV[0]);
    }

    if (fOk)
    {
        fOk = EVP_EncryptUpdate(&ctx, &vchCiphertext[0], &nCLen, chPlaintext, nLen);
    }

    if(fOk)
    {
        fOk = EVP_EncryptFinal_ex(&ctx, (&vchCiphertext[0])+nCLen, &nFLen);
    }

#else
// OPENSSL 1.1+

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    if (fOk)
    {
        fOk = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &chKey[0], &chIV[0]);
    }

    if (fOk)
    {
        fOk = EVP_EncryptUpdate(ctx, &vchCiphertext[0], &nCLen, chPlaintext, nLen);
    }

    if(fOk)
    {
        fOk = EVP_EncryptFinal_ex(ctx, (&vchCiphertext[0])+nCLen, &nFLen);
    }

#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    EVP_CIPHER_CTX_cleanup(&ctx);

#else
// OPENSSL 1.1+

    EVP_CIPHER_CTX_cleanup(ctx);

    EVP_CIPHER_CTX_free(ctx);

#endif

    if (!fOk)
    {
        return false;
    }

    vchCiphertext.resize(nCLen + nFLen);

    return true;
}


bool SecMsgCrypter::Decrypt(uint8_t* chCiphertext, uint32_t nCipher, std::vector<uint8_t>& vchPlaintext)
{
    if (!fKeySet)
    {
        return false;
    }

    // plaintext will always be equal to or lesser than length of ciphertext
    int nPLen = nCipher, nFLen = 0;

    vchPlaintext.resize(nCipher);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);

    if (fOk)
    {
        fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, &chKey[0], &chIV[0]);
    }

    if (fOk)
    {
        fOk = EVP_DecryptUpdate(&ctx, &vchPlaintext[0], &nPLen, &chCiphertext[0], nCipher);
    }

    if (fOk)
    {
        fOk = EVP_DecryptFinal_ex(&ctx, (&vchPlaintext[0])+nPLen, &nFLen);
    }
    
    EVP_CIPHER_CTX_cleanup(&ctx);

#else
// OpenSSL 1.1

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    bool fOk = true;

    EVP_CIPHER_CTX_init(ctx);
    
    if (fOk)
    {
        fOk = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &chKey[0], &chIV[0]);
    }

    if(fOk)
    {
        fOk = EVP_DecryptUpdate(ctx, &vchPlaintext[0], &nPLen, &chCiphertext[0], nCipher);
    }

    if(fOk)
    {
        fOk = EVP_DecryptFinal_ex(ctx, (&vchPlaintext[0])+nPLen, &nFLen);
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

#endif

    if (!fOk)
    {
        return false;
    }

    vchPlaintext.resize(nPLen + nFLen);

    return true;
}


void SecMsgBucket::hashBucket()
{
    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - Debug messages enabled \n", __FUNCTION__);
    }

    timeChanged = GetTime();
    
    std::set<SecMsgToken>::iterator it;
    
    void* state = XXH32_init(1);
    
    for (it = setTokens.begin(); it != setTokens.end(); ++it)
    {
        XXH32_update(state, it->sample, 8);
    }
    
    hash = XXH32_digest(state);

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - Hashed %u messages, hash %u \n", __FUNCTION__, setTokens.size(), hash);
    }
}


bool SecMsgDB::Open(const char* pszMode)
{
    if (smsgDB)
    {
        pdb = smsgDB;

        return true;
    }

    bool fCreate = strchr(pszMode, 'c');

    fs::path fullpath = GetDataDir(true) / "smsgDB";

    if (!fCreate && (!fs::exists(fullpath)
        || !fs::is_directory(fullpath)))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - DB does not exist. \n", __FUNCTION__);
        }

        return false;
    }

    leveldb::Options options;

    options.create_if_missing = fCreate;

    leveldb::Status s = leveldb::DB::Open(options, fullpath.string(), &smsgDB);

    if (!s.ok())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Opening db: %s. \n", __FUNCTION__, s.ToString().c_str());
        }

        return false;
    }

    pdb = smsgDB;

    return true;
}


class SecMsgBatchScanner : public leveldb::WriteBatch::Handler
{
    public:

        std::string needle;
    
        bool* deleted;
    
        std::string* foundValue;
    
        bool foundEntry;

        SecMsgBatchScanner() : foundEntry(false) {}

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
bool SecMsgDB::ScanBatch(const CDataStream& key, std::string* value, bool* deleted) const
{
    if (!activeBatch)
    {
        return false;
    }

    *deleted = false;
    
    SecMsgBatchScanner scanner;
    
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    
    leveldb::Status s = activeBatch->Iterate(&scanner);
    
    if (!s.ok())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - ScanBatch error: %s \n", __FUNCTION__, s.ToString().c_str());
        }

        return false;
    }

    return scanner.foundEntry;
}


bool SecMsgDB::TxnBegin()
{
    if (activeBatch)
    {
        return true;
    }

    activeBatch = new leveldb::WriteBatch();
    
    return true;
}


bool SecMsgDB::TxnCommit()
{
    if (!activeBatch)
    {
        return false;
    }

    leveldb::WriteOptions writeOptions;
    
    writeOptions.sync = true;
    
    leveldb::Status status = pdb->Write(writeOptions, activeBatch);
    
    delete activeBatch;
    
    activeBatch = NULL;

    if (!status.ok())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Batch commit failure: %s \n", __FUNCTION__, status.ToString().c_str());
        }

        return false;
    }

    return true;
}


bool SecMsgDB::TxnAbort()
{
    delete activeBatch;
   
    activeBatch = NULL;
   
    return true;
}


bool SecMsgDB::ReadPK(CKeyID& addr, CPubKey& pubkey)
{
    if (!pdb)
    {
        return false;
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    
    ssKey.reserve(sizeof(addr) + 2);
    ssKey << 'p';
    ssKey << 'k';
    ssKey << addr;

    std::string strValue;

    bool readFromDb = true;
    
    if (activeBatch)
    {
        // -- check activeBatch first
        bool deleted = false;
        
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        
        if (deleted)
        {
            return false;
        }
    }

    if (readFromDb)
    {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        
        if (!s.ok())
        {
            if (s.IsNotFound())
            {
                return false;
            }

            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - LevelDB read failure: %s \n", __FUNCTION__, s.ToString().c_str());
            }
            
            return false;
        }
    }

    try
    {
        CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
        ssValue >> pubkey;
    }
    catch (std::exception& e)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Unserialize threw: %s. \n", __FUNCTION__, e.what());
        }

        return false;
    }

    return true;
}


bool SecMsgDB::WritePK(CKeyID& addr, CPubKey& pubkey)
{
    if (!pdb)
    {
        return false;
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    
    ssKey.reserve(sizeof(addr) + 2);
    ssKey << 'p';
    ssKey << 'k';
    ssKey << addr;
    
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    
    ssValue.reserve(sizeof(pubkey));
    ssValue << pubkey;

    if (activeBatch)
    {
        activeBatch->Put(ssKey.str(), ssValue.str());
        
        return true;
    }

    leveldb::WriteOptions writeOptions;
    
    writeOptions.sync = true;
    
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    
    if (!s.ok())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Write failure: %s \n", __FUNCTION__, s.ToString().c_str());
        }

        return false;
    }

    return true;
}


bool SecMsgDB::ExistsPK(CKeyID& addr)
{
    if (!pdb)
    {
        return false;
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    
    ssKey.reserve(sizeof(addr)+2);
    ssKey << 'p';
    ssKey << 'k';
    ssKey << addr;
    
    std::string unused;

    if (activeBatch)
    {
        bool deleted;

        if (ScanBatch(ssKey, &unused, &deleted) && !deleted)
        {
            return true;
        }
    }

    leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
    
    return s.IsNotFound() == false;
}


bool SecMsgDB::NextSmesg(leveldb::Iterator* it, std::string& prefix, uint8_t* chKey, SecMsgStored& smsgStored)
{
    if (!pdb)
    {
        return false;
    }

    if (!it->Valid())
    {
        // first run
        it->Seek(prefix);
    } 
    else
    {
        it->Next();
    }

    if (!(it->Valid()
        && it->key().size() == 18
        && memcmp(it->key().data(), prefix.data(), 2) == 0))
    {
        return false;
    }

    memcpy(chKey, it->key().data(), 18);

    try
    {
        CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
    
        ssValue >> smsgStored;
    }
    catch (std::exception& e)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Unserialize threw: %s. \n", __FUNCTION__, e.what());
        }

        return false;
    }

    return true;
}


bool SecMsgDB::NextSmesgKey(leveldb::Iterator* it, std::string& prefix, uint8_t* chKey)
{
    if (!pdb)
    {
        return false;
    }

    if (!it->Valid())
    {
        // first run
        it->Seek(prefix);
    } 
    else
    {
        it->Next();
    }

    if (!(it->Valid()
        && it->key().size() == 18
        && memcmp(it->key().data(), prefix.data(), 2) == 0))
    {
        return false;
    }

    memcpy(chKey, it->key().data(), 18);

    return true;
}


bool SecMsgDB::ReadSmesg(uint8_t* chKey, SecMsgStored& smsgStored)
{
    if (!pdb)
    {
        return false;
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);

    ssKey.write((const char*)chKey, 18);

    std::string strValue;

    bool readFromDb = true;

    if (activeBatch)
    {
        // -- check activeBatch first
        bool deleted = false;
        
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        
        if (deleted)
        {
            return false;
        }
    }

    if (readFromDb)
    {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);

        if (!s.ok())
        {
            if (s.IsNotFound())
            {
                return false;
            }

            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - LevelDB read failure: %s \n", __FUNCTION__, s.ToString().c_str());
            }

            return false;
        }
    }

    try
    {
        CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
        
        ssValue >> smsgStored;
    }
    catch (std::exception& e)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Unserialize threw: %s. \n", __FUNCTION__, e.what());
        }

        return false;
    }

    return true;
}


bool SecMsgDB::WriteSmesg(uint8_t* chKey, SecMsgStored& smsgStored)
{
    if (!pdb)
    {
        return false;
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);

    ssKey.write((const char*)chKey, 18);

    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssValue << smsgStored;

    if (activeBatch)
    {
        activeBatch->Put(ssKey.str(), ssValue.str());

        return true;
    }

    leveldb::WriteOptions writeOptions;
    
    writeOptions.sync = true;

    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    
    if (!s.ok())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Write failed: %s \n", __FUNCTION__, s.ToString().c_str());
        }

        return false;
    }

    return true;
}


bool SecMsgDB::ExistsSmesg(uint8_t* chKey)
{
    if (!pdb)
    {
        return false;
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    
    ssKey.write((const char*)chKey, 18);
    std::string unused;

    if (activeBatch)
    {
        bool deleted;
        
        if (ScanBatch(ssKey, &unused, &deleted) && !deleted)
        {
            return true;
        }
    }

    leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
    
    return s.IsNotFound() == false;

    return true;
}


bool SecMsgDB::EraseSmesg(uint8_t* chKey)
{
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    
    ssKey.write((const char*)chKey, 18);

    if (activeBatch)
    {
        activeBatch->Delete(ssKey.str());
     
        return true;
    }

    leveldb::WriteOptions writeOptions;
    
    writeOptions.sync = true;
    
    leveldb::Status s = pdb->Delete(writeOptions, ssKey.str());

    if (s.ok()
        || s.IsNotFound())
    {
        return true;
    }
    
    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : ERROR - Erase failed: %s \n", __FUNCTION__, s.ToString().c_str());
    }

    return false;
}


void ThreadSecureMsg()
{
    // -- bucket management thread
    
    uint32_t nLoop = 0;
    
    std::vector<std::pair<int64_t, NodeId> > vTimedOutLocks;
    
    while (fSecMsgEnabled)
    {
        nLoop++;

        int64_t now = GetTime();
        
        if (nLoop % SMSG_THREAD_LOG_GAP == 0)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                // log every SMSG_THREAD_LOG_GAP instance, is useful source of timestamps
                LogPrint("smessage", "%s : ERROR - LogGap: %d \n", __FUNCTION__, now);
            }
        } 
        
        vTimedOutLocks.resize(0);
        
        int64_t cutoffTime = now - SMSG_RETENTION;
        {
            LOCK(cs_smsg);
            
            for (std::map<int64_t, SecMsgBucket>::iterator it(smsgBuckets.begin()); it != smsgBuckets.end(); it++)
            {
                //if (fDebugSmsg)
                //    LogPrint("smessage", "Checking bucket %d", size %u \n", it->first, it->second.setTokens.size());
                
                if (it->first < cutoffTime)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : NOTICE - Removing bucket %d \n", __FUNCTION__, it->first);
                    }

                    std::string fileName = boost::lexical_cast<std::string>(it->first);

                    fs::path fullPath = GetDataDir(true) / "smsgStore" / (fileName + "_01.dat");

                    if (fs::exists(fullPath))
                    {
                        try
                        {
                            fs::remove(fullPath);
                        } 
                        catch (const fs::filesystem_error& ex)
                        {
                            if (fDebug 
                                && fDebugSmsg)
                            {
                                LogPrint("smessage", "%s : ERROR - Removing bucket file %s. \n", __FUNCTION__, ex.what());
                            }
                        }
                    }
                    else
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : ERROR - Path %s does not exist \n", __FUNCTION__, fullPath.string().c_str());
                        }
                    }
                    
                    // -- look for a wl file, it stores incoming messages when wallet is locked
                    fullPath = GetDataDir(true) / "smsgStore" / (fileName + "_01_wl.dat");
                    
                    if (fs::exists(fullPath))
                    {
                        try
                        {
                            fs::remove(fullPath);
                        }
                        catch (const fs::filesystem_error& ex)
                        {
                            if (fDebug 
                                && fDebugSmsg)
                            {
                                LogPrint("smessage", "%s : ERROR - Removing wallet locked file %s. \n", __FUNCTION__, ex.what());
                            }
                        }
                    }

                    smsgBuckets.erase(it);
                }
                else
                {
                    // -- tick down nLockCount, so will eventually expire if peer never sends data
                    if (it->second.nLockCount > 0)
                    {
                        it->second.nLockCount--;

                        // lock timed out
                        if (it->second.nLockCount == 0)
                        {
                            // cs_vNodes
                            vTimedOutLocks.push_back(std::make_pair(it->first, it->second.nLockPeerId)); 
                            
                            it->second.nLockPeerId = 0;
                        } // if (it->second.nLockCount == 0)
                        
                    } // ! if (it->first < cutoffTime)
                }
            }
        } // cs_smsg
        
        for (std::vector<std::pair<int64_t, NodeId> >::iterator it(vTimedOutLocks.begin()); it != vTimedOutLocks.end(); it++)
        {
            NodeId nPeerId = it->second;
            
            int64_t ignoreUntil = GetTime() + SMSG_TIME_IGNORE;

            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Lock on bucket %d for peer %d timed out. \n", __FUNCTION__, it->first, nPeerId);
            }

            // -- look through the nodes for the peer that locked this bucket
            
            // Global Namespace Start
            {
                LOCK(cs_vNodes);

                for(CNode* pnode: vNodes)
                {
                    if (pnode->id != nPeerId)
                    {
                        continue;
                    }

                    LOCK2(pnode->cs_vSend, pnode->smsgData.cs_smsg_net);
                    
                    pnode->smsgData.ignoreUntil = ignoreUntil;
                    
                    // -- alert peer that they are being ignored
                    std::vector<uint8_t> vchData;
                    
                    vchData.resize(8);
                    
                    memcpy(&vchData[0], &ignoreUntil, 8);
                    
                    pnode->PushMessage("smsgIgnore", vchData);

                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : This node will ignore peer %d until %d. \n", __FUNCTION__, nPeerId, ignoreUntil);
                    }
                    
                    break;
                }
            }
            // Global Namespace End cs_vNodes
        }
        
        // check every SMSG_THREAD_DELAY seconds
        MilliSleep(SMSG_THREAD_DELAY * 1000);
    }
}


void ThreadSecureMsgPow()
{
    // -- proof of work thread
    int rv;
    
    std::vector<uint8_t> vchKey;
    
    SecMsgStored smsgStored;

    std::string sPrefix("qm");
    
    uint8_t chKey[18];

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : *** RGP >>> ThreadSecureMsgPow start... Debug 001 \n", __FUNCTION__);
    }

    while (fSecMsgEnabled)
    {
        // -- sleep at end, then fSecMsgEnabled is tested on wake

        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : *** RGP >>> ThreadSecureMsgPow main loop Debug 002 \n", __FUNCTION__);
        }

        SecMsgDB dbOutbox;
        leveldb::Iterator* it;

        // Global Namespace Start
        {
            LOCK(cs_smsgDB);

            if (!dbOutbox.Open("cr+"))
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : *** RGP >>> ThreadSecureMsgPow dbOutbox.Open Debug 003 \n", __FUNCTION__);
                }

                MilliSleep(5);

                continue;
            }

            // -- fifo (smallest key first)
            it = dbOutbox.pdb->NewIterator(leveldb::ReadOptions());
        }
        // Global Namespace End
        // -- break up lock, SecureMsgSetHash will take long

        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : *** RGP >>> ThreadSecureMsgPow main loop Debug 004 \n", __FUNCTION__);
        }

        for (;;)
        {
            // Global Namespace Start
            {
                LOCK(cs_smsgDB);
                
                if (!dbOutbox.NextSmesg(it, sPrefix, chKey, smsgStored))
                {        
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : *** RGP*** ThreadSecureMsgPow No Next Messagee... Debug 001a \n", __FUNCTION__);
                    }
                    
                    break;
                }
            }
            // Global Namespace End

            uint8_t* pHeader = &smsgStored.vchMessage[0];
            uint8_t* pPayload = &smsgStored.vchMessage[SMSG_HDR_LEN];
            
            SecureMessage* psmsg = (SecureMessage*) pHeader;

            // -- do proof of work
            rv = SecureMsgSetHash(pHeader, pPayload, psmsg->nPayload);

            if (rv == 2)
            {
                // leave message in db, if terminated due to shutdow
                break;
            }

            // -- message is removed here, no matter what
            // Global Namespace Start
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : *** RGP*** ThreadSecureMsgPow Erase Message... Debug 002 \n", __FUNCTION__);
                }

                LOCK(cs_smsgDB);
                
                dbOutbox.EraseSmesg(chKey);
            }
            // Global Namespace End

            if (rv != 0)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : Could not get proof of work hash, message removed. \n", __FUNCTION__);
                }

                continue;
            }

            // -- add to message store
            // Global Namespace Start
            {
                LOCK(cs_smsg);
                
                if (SecureMsgStore(pHeader, pPayload, psmsg->nPayload, true) != 0)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : *** RGP*** ThreadSecureMsgPow SecureMsgScanMessage error... Debug 003 \n", __FUNCTION__);
                    }

                    continue;
                }
            }
            // Global Namespace End

            // -- test if message was sent to self
            if (SecureMsgScanMessage(pHeader, pPayload, psmsg->nPayload, true) != 0)
            {
                // message recipient is not this node (or failed)
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : *** RGP*** ThreadSecureMsgPow SecureMsgScanMessage error... Debug 003 \n", __FUNCTION__);
                }
            }

            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : *** RGP*** ThreadSecureMsgPow start... Debug 002 \n", __FUNCTION__);
            }

            MilliSleep(5);

        }

        delete it;

        // -- shutdown thread waits 5 seconds, this should be less
        MilliSleep(2000);
    }
}


int SecureMsgBuildBucketSet()
{
    /*
        Build the bucket set by scanning the files in the smsgStore dir.

        smsgBuckets should be empty
    */

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : \n", __FUNCTION__);
    }

    int64_t  now            = GetTime();
    uint32_t nFiles         = 0;
    uint32_t nMessages      = 0;

    fs::path pathSmsgDir = GetDataDir(true) / "smsgStore";
    fs::directory_iterator itend;

    if (!fs::exists(pathSmsgDir)
        || !fs::is_directory(pathSmsgDir))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Message store directory does not exist. \n", __FUNCTION__);
        }

        // not an error
        return 0; 
    }

    for (fs::directory_iterator itd(pathSmsgDir) ; itd != itend ; ++itd)
    {
        if (!fs::is_regular_file(itd->status()))
        {
            continue;
        }

        std::string fileType = (*itd).path().extension().string();

        if (fileType.compare(".dat") != 0)
        {
            continue;
        }

        std::string fileName = (*itd).path().filename().string();

         if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : NOTICE - Processing file: %s. \n", __FUNCTION__, fileName.c_str());
        }

        nFiles++;

        // TODO files must be split if > 2GB
        // time_noFile.dat
        size_t sep = fileName.find_first_of("_");

        if (sep == std::string::npos)
        {
            continue;
        }

        std::string stime = fileName.substr(0, sep);

        int64_t fileTime = boost::lexical_cast<int64_t>(stime);

        if (fileTime < now - SMSG_RETENTION)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : NOTICE - Dropping file %s, expired. \n", __FUNCTION__, fileName.c_str());
            }

            try
            {
                fs::remove((*itd).path());
            }
            catch (const fs::filesystem_error& ex)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Removing bucket file %s, %s. \n", __FUNCTION__, fileName.c_str(), ex.what());
                }
            }
            
            continue;
        }

        if (boost::algorithm::ends_with(fileName, "_wl.dat"))
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : Skipping wallet locked file: %s.\n", __FUNCTION__, fileName.c_str());
            }

            continue;
        }

        size_t nTokenSetSize = 0;

        SecureMessage smsg;

        // Global Namespace Start
        {
            LOCK(cs_smsg);
            
            std::set<SecMsgToken>& tokenSet = smsgBuckets[fileTime].setTokens;
            
            FILE *fp;

            if (!(fp = fopen((*itd).path().string().c_str(), "rb")))
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : Error opening file: %s \n", __FUNCTION__, strerror(errno));
                }
                
                continue;
            }

            for (;;)
            {
                long int ofs = ftell(fp);
                
                SecMsgToken token;
                
                token.offset = ofs;
                
                errno = 0;

#if __ANDROID__                
                if (fread(&smsg.hash[0], sizeof(uint8_t), 4, fp) != (size_t)SMSG_HDR_LEN)
#else

                if (fread(&smsg.hash[0], sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN)
#endif
                {
                    if (errno != 0)
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : fread header failed: %s \n", __FUNCTION__, strerror(errno));
                        }
                    }
                    else
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : End of file. \n", __FUNCTION__);
                        }
                    }

                    break;
                }

                token.timestamp = smsg.timestamp;

                if (smsg.nPayload < 8)
                {
                    continue;
                }

                if (fread(token.sample, sizeof(uint8_t), 8, fp) != 8)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : fread data failed: %s \n", __FUNCTION__, strerror(errno));
                    }

                    break;
                }

                if (fseek(fp, smsg.nPayload-8, SEEK_CUR) != 0)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : fseek, strerror: %s. \n", __FUNCTION__, strerror(errno));
                    }

                    break;
                }

                tokenSet.insert(token);

                MilliSleep(5);
            }

            fclose(fp);
            
            smsgBuckets[fileTime].hashBucket();
            
            nTokenSetSize = tokenSet.size();

        } // Global Namespace End
        // LOCK(cs_smsg);
        
        nMessages += nTokenSetSize;

        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : Bucket %d contains %u messages. \n", __FUNCTION__, fileTime, nTokenSetSize);
        }
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : Processed %u files, loaded %u buckets containing %u messages. \n", __FUNCTION__, nFiles, smsgBuckets.size(), nMessages);
    }

    return 0;
}


int SecureMsgAddWalletAddresses()
{
    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : SecureMsgAddWalletAddresses() \n", __FUNCTION__);
    }

    std::string sAnonPrefix("ao ");

    uint32_t nAdded = 0;

    for(const PAIRTYPE(CTxDestination, std::string)& entry: pwalletMain->mapAddressBook)
    {
        if (!IsMine(*pwalletMain, entry.first))
        {
            continue;
        }

        // -- skip addresses for anon outputs
        if (entry.second.compare(0, sAnonPrefix.length(), sAnonPrefix) == 0)
        {
            continue;
        }

        // TODO: skip addresses for stealth transactions

        CCoinAddress coinAddress(entry.first);

        if (!coinAddress.IsValid())
        {
            continue;
        }

        std::string address;
        std::string strPublicKey;

        address = coinAddress.ToString();

        bool fExists        = 0;

        for (std::vector<SecMsgAddress>::iterator it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
        {
            if (address != it->sAddress)
            {
                continue;
            }

            fExists = 1;

            break;
        }

        if (fExists)
        {
            continue;
        }

        bool recvEnabled    = 1;
        bool recvAnon       = 1;

        smsgAddresses.push_back(SecMsgAddress(address, recvEnabled, recvAnon));
        nAdded++;
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : Added %u addresses to whitelist. \n", __FUNCTION__, nAdded);
    }

    return 0;
}


int SecureMsgReadIni()
{
    if (!fSecMsgEnabled)
    {
        return false;
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : \n", __FUNCTION__);
    }

    fs::path fullpath = GetDataDir(true) / "smsg.ini";


    FILE *fp;
    errno = 0;
    
    if (!(fp = fopen(fullpath.string().c_str(), "r")))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : Error opening file: %s \n", __FUNCTION__, strerror(errno));
        }

        return 1;
    }

    char cLine[512];
    char *pName, *pValue;

    char cAddress[64];
    int addrRecv, addrRecvAnon;

    while (fgets(cLine, 512, fp))
    {
        cLine[strcspn(cLine, "\n")] = '\0';
        cLine[strcspn(cLine, "\r")] = '\0';
        cLine[511] = '\0'; // for safety

        // -- check that line contains a name value pair and is not a comment, or section header
        if (cLine[0] == '#'
            || cLine[0] == '['
            || strcspn(cLine, "=") < 1)
        {
            continue;
        }

        if (!(pName = strtok(cLine, "="))
            || !(pValue = strtok(NULL, "=")))
        {
            continue;
        }

        if (strcmp(pName, "newAddressRecv") == 0)
        {
            smsgOptions.fNewAddressRecv = (strcmp(pValue, "true") == 0) ? true : false;
        }
        else
        {
            if (strcmp(pName, "newAddressAnon") == 0)
            {
                smsgOptions.fNewAddressAnon = (strcmp(pValue, "true") == 0) ? true : false;
            }
            else
            {
                if (strcmp(pName, "scanIncoming") == 0)
                {
                    smsgOptions.fScanIncoming = (strcmp(pValue, "true") == 0) ? true : false;
                }
                else
                {
                    if (strcmp(pName, "key") == 0)
                    {
                        int rv = sscanf(pValue, "%64[^|]|%d|%d", cAddress, &addrRecv, &addrRecvAnon);
                        
                        if (rv == 3)
                        {
                            smsgAddresses.push_back(SecMsgAddress(std::string(cAddress), addrRecv, addrRecvAnon));
                        }
                        else
                        {   
                            if (fDebug 
                                && fDebugSmsg)
                            {
                                LogPrint("smessage", "Could not parse key line %s, rv %d. \n", pValue, rv);
                            }
                        }
                    }
                    else
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "Unknown setting name: '%s'. \n", pName);
                        }
                    }
                }
            }
        }
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : Loaded %u addresses. \n", __FUNCTION__, smsgAddresses.size());
    }

    fclose(fp);

    return 0;
}


int SecureMsgWriteIni()
{
    if (!fSecMsgEnabled)
    {
        return false;
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : SecureMsgWriteIni() \n", __FUNCTION__);
    }

    fs::path fullpath = GetDataDir(true) / "smsg.ini~";

    FILE *fp;
    errno = 0;
    
    if (!(fp = fopen(fullpath.string().c_str(), "w")))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : Error opening file: %s \n", __FUNCTION__, strerror(errno));
        }

        return 1;
    }

    if (fwrite("[Options]\n", sizeof(char), 10, fp) != 10)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : fwrite error: %s \n", __FUNCTION__, strerror(errno));
        }

        fclose(fp);
        
        return false;
    }

    if (fprintf(fp, "newAddressRecv=%s\n", smsgOptions.fNewAddressRecv ? "true" : "false") < 0
        || fprintf(fp, "newAddressAnon=%s\n", smsgOptions.fNewAddressAnon ? "true" : "false") < 0
        || fprintf(fp, "scanIncoming=%s\n", smsgOptions.fScanIncoming ? "true" : "false") < 0)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : fprintf error: %s \n", __FUNCTION__, strerror(errno));
        }

        fclose(fp);
        
        return false;
    }

    if (fwrite("\n[Keys]\n", sizeof(char), 8, fp) != 8)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : fwrite error: %s \n", __FUNCTION__, strerror(errno));
        }

        fclose(fp);
        
        return false;
    }

    for (std::vector<SecMsgAddress>::iterator it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
    {
        errno = 0;

        if (fprintf(fp, "key=%s|%d|%d\n", it->sAddress.c_str(), it->fReceiveEnabled, it->fReceiveAnon) < 0)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : fprintf error: %s \n", __FUNCTION__, strerror(errno));
            }

            continue;
        }
    }

    fclose(fp);

    try
    {
        fs::path finalpath = GetDataDir(true) / "smsg.ini";
        
        fs::rename(fullpath, finalpath);
    }
    catch (const fs::filesystem_error& ex)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : Error renaming file %s, %s. \n", __FUNCTION__, fullpath.string().c_str(), ex.what());
        }
    }

    return 0;
}


/** called from AppInit2() in init.cpp */
bool SecureMsgStart(bool fDontStart, bool fScanChain)
{
    if (fDontStart)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : Secure messaging not started. \n", __FUNCTION__);
        }

        return false;
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : Secure messaging starting. \n", __FUNCTION__);
    }

    fSecMsgEnabled = true;

    if (SecureMsgReadIni() != 0)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : Failed to read smsg.ini \n", __FUNCTION__);
        }
    }

    if (smsgAddresses.size() < 1)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : No address keys loaded. \n", __FUNCTION__);
        }

        if (SecureMsgAddWalletAddresses() != 0)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : Failed to load addresses from wallet. \n", __FUNCTION__);
            }
        }
    }

    if (fScanChain)
    {
        SecureMsgScanBlockChain();
    }

    if (SecureMsgBuildBucketSet() != 0)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : SecureMsg could not load bucket sets, secure messaging disabled. \n", __FUNCTION__);
        }

        fSecMsgEnabled = false;
    
        return false;
    }
    
    threadGroupSmsg.create_thread(boost::bind(&TraceThread<void (*)()>, "smsg", &ThreadSecureMsg));
    threadGroupSmsg.create_thread(boost::bind(&TraceThread<void (*)()>, "smsg-pow", &ThreadSecureMsgPow));
    
    return true;
}


bool SecureMsgShutdown()
{
    if (!fSecMsgEnabled)
    {
        return false;
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : Stopping secure messaging. \n", __FUNCTION__);
    }

    if (SecureMsgWriteIni() != 0)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : Failed to save smsg.ini \n", __FUNCTION__);
        }
    }

    fSecMsgEnabled = false;
    
    threadGroupSmsg.interrupt_all();
    threadGroupSmsg.join_all();

    if (smsgDB)
    {
        LOCK(cs_smsgDB);
        
        delete smsgDB;
        
        smsgDB = NULL;
    }

    return true;
}


bool SecureMsgEnable()
{
    // -- start secure messaging at runtime
    if (fSecMsgEnabled)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : SecureMsgEnable: secure messaging is already enabled. \n", __FUNCTION__);
        }

        return false;
    }

    // Global Namespace Start
    {
        LOCK(cs_smsg);

        fSecMsgEnabled = true;

        // should be empty already
        smsgAddresses.clear();

        if (SecureMsgReadIni() != 0)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : Failed to read smsg.ini \n", __FUNCTION__);
            }
        }

        if (smsgAddresses.size() < 1)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : No address keys loaded. \n", __FUNCTION__);
            }

            if (SecureMsgAddWalletAddresses() != 0)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : Failed to load addresses from wallet. \n", __FUNCTION__);
                }
            }
        }

        // should be empty already
        smsgBuckets.clear();

        if (SecureMsgBuildBucketSet() != 0)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : SecureMsgEnable: could not load bucket sets, secure messaging disabled. \n", __FUNCTION__);
            }

            fSecMsgEnabled = false;

            return false;
        }

    } 
    // Global Namespace End
    // cs_smsg
    
    // -- start threads
    threadGroupSmsg.create_thread(boost::bind(&TraceThread<void (*)()>, "smsg", &ThreadSecureMsg));
    threadGroupSmsg.create_thread(boost::bind(&TraceThread<void (*)()>, "smsg-pow", &ThreadSecureMsgPow));
    
    /*
    if (!NewThread(ThreadSecureMsg, NULL)
        || !NewThread(ThreadSecureMsgPow, NULL))
    {
        LogPrint("smessage", "%s : SecureMsgEnable could not start threads, secure messaging disabled.\n", __FUNCTION__);
        fSecMsgEnabled = false;
        return false;
    }
    */
    // -- ping each peer, don't know which have messaging enabled
    // Global Namespace Start
    {
        LOCK(cs_vNodes);

        for(CNode* pnode: vNodes)
        {
            pnode->PushMessage("smsgPing");
        
            // Send pong as have missed initial ping sent by peer when it connected
            pnode->PushMessage("smsgPong");
        }
    } // cs_vNodes
    // Global Namespace End

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : Secure messaging enabled. \n", __FUNCTION__);
    }

    return true;
}


bool SecureMsgDisable()
{
    // -- stop secure messaging at runtime
    if (!fSecMsgEnabled)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : SecureMsgDisable: secure messaging is already disabled. \n", __FUNCTION__);
        }

        return false;
    }
    
    // Global Namespace Start
    {
        LOCK(cs_smsg);
        
        fSecMsgEnabled = false;
        
        threadGroupSmsg.interrupt_all();
        threadGroupSmsg.join_all();
        
        // -- clear smsgBuckets
        std::map<int64_t, SecMsgBucket>::iterator it;
        it = smsgBuckets.begin();
        
        for (it = smsgBuckets.begin(); it != smsgBuckets.end(); ++it)
        {
            it->second.setTokens.clear();
        }

        smsgBuckets.clear();
        smsgAddresses.clear();
    }
    // Global Namespace End
    // cs_smsg
    
    // -- tell each smsg enabled peer that this node is disabling
    // Global Namespace Start
    {
        LOCK(cs_vNodes);
        
        for(CNode* pnode: vNodes)
        {
            if (!pnode->smsgData.fEnabled)
            {
                continue;
            }
        
            LOCK2(pnode->cs_vSend, pnode->smsgData.cs_smsg_net);
        
            pnode->PushMessage("smsgDisabled");

            pnode->smsgData.fEnabled = false;
        }
    } 
    // Global Namespace End
    // cs_vNodes


    if (SecureMsgWriteIni() != 0)
    {
        if (fDebug)
        {
            LogPrint("smessage", "%s : Failed to save smsg.ini \n", __FUNCTION__);
        }
    }

    // -- allow time for threads to stop
    MilliSleep(3000); // seconds
    // TODO be certain that threads have stopped

    if (smsgDB)
    {
        LOCK(cs_smsgDB);
        
        delete smsgDB;
        
        smsgDB = NULL;
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : Secure messaging disabled. \n", __FUNCTION__);
    }

    return true;
}


bool SecureMsgReceiveData(CNode* pfrom, std::string strCommand, CDataStream& vRecv)
{
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */

    if (fDebugSmsg)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : NOTICE - %s %s. \n", __FUNCTION__, pfrom->addrName.c_str(), strCommand.c_str());
        }
    }    
    
    if (strCommand == "smsgInv")
    {
        std::vector<uint8_t> vchData;
        vRecv >> vchData;

        if (vchData.size() < 4)
        {
            Misbehaving(pfrom->GetId(), 1);
            
            // not enough data received to be a valid smsgInv
            return false;
        }

        int64_t now = GetTime();
        
        // Global Namespace Start
        {
            LOCK(pfrom->smsgData.cs_smsg_net);
                
            if (now < pfrom->smsgData.ignoreUntil)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Node is ignoring peer %d until %d. \n", __FUNCTION__, pfrom->id, pfrom->smsgData.ignoreUntil);
                }

                return false;
            }
        }
        // Global Namespace End
        
        uint32_t nBuckets       = smsgBuckets.size();
        uint32_t nLocked        = 0;    // no. of locked buckets on this node
        uint32_t nInvBuckets;           // no. of bucket headers sent by peer in smsgInv
        
        memcpy(&nInvBuckets, &vchData[0], 4);
        
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : NOTICE - Remote node sent %d bucket headers, this has %d. \n", __FUNCTION__, nInvBuckets, nBuckets);
        }

        // -- Check no of buckets: +1 for some leeway
        if (nInvBuckets > (SMSG_RETENTION / SMSG_BUCKET_LEN) + 1) 
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Peer sent more bucket headers than possible %u, %u. \n", __FUNCTION__, nInvBuckets, (SMSG_RETENTION / SMSG_BUCKET_LEN));
            }

            Misbehaving(pfrom->GetId(), 1);
            
            return false;
        }

        if (vchData.size() < 4 + nInvBuckets*16)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Remote node did not send enough data. \n", __FUNCTION__);
            }

            Misbehaving(pfrom->GetId(), 1);
            
            return false;
        }

        std::vector<uint8_t> vchDataOut;
        
        // reserve max possible size
        vchDataOut.reserve(4 + 8 * nInvBuckets);
        vchDataOut.resize(4);
        
        uint32_t nShowBuckets = 0;

        uint8_t *p = &vchData[4];

        for (uint32_t i = 0; i < nInvBuckets; ++i)
        {
            int64_t time;
            
            uint32_t ncontent, hash;
            
            memcpy(&time, p, 8);
            memcpy(&ncontent, p+8, 4);
            memcpy(&hash, p+12, 4);

            p += 16;

            // Check time valid:
            if (time < now - SMSG_RETENTION)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Not interested in peer bucket %d, has expired. \n", __FUNCTION__, time);
                }

                if (time < now - SMSG_RETENTION - SMSG_TIME_LEEWAY)
                {
                    Misbehaving(pfrom->GetId(), 1);
                }

                continue;
            }

            if (time > now + SMSG_TIME_LEEWAY)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Not interested in peer bucket %d, in the future. \n", __FUNCTION__, time);
                }

                Misbehaving(pfrom->GetId(), 1);

                continue;
            }

            if (ncontent < 1)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : WARNING - Peer sent empty bucket, ignore %d %u %u. \n", __FUNCTION__, time, ncontent, hash);
                }

                continue;
            }

            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : NOTICE - Peer bucket %d %u %u. \n", __FUNCTION__, time, ncontent, hash);

                LogPrint("smessage", "%s : NOTICE - This bucket %d %u %u. \n", __FUNCTION__, time, smsgBuckets[time].setTokens.size(), smsgBuckets[time].hash);
            }

            // Global Namespace Start
            {
                LOCK(cs_smsg);

                if (smsgBuckets[time].nLockCount > 0)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : OK - Bucket is locked %u, waiting for peer %u to send data. \n", __FUNCTION__, smsgBuckets[time].nLockCount, smsgBuckets[time].nLockPeerId);
                    }

                    nLocked++;
                    
                    continue;
                }

                // -- if this node has more than the peer node, peer node will pull from this
                //    if then peer node has more this node will pull fom peer
                if (smsgBuckets[time].setTokens.size() < ncontent
                    || (smsgBuckets[time].setTokens.size() == ncontent
                    && smsgBuckets[time].hash != hash)) // if same amount in buckets check hash
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : NOTICE - Requesting contents of bucket %d. \n", __FUNCTION__, time);
                    }

                    uint32_t sz = vchDataOut.size();
                    
                    vchDataOut.resize(sz + 8);
                    
                    memcpy(&vchDataOut[sz], &time, 8);

                    nShowBuckets++;
                }
            } 
            // Global Namespace End
            // LOCK(cs_smsg);
        }

        // TODO: should include hash?
        memcpy(&vchDataOut[0], &nShowBuckets, 4);
        
        if (vchDataOut.size() > 4)
        {
            pfrom->PushMessage("smsgShow", vchDataOut);
        }
        else
        {
            if (nLocked < 1) // Don't report buckets as matched if any are locked
            {
                // -- peer has no buckets we want, don't send them again until something changes
                //    peer will still request buckets from this node if needed (< ncontent)
                vchDataOut.resize(8);

                memcpy(&vchDataOut[0], &now, 8);

                pfrom->PushMessage("smsgMatch", vchDataOut);

                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : OK - Sent smsgMatch, %d. \n", __FUNCTION__, now);
                }
            }
        }
    }
    else
    {
        if (strCommand == "smsgShow")
        {
            std::vector<uint8_t> vchData;
            vRecv >> vchData;

            if (vchData.size() < 4)
            {
                return false;
            }

            uint32_t nBuckets;

            memcpy(&nBuckets, &vchData[0], 4);

            if (vchData.size() < 4 + nBuckets * 8)
            {
                return false;
            }

            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : NOTICE - smsgShow peer wants to see content of %u buckets. \n", __FUNCTION__, nBuckets);
            }
            
            std::map<int64_t, SecMsgBucket>::iterator itb;
            std::set<SecMsgToken>::iterator it;
            std::vector<uint8_t> vchDataOut;

            int64_t time;
            uint8_t* pIn = &vchData[4];

            for (uint32_t i = 0; i < nBuckets; ++i, pIn += 8)
            {
                memcpy(&time, pIn, 8);
                
                // Global Namespace Start
                {
                    LOCK(cs_smsg);
                    
                    itb = smsgBuckets.find(time);
                    
                    if (itb == smsgBuckets.end())
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : WARNING - Don't have bucket %d. \n", __FUNCTION__, time);
                        }
                        
                        continue;
                    }

                    std::set<SecMsgToken>& tokenSet = (*itb).second.setTokens;

                    try
                    {
                        vchDataOut.resize(8 + 16 * tokenSet.size());
                    }
                    catch (std::exception& e)
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : ERROR - vchDataOut.resize %u threw: %s. \n", __FUNCTION__, 8 + 16 * tokenSet.size(), e.what());
                        }

                        continue;
                    }

                    memcpy(&vchDataOut[0], &time, 8);

                    uint8_t* p = &vchDataOut[8];

                    for (it = tokenSet.begin(); it != tokenSet.end(); ++it)
                    {
                        memcpy(p, &it->timestamp, 8);
                        memcpy(p+8, &it->sample, 8);

                        p += 16;
                    }
                }
                // Global Namespace End

                pfrom->PushMessage("smsgHave", vchDataOut);
            }
        }
        else
        {
            if (strCommand == "smsgHave")
            {
                // -- peer has these messages in bucket
                std::vector<uint8_t> vchData;
                vRecv >> vchData;

                if (vchData.size() < 8)
                {
                    return false;
                }

                int n = (vchData.size() - 8) / 16;

                int64_t time;

                memcpy(&time, &vchData[0], 8);

                // -- Check time valid:
                int64_t now = GetTime();

                if (time < now - SMSG_RETENTION)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - Not interested in peer bucket %d, has expired. \n", __FUNCTION__, time);
                    }

                    return false;
                }

                if (time > now + SMSG_TIME_LEEWAY)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - Not interested in peer bucket %d, in the future. \n", __FUNCTION__, time);
                    }
                    
                    Misbehaving(pfrom->GetId(), 1);
                    
                    return false;
                }
                
                std::vector<uint8_t> vchDataOut;
                
                // Global Namespace Start
                {
                    LOCK(cs_smsg);
                    
                    if (smsgBuckets[time].nLockCount > 0)
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : WARNING - Bucket %d lock count %u, waiting for message data from peer %u. \n", __FUNCTION__, time, smsgBuckets[time].nLockCount, smsgBuckets[time].nLockPeerId);
                        }

                        return false;
                    }

                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : NOTICE - Sifting through bucket %d. \n", __FUNCTION__, time);
                    }
                    
                    vchDataOut.resize(8);

                    memcpy(&vchDataOut[0], &vchData[0], 8);

                    std::set<SecMsgToken>& tokenSet = smsgBuckets[time].setTokens;
                    std::set<SecMsgToken>::iterator it;

                    SecMsgToken token;

                    uint8_t* p = &vchData[8];

                    for (int i = 0; i < n; ++i)
                    {
                        memcpy(&token.timestamp, p, 8);
                        memcpy(&token.sample, p+8, 8);

                        it = tokenSet.find(token);

                        if (it == tokenSet.end())
                        {
                            int nd = vchDataOut.size();
                            
                            try
                            {
                                vchDataOut.resize(nd + 16);
                            }
                            catch (std::exception& e)
                            {
                                if (fDebug 
                                    && fDebugSmsg)
                                {
                                    LogPrint("smessage", "%s : ERROR - vchDataOut.resize %d threw: %s. \n", __FUNCTION__, nd + 16, e.what());
                                }

                                continue;
                            }

                            memcpy(&vchDataOut[nd], p, 16);
                        }

                        p += 16;
                    }
                }
                // // Global Namespace End
                
                if (vchDataOut.size() > 8)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : OK - Asking peer for %u messages. \n", __FUNCTION__, (vchDataOut.size() - 8) / 16);
                        LogPrint("smessage", "%s : OK - Locking bucket %u for peer %d. \n", __FUNCTION__, time, pfrom->id);
                    }

                    // Global Namespace Start
                    {
                        LOCK(cs_smsg);

                        // lock this bucket for at most 3 * SMSG_THREAD_DELAY seconds, unset when peer sends smsgMsg
                        smsgBuckets[time].nLockCount   = 3;
                        smsgBuckets[time].nLockPeerId  = pfrom->id;
                    }
                    // // Global Namespace End

                    pfrom->PushMessage("smsgWant", vchDataOut);
                }
            }
            else
            {
                if (strCommand == "smsgWant")
                {
                    std::vector<uint8_t> vchData;
                    vRecv >> vchData;

                    if (vchData.size() < 8)
                    {
                        return false;
                    }

                    std::vector<uint8_t> vchOne;
                    std::vector<uint8_t> vchBunch;

                    // nmessages + bucketTime
                    vchBunch.resize(4+8);

                    int n = (vchData.size() - 8) / 16;

                    int64_t time;
                    uint32_t nBunch = 0;

                    memcpy(&time, &vchData[0], 8);
                    
                    std::map<int64_t, SecMsgBucket>::iterator itb;
                    
                    // Global Namespace Start
                    {
                        LOCK(cs_smsg);

                        itb = smsgBuckets.find(time);

                        if (itb == smsgBuckets.end())
                        {
                            if (fDebug 
                                && fDebugSmsg)
                            {
                                LogPrint("smessage", "%s : ERROR - Don't have bucket %d. \n", __FUNCTION__, time);
                            }

                            return false;
                        }

                        std::set<SecMsgToken>& tokenSet = itb->second.setTokens;
                        std::set<SecMsgToken>::iterator it;

                        SecMsgToken token;

                        uint8_t* p = &vchData[8];

                        for (int i = 0; i < n; ++i)
                        {
                            memcpy(&token.timestamp, p, 8);
                            memcpy(&token.sample, p+8, 8);

                            it = tokenSet.find(token);

                            if (it == tokenSet.end())
                            {
                                if (fDebug 
                                    && fDebugSmsg)
                                {
                                    LogPrint("smessage", "%s : WARNING - Don't have wanted message %d. \n", __FUNCTION__, token.timestamp);
                                }
                            }
                            else
                            {
                                //LogPrint("smessage", "Have message at %d.\n", it->offset); // DEBUG
                                token.offset = it->offset;
                                //LogPrint("smessage", "winb before SecureMsgRetrieve %d.\n", token.timestamp);

                                // -- place in vchOne so if SecureMsgRetrieve fails it won't corrupt vchBunch
                                if (SecureMsgRetrieve(token, vchOne) == 0)
                                {
                                    nBunch++;
                                    // append
                                    vchBunch.insert(vchBunch.end(), vchOne.begin(), vchOne.end());
                                }
                                else
                                {
                                    if (fDebug 
                                        && fDebugSmsg)
                                    {
                                        LogPrint("smessage", "%s : ERROR - SecureMsgRetrieve failed %d. \n", __FUNCTION__, token.timestamp);
                                    }
                                }

                                if (nBunch >= 500
                                    || vchBunch.size() >= 96000)
                                {
                                    if (fDebug 
                                        && fDebugSmsg)
                                    {
                                        LogPrint("smessage", "%s : NOTICE - Break bunch %u, %u. \n", nBunch, __FUNCTION__, vchBunch.size());
                                    }

                                    break; // end here, peer will send more want messages if needed.
                                }
                            }

                            p += 16;
                        }
                    } // LOCK(cs_smsg);
                    // // Global Namespace End
                    
                    if (nBunch > 0)
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : OK - Sending block of %u messages for bucket %d. \n", __FUNCTION__, nBunch, time);
                        }

                        memcpy(&vchBunch[0], &nBunch, 4);
                        memcpy(&vchBunch[4], &time, 8);
                        
                        pfrom->PushMessage("smsgMsg", vchBunch);
                    }
                }
                else
                {
                    if (strCommand == "smsgMsg")
                    {
                        std::vector<uint8_t> vchData;
                        vRecv >> vchData;

                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : NOTICE - smsgMsg vchData.size() %u. \n", __FUNCTION__, vchData.size());
                        }

                        SecureMsgReceive(pfrom, vchData);
                    }
                    else
                    {
                        if (strCommand == "%s : smsgMatch")
                        {
                            std::vector<uint8_t> vchData;
                            vRecv >> vchData;

                            if (vchData.size() < 8)
                            {
                                if (fDebug 
                                    && fDebugSmsg)
                                {
                                    LogPrint("smessage", "%s : ERROR - smsgMatch, not enough data %u. \n", __FUNCTION__, vchData.size());
                                }

                                Misbehaving(pfrom->GetId(), 1);
                                
                                return false;
                            }

                            int64_t time;

                            memcpy(&time, &vchData[0], 8);

                            int64_t now = GetTime();

                            if (time > now + SMSG_TIME_LEEWAY)
                            {
                                if (fDebug 
                                    && fDebugSmsg)
                                {
                                    LogPrint("smessage", "%s : WARNING - Peer buckets matched in the future: %d. \n Either this node or the peer node has the incorrect time set. \n", __FUNCTION__, time);
                                    LogPrint("smessage", "%s : OK - Peer match time set to now. \n", __FUNCTION__);
                                }
                                
                                time = now;
                            }
                            
                            // Global Namespace Start
                            {
                                LOCK(pfrom->smsgData.cs_smsg_net);

                                pfrom->smsgData.lastMatched = time;
                            }
                            // Global Namespace End
                            
                            if (fDebug 
                                && fDebugSmsg)
                            {
                                LogPrint("smessage", "%s : OK - Peer buckets matched at %d. \n", __FUNCTION__, time);
                            }
                        }
                        else
                        {
                            if (strCommand == "smsgPing")
                            {
                                // -- smsgPing is the initial message, send reply
                                pfrom->PushMessage("smsgPong");
                            }
                            else
                            {
                                if (strCommand == "smsgPong")
                                {
                                    if (fDebug 
                                        && fDebugSmsg)
                                    {
                                        LogPrint("smessage", "%s : NOTICE - Peer replied, secure messaging enabled. \n", __FUNCTION__);
                                    }
                                    
                                    // Global Namespace Start
                                    {
                                        LOCK(pfrom->smsgData.cs_smsg_net);

                                        pfrom->smsgData.fEnabled = true;
                                    }
                                    // // Global Namespace End                                    
                                }
                                else
                                {
                                    if (strCommand == "smsgDisabled")
                                    {
                                        // -- peer has disabled secure messaging.
                                        
                                        // // Global Namespace Start
                                        {
                                            LOCK(pfrom->smsgData.cs_smsg_net);

                                            pfrom->smsgData.fEnabled = false;
                                        }
                                        // // Global Namespace End
                                        
                                        if (fDebug 
                                            && fDebugSmsg)
                                        {
                                            LogPrint("smessage", "%s : WARNING - Peer %d has disabled secure messaging. \n", __FUNCTION__, pfrom->id);
                                        }
                                    }
                                    else
                                    {
                                        if (strCommand == "smsgIgnore")
                                        {
                                            // -- peer is reporting that it will ignore this node until time.
                                            //    Ignore peer too
                                            std::vector<uint8_t> vchData;
                                            vRecv >> vchData;

                                            if (vchData.size() < 8)
                                            {
                                                if (fDebug 
                                                    && fDebugSmsg)
                                                {
                                                    LogPrint("smessage", "%s : ERROR - smsgIgnore, not enough data %u. \n", __FUNCTION__, vchData.size());
                                                }

                                                Misbehaving(pfrom->GetId(), 1);
                                                
                                                return false;
                                            }

                                            int64_t time;

                                            memcpy(&time, &vchData[0], 8);
                                            
                                            // Global Namespace Start
                                            {
                                                LOCK(pfrom->smsgData.cs_smsg_net);

                                                pfrom->smsgData.ignoreUntil = time;
                                            }
                                            // Global Namespace End                                            

                                            if (fDebug 
                                                && fDebugSmsg)
                                            {
                                                LogPrint("smessage", "%s : NOTICE - Peer %d is ignoring this node until %d, ignore peer too. \n", __FUNCTION__, pfrom->id, time);
                                            }
                                        }
                                        else
                                        {
                                            // Unknown message
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return true;
}


bool SecureMsgSendData(CNode* pto, bool fSendTrickle)
{
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */
    
    LOCK(pto->smsgData.cs_smsg_net);

    /*  Not needed for debug, shows connection
    if (fDebug)
    {
        LogPrint("smessage", "%s : %s.\n", __FUNCTION__, pto->addrName.c_str());
    }
    */

    int64_t now = GetTime();

    if (pto->smsgData.lastSeen == 0)
    {
        // -- first contact
        pto->smsgData.lastSeen = GetTime();

        // -- Send smsgPing once, do nothing until receive 1st smsgPong (then set fEnabled)
        pto->PushMessage("smsgPing");

        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : OK - new node %s, peer id %u. \n", __FUNCTION__, pto->addrName.c_str(), pto->id);
        }

        return true;
    }
    else
    {
        if (!pto->smsgData.fEnabled
            || now - pto->smsgData.lastSeen < SMSG_SEND_DELAY
            || now < pto->smsgData.ignoreUntil)
        {
            return true;
        }
    }

    // -- When nWakeCounter == 0, resend bucket inventory.
    if (pto->smsgData.nWakeCounter < 1)
    {
        pto->smsgData.lastMatched = 0;

        // set to a random time between [10, 300] * SMSG_SEND_DELAY seconds
        pto->smsgData.nWakeCounter = 10 + GetRandInt(300);

        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : OK - nWakeCounter expired, sending bucket inventory to %s."
                    " Now %d next wake counter %u \n", __FUNCTION__, pto->addrName.c_str(), now, pto->smsgData.nWakeCounter);
        }
    }

    pto->smsgData.nWakeCounter--;

    // Global Namespace Start
    {
        LOCK(cs_smsg);

        std::map<int64_t, SecMsgBucket>::iterator it;

        uint32_t nBuckets = smsgBuckets.size();
        
        // no need to send keep alive pkts, coin messages already do that
        if (nBuckets > 0)
        {
            std::vector<uint8_t> vchData;

            // should reserve?
            // timestamp + size + hash
            vchData.reserve(4 + nBuckets*16);

            uint32_t nBucketsShown = 0;

            vchData.resize(4);

            uint8_t* p = &vchData[4];
            
            for (it = smsgBuckets.begin(); it != smsgBuckets.end(); ++it)
            {
                SecMsgBucket &bkt = it->second;

                uint32_t nMessages = bkt.setTokens.size();

                if (bkt.timeChanged < pto->smsgData.lastMatched
                    || nMessages < 1)
                {
                    // peer has this bucket
                    // this bucket is empty
                    continue;
                }         

                uint32_t hash = bkt.hash;

                try
                {
                    vchData.resize(vchData.size() + 16);
                } 
                catch (std::exception& e)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - vchData.resize %u threw: %s. \n", __FUNCTION__, vchData.size() + 16, e.what());
                    }

                    continue;
                }

                memcpy(p, &it->first, 8);
                memcpy(p+8, &nMessages, 4);
                memcpy(p+12, &hash, 4);

                p += 16;

                nBucketsShown++;
                
                /* Not working (Compile Error)
                if (fDebug)
                {
                    LogPrint("smessage", "%s : Sending bucket %d, size %d \n", __FUNCTION__, it->first, it->second.size());
                }
                */
            }

            if (vchData.size() > 4)
            {
                memcpy(&vchData[0], &nBucketsShown, 4);
                
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : OK - Sending %d bucket headers. \n", __FUNCTION__, nBucketsShown);
                }

                pto->PushMessage("smsgInv", vchData);
            }
        }
    }
    // Global Namespace End
    // cs_smsg

    pto->smsgData.lastSeen = GetTime();

    return true;
}


static int SecureMsgInsertAddress(CKeyID& hashKey, CPubKey& pubKey, SecMsgDB& addrpkdb)
{
    /* insert key hash and public key to addressdb

        should have LOCK(cs_smsg) where db is opened

        returns
            0 success
            1 error
            4 address is already in db
    */


    if (addrpkdb.ExistsPK(hashKey))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : WARNING - DB already contains public key for address. \n", __FUNCTION__);
        }

        CPubKey cpkCheck;
        
        if (!addrpkdb.ReadPK(hashKey, cpkCheck))
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - addrpkdb.Read failed. \n", __FUNCTION__);
            }
        }
        else
        {
            if (cpkCheck != pubKey)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - DB already contains existing public key that does not match . \n", __FUNCTION__);
                }
            }
        }
    
        return 4;
    }

    if (!addrpkdb.WritePK(hashKey, pubKey))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Write pair failed. \n", __FUNCTION__);
        }

        return 1;
    }

    return 0;
}


int SecureMsgInsertAddress(CKeyID& hashKey, CPubKey& pubKey)
{
    int rv;

    // Global Namespace Start
    {
        LOCK(cs_smsgDB);

        SecMsgDB addrpkdb;

        if (!addrpkdb.Open("cr+"))
        {
            return 1;
        }

        rv = SecureMsgInsertAddress(hashKey, pubKey, addrpkdb);
    }
    // Global Namespace End

    return rv;
}


static bool ScanBlock(CBlock& block, CTxDB& txdb, SecMsgDB& addrpkdb, uint32_t& nTransactions, uint32_t& nElements, uint32_t& nPubkeys, uint32_t& nDuplicates)
{
    AssertLockHeld(cs_smsgDB);
    
    valtype vch;
    opcodetype opcode;
    
    // -- only scan inputs of standard txns and coinstakes
    
    for(CTransaction& tx: block.vtx)
    {
        std::string sReason;

        // - harvest public keys from coinstake txns
        if (tx.IsCoinStake())
        {
            const CTxOut& txout = tx.vout[1];
            
            CScript::const_iterator pc = txout.scriptPubKey.begin();
            
            while (pc < txout.scriptPubKey.end())
            {
                if (!txout.scriptPubKey.GetOp(pc, opcode, vch))
                {
                    break;
                }
                
                // pubkey
                if (vch.size() == 33)
                {
                    CPubKey pubKey(vch);
                    
                    if (!pubKey.IsValid()
                        || !pubKey.IsCompressed())
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : ERROR - Public key is invalid %s. \n", __FUNCTION__, HexStr(pubKey).c_str());
                        }

                        continue;
                    }
                    
                    CKeyID addrKey = pubKey.GetID();
                    
                    switch (SecureMsgInsertAddress(addrKey, pubKey, addrpkdb))
                    {
                        case 0:
                        {
                            // added key
                            nPubkeys++;
                        }
                        break;
                        
                        case 4:
                        {
                            // duplicate key
                            nDuplicates++;
                        }
                        break;
                    }
                    break;
                }
            }

            nElements++;
        }
        else if (IsStandardTx(tx, sReason))
        {
            for (uint32_t i = 0; i < tx.vin.size(); i++)
            {
                CScript *script = &tx.vin[i].scriptSig;
                CScript::const_iterator pc = script->begin();
                CScript::const_iterator pend = script->end();

                uint256 prevoutHash;
                
                CKey key;

                while (pc < pend)
                {
                    if (!script->GetOp(pc, opcode, vch))
                    {
                        break;
                    }

                    // - opcode is the length of the following data, compressed public key is always 33
                    if (opcode == 33)
                    {
                        CPubKey pubKey(vch);
                        
                        if (!pubKey.IsValid()
                            || !pubKey.IsCompressed())
                        {
                            if (fDebug 
                                && fDebugSmsg)
                            {
                                LogPrint("smessage", "%s : ERROR - Public key is invalid %s. \n", __FUNCTION__, HexStr(pubKey).c_str());
                            }

                            continue;
                        }
                        
                        CKeyID addrKey = pubKey.GetID();
                        
                        switch (SecureMsgInsertAddress(addrKey, pubKey, addrpkdb))
                        {
                            case 0:
                            {
                                // added key
                                nPubkeys++;
                            }
                            break;
                            
                            case 4:
                            {
                                // duplicate key
                                nDuplicates++;
                            }
                            break;
                        }
                        break;
                    }

                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : OK - Opcode %d, %s, value %s. \n", __FUNCTION__, opcode, GetOpName(opcode), ValueString(vch).c_str());
                    }
                }

                nElements++;
            }
        }

        nTransactions++;

        // for ScanChainForPublicKeys
        if (nTransactions % 10000 == 0)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : OK - Scanning transaction no. %u. \n", __FUNCTION__, nTransactions);
            }
        }
    }

    return true;
}


bool SecureMsgScanBlock(CBlock& block)
{
    // - scan block for public key addresses
    
    if (!smsgOptions.fScanIncoming)
    {
        return true;
    }

    uint32_t nTransactions  = 0;
    uint32_t nElements      = 0;
    uint32_t nPubkeys       = 0;
    uint32_t nDuplicates    = 0;

    // Global Namespace Start
    {
        LOCK(cs_smsgDB);

        CTxDB txdb("r");

        SecMsgDB addrpkdb;
        
        if (!addrpkdb.Open("cw")
            || !addrpkdb.TxnBegin())
        {
            return false;
        }

        ScanBlock(block, txdb, addrpkdb, nTransactions, nElements, nPubkeys, nDuplicates);

        addrpkdb.TxnCommit();
    }
    // Global Namespace End
    // cs_smsgDB

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : OK - Found %u transactions, %u elements, %u new public keys, %u duplicates. \n", __FUNCTION__, nTransactions, nElements, nPubkeys, nDuplicates);
    }

    if (nDuplicates > 0)
    {
        CChain::PruneOrphanBlocks();
    }

    return true;
}


bool ScanChainForPublicKeys(CBlockIndex* pindexStart)
{
    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - Scanning block chain for public keys. \n", __FUNCTION__);
    }

    int64_t nStart = GetTimeMillis();

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - From height %u. \n", __FUNCTION__, pindexStart->nHeight);
    }

    // -- public keys are in txin.scriptSig
    //    matching addresses are in scriptPubKey of txin's referenced output

    uint32_t nBlocks        = 0;
    uint32_t nTransactions  = 0;
    uint32_t nInputs        = 0;
    uint32_t nPubkeys       = 0;
    uint32_t nDuplicates    = 0;

    // Global Namespace Start
    {
        LOCK(cs_smsgDB);

        CTxDB txdb("r");

        SecMsgDB addrpkdb;
        
        if (!addrpkdb.Open("cw")
            || !addrpkdb.TxnBegin())
        {
            return false;
        }

        CBlockIndex* pindex = pindexStart;
        
        while (pindex)
        {
            nBlocks++;
            
            CBlock block;
            
            block.ReadFromDisk(pindex, true);

            ScanBlock(block, txdb, addrpkdb, nTransactions, nInputs, nPubkeys, nDuplicates);

            pindex = pindex->pnext;
        }

        addrpkdb.TxnCommit();
    }
    // Global Namespace End
    // cs_smsgDB

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - Scanned %u blocks, %u transactions, %u inputs \n", __FUNCTION__, nBlocks, nTransactions, nInputs);
        LogPrint("smessage", "%s : NOTICE - Found %u public keys, %u duplicates. \n", __FUNCTION__, nPubkeys, nDuplicates);
        LogPrint("smessage", "%s : NOTICE - Took %d ms \n", __FUNCTION__, GetTimeMillis() - nStart);
    }

    return true;
}


bool SecureMsgScanBlockChain()
{
    TRY_LOCK(cs_main, lockMain);

    if (lockMain)
    {
        CBlockIndex *pindexScan = pindexGenesisBlock;
    
        if (pindexScan == NULL)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - pindexGenesisBlock not set. \n", __FUNCTION__);
            }

            return false;
        }


        try
        { // -- in try to catch errors opening db,
            if (!ScanChainForPublicKeys(pindexScan))
            {
                return false;
            }
        }
        catch (std::exception& e)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Threw: %s. \n", __FUNCTION__, e.what());
            }

            return false;
        }
    }
    else
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Could not lock main. \n", __FUNCTION__);
        }

        return false;
    }

    return true;
}


bool SecureMsgScanBuckets()
{
    if (!fSecMsgEnabled
        || pwalletMain->IsLocked())
    {
        return false;
    }

    int64_t  mStart         = GetTimeMillis();
    int64_t  now            = GetTime();
    uint32_t nFiles         = 0;
    uint32_t nMessages      = 0;
    uint32_t nFoundMessages = 0;

    fs::path pathSmsgDir = GetDataDir(true) / "smsgStore";
    fs::directory_iterator itend;

    if (!fs::exists(pathSmsgDir)
        || !fs::is_directory(pathSmsgDir))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : WARNING - Message store directory does not exist. \n", __FUNCTION__);
        }

        return 0; // not an error
    }

    SecureMessage smsg;
    std::vector<uint8_t> vchData;

    for (fs::directory_iterator itd(pathSmsgDir) ; itd != itend ; ++itd)
    {
        if (!fs::is_regular_file(itd->status()))
        {
            continue;
        }

        std::string fileType = (*itd).path().extension().string();

        if (fileType.compare(".dat") != 0)
        {
            continue;
        }

        std::string fileName = (*itd).path().filename().string();

        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : NOTICE - Processing file: %s. \n", __FUNCTION__, fileName.c_str());
        }

        nFiles++;

        // TODO files must be split if > 2GB
        // time_noFile.dat
        size_t sep = fileName.find_first_of("_");

        if (sep == std::string::npos)
        {
            continue;
        }

        std::string stime = fileName.substr(0, sep);

        int64_t fileTime = boost::lexical_cast<int64_t>(stime);

        if (fileTime < now - SMSG_RETENTION)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : WARNING - Dropping file %s, expired. \n", __FUNCTION__, fileName.c_str());
            }

            try
            {
                fs::remove((*itd).path());
            }
            catch (const fs::filesystem_error& ex)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Removing bucket file %s, %s. \n", __FUNCTION__, fileName.c_str(), ex.what());
                }
            }

            continue;
        }

        if (boost::algorithm::ends_with(fileName, "_wl.dat"))
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : WARNING - Skipping wallet locked file: %s. \n", __FUNCTION__, fileName.c_str());
            }

            continue;
        }

        // Global Namespace Start
        {
            LOCK(cs_smsg);

            FILE *fp;
            
            errno = 0;
            
            if (!(fp = fopen((*itd).path().string().c_str(), "rb")))
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Opening file: %s \n", __FUNCTION__, strerror(errno));
                }

                continue;
            }

            for (;;)
            {
                errno = 0;
#if __ANDROID__ 
                if (fread(&smsg.hash[0], sizeof(uint8_t), 4, fp) != (size_t)SMSG_HDR_LEN)
#else
                if (fread(&smsg.hash[0], sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN)
#endif
                {
                    if (errno != 0)
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : ERROR - Fread header failed: %s \n", __FUNCTION__, strerror(errno));
                        }
                    }
                    else
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : ERROR - End of file. \n", __FUNCTION__);
                        }
                    }
                    break;
                }

                try
                {
                    vchData.resize(smsg.nPayload);
                }
                catch (std::exception& e)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - Could not resize vchData, %u, %s \n", __FUNCTION__, smsg.nPayload, e.what());
                    }

                    fclose(fp);
                    
                    return 1;
                }

                if (fread(&vchData[0], sizeof(uint8_t), smsg.nPayload, fp) != smsg.nPayload)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - Fread data failed: %s \n", __FUNCTION__, strerror(errno));
                    }

                    break;
                }

                // -- don't report to gui,
                int rv = SecureMsgScanMessage(&smsg.hash[0], &vchData[0], smsg.nPayload, false);

                if (rv == 0)
                {
                    nFoundMessages++;
                }
                else if (rv != 0)
                {
                    // SecureMsgScanMessage failed
                }

                nMessages ++;
            }

            fclose(fp);

            // -- remove wl file when scanned
            try
            {
                fs::remove((*itd).path());
            }
            catch (const boost::filesystem::filesystem_error& ex)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Removing wl file %s - %s \n", __FUNCTION__, fileName.c_str(), ex.what());
                }

                return 1;
            }
        } // cs_smsg
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : OK - Processed %u files, scanned %u messages, received %u messages. \n", __FUNCTION__, nFiles, nMessages, nFoundMessages);
        LogPrint("smessage", "%s : OK - Took %d ms \n", __FUNCTION__, GetTimeMillis() - mStart);
    }

    return true;
}


int SecureMsgWalletUnlocked()
{
    /*
    When the wallet is unlocked, scan messages received while wallet was locked.
    */

    if (!fSecMsgEnabled)
    {
        return 0;
    }

    if (pwalletMain->IsLocked())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Wallet is locked. \n", __FUNCTION__);
        }

        return 1;
    }

    int64_t  now            = GetTime();
    uint32_t nFiles         = 0;
    uint32_t nMessages      = 0;
    uint32_t nFoundMessages = 0;

    fs::path pathSmsgDir = GetDataDir(true) / "smsgStore";
    fs::directory_iterator itend;

    if (!fs::exists(pathSmsgDir)
        || !fs::is_directory(pathSmsgDir))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : WARNING - Message store directory does not exist. \n", __FUNCTION__);
        }

        // not an error
        return 0;
    }

    SecureMessage smsg;
    std::vector<uint8_t> vchData;

    for (fs::directory_iterator itd(pathSmsgDir) ; itd != itend ; ++itd)
    {
        if (!fs::is_regular_file(itd->status()))
        {
            continue;
        }

        std::string fileName = (*itd).path().filename().string();

        if (!boost::algorithm::ends_with(fileName, "_wl.dat"))
        {
            continue;
        }

        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : NOTICE - Processing file: %s. \n", __FUNCTION__, fileName.c_str());
        }

        nFiles++;

        // TODO files must be split if > 2GB
        // time_noFile_wl.dat
        size_t sep = fileName.find_first_of("_");

        if (sep == std::string::npos)
        {
            continue;
        }

        std::string stime = fileName.substr(0, sep);

        int64_t fileTime = boost::lexical_cast<int64_t>(stime);

        if (fileTime < now - SMSG_RETENTION)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : WARNING - Dropping wallet locked file %s, expired. \n", __FUNCTION__, fileName.c_str());
            }

            try
            {
                fs::remove((*itd).path());
            }
            catch (const boost::filesystem::filesystem_error& ex)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Removing wl file %s - %s \n", __FUNCTION__, fileName.c_str(), ex.what());
                }

                return 1;
            }

            continue;
        }

        // Global Namespace Start
        {
            LOCK(cs_smsg);
            
            FILE *fp;
            
            errno = 0;
            
            if (!(fp = fopen((*itd).path().string().c_str(), "rb")))
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Opening file: %s \n", __FUNCTION__, strerror(errno));
                }

                continue;
            }

            for (;;)
            {
                errno = 0;

#if __ANDROID__ 
                if (fread(&smsg.hash[0], sizeof(uint8_t), 4, fp) != (size_t)SMSG_HDR_LEN)
#else
                if (fread(&smsg.hash[0], sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN)
#endif
                {
                    if (errno != 0)
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : ERROR - Fread header failed: %s \n", __FUNCTION__, strerror(errno));
                        }
                    }
                    else
                    {
                        if (fDebug 
                            && fDebugSmsg)
                        {
                            LogPrint("smessage", "%s : ERROR - End of file. \n", __FUNCTION__);
                        }
                    }

                    break;
                }

                try
                {
                    vchData.resize(smsg.nPayload);
                }
                catch (std::exception& e)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - Could not resize vchData, %u, %s \n", __FUNCTION__, smsg.nPayload, e.what());
                    }

                    fclose(fp);
                
                    return 1;
                }

                if (fread(&vchData[0], sizeof(uint8_t), smsg.nPayload, fp) != smsg.nPayload)
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - Fread data failed: %s \n", __FUNCTION__, strerror(errno));
                    }

                    break;
                }

                // -- don't report to gui,
                int rv = SecureMsgScanMessage(&smsg.hash[0], &vchData[0], smsg.nPayload, false);

                if (rv == 0)
                {
                    nFoundMessages++;
                }
                else if (rv != 0)
                {
                    // SecureMsgScanMessage failed
                }

                nMessages ++;
            }

            fclose(fp);

            // -- remove wl file when scanned
            try
            {
                fs::remove((*itd).path());
            }
            catch (const boost::filesystem::filesystem_error& ex)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - Removing wl file %s - %s \n", __FUNCTION__, fileName.c_str(), ex.what());
                }

                return 1;
            }

            MilliSleep(5);
        }
        // Global Namespace End
        // cs_smsg
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : OK - Processed %u files, scanned %u messages, received %u messages. \n", __FUNCTION__, nFiles, nMessages, nFoundMessages);
    }

    // -- notify gui
    NotifySecMsgWalletUnlocked();
    
    return 0;
}


int SecureMsgWalletKeyChanged(std::string sAddress, std::string sLabel, ChangeType mode)
{
    if (!fSecMsgEnabled)
    {
        return 0;
    }

    // TODO: default recv and recvAnon
    // Global Namespace Start
    {
        LOCK(cs_smsg);

        switch(mode)
        {
            case CT_NEW:
            {
                smsgAddresses.push_back(SecMsgAddress(sAddress, smsgOptions.fNewAddressRecv, smsgOptions.fNewAddressAnon));
            }
            break;
            
            case CT_DELETED:
            {
                for (std::vector<SecMsgAddress>::iterator it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
                {
                    if (sAddress != it->sAddress)
                    {
                        continue;
                    }

                    smsgAddresses.erase(it);
                    
                    break;
                }

                break;
            }
            break;

            default:
            {
                // Do nothing
            }
            break;
        }

    }
    // Global Namespace End
    // cs_smsg


    return 0;
}


int SecureMsgScanMessage(uint8_t *pHeader, uint8_t *pPayload, uint32_t nPayload, bool reportToGui)
{
    /*
    Check if message belongs to this node.
    If so add to inbox db.

    if !reportToGui don't fire NotifySecMsgInboxChanged
     - loads messages received when wallet locked in bulk.

    returns
        0 success,
        1 error
        2 no match
        3 wallet is locked - message stored for scanning later.
    */

    if (pwalletMain->IsLocked())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : WARNING - ScanMessage: Wallet is locked, storing message to scan later. \n", __FUNCTION__);
        }

        int rv;
        
        if ((rv = SecureMsgStoreUnscanned(pHeader, pPayload, nPayload)) != 0)
        {
            return 1;
        }

        return 3;
    }

    std::string addressTo;
    
    MessageData msg; // placeholder
    
    bool fOwnMessage = false;

    for (std::vector<SecMsgAddress>::iterator it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
    {
        if (!it->fReceiveEnabled)
        {
            continue;
        }

        CCoinAddress coinAddress(it->sAddress);
        addressTo = coinAddress.ToString();

        if (!it->fReceiveAnon)
        {
            // -- have to do full decrypt to see address from
            if (SecureMsgDecrypt(false, addressTo, pHeader, pPayload, nPayload, msg) == 0)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : OK - Decrypted message with %s. \n", __FUNCTION__, addressTo.c_str());
                }

                if (msg.sFromAddress.compare("anon") != 0)
                {
                    fOwnMessage = true;
                }

                break;
            }
        }
        else
        {

            if (SecureMsgDecrypt(true, addressTo, pHeader, pPayload, nPayload, msg) == 0)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : OK - Decrypted message with %s. \n", __FUNCTION__, addressTo.c_str());
                }

                fOwnMessage = true;
                break;
            }
        }
    }

    if (fOwnMessage)
    {
        // -- save to inbox
        SecureMessage* psmsg = (SecureMessage*) pHeader;
        
        std::string sPrefix("im");
        
        uint8_t chKey[18];
        
        memcpy(&chKey[0],  sPrefix.data(),    2);
        memcpy(&chKey[2],  &psmsg->timestamp, 8);
        memcpy(&chKey[10], pPayload,          8);

        SecMsgStored smsgInbox;
        
        smsgInbox.timeReceived  = GetTime();
        smsgInbox.status        = (SMSG_MASK_UNREAD) & 0xFF;
        smsgInbox.sAddrTo       = addressTo;

        // -- data may not be contiguous
        try
        {
            smsgInbox.vchMessage.resize(SMSG_HDR_LEN + nPayload);
        }
        catch (std::exception& e)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Could not resize vchData, %u, %s \n", __FUNCTION__, SMSG_HDR_LEN + nPayload, e.what());
            }

            return 1;
        }

        memcpy(&smsgInbox.vchMessage[0], pHeader, SMSG_HDR_LEN);
        memcpy(&smsgInbox.vchMessage[SMSG_HDR_LEN], pPayload, nPayload);

        // Global Namespace Start
        {
            LOCK(cs_smsgDB);

            SecMsgDB dbInbox;

            if (dbInbox.Open("cw"))
            {
                if (dbInbox.ExistsSmesg(chKey))
                {
                    if (fDebug 
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - Message already exists in inbox db. \n", __FUNCTION__);
                    }
                }
                else
                {
                    dbInbox.WriteSmesg(chKey, smsgInbox);

                    if (reportToGui)
                    {
                        NotifySecMsgInboxChanged(smsgInbox);
                    }

                    if (fDebug
                        && fDebugSmsg)
                    {
                        LogPrint("smessage", "%s : ERROR - SecureMsg saved to inbox, received with %s. \n", __FUNCTION__, addressTo.c_str());
                    }
                }
            }
        }
        // Global Namespace End
        // cs_smsgDB
    }

    return 0;
}


int SecureMsgGetLocalKey(CKeyID& ckid, CPubKey& cpkOut)
{
    if (!pwalletMain->GetPubKey(ckid, cpkOut))
    {
        return 4;
    }

    if (!cpkOut.IsValid()
        || !cpkOut.IsCompressed())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Public key is invalid %s. \n", __FUNCTION__, HexStr(cpkOut).c_str());
        }

        return 1;
    }
    
    return 0;
}


int SecureMsgGetLocalPublicKey(std::string& strAddress, std::string& strPublicKey)
{
    /* returns
        0 success,
        1 error
        2 invalid address
        3 address does not refer to a key
        4 address not in wallet
    */

    CCoinAddress address;

    if (!address.SetString(strAddress))
    {
        // Invalid coin address
        return 2;
    }

    CKeyID keyID;

    if (!address.GetKeyID(keyID))
    {
        return 3;
    }

    int rv;
    
    CPubKey pubKey;
    
    if ((rv = SecureMsgGetLocalKey(keyID, pubKey)) != 0)
    {
        return rv;
    }

    strPublicKey = EncodeBase58(pubKey.begin(), pubKey.end());

    return 0;
}


int SecureMsgGetStoredKey(CKeyID& ckid, CPubKey& cpkOut)
{
    /* returns
        0 success,
        1 error
        2 public key not in database
    */

    // Global Namespace Start
    {
        LOCK(cs_smsgDB);
        
        SecMsgDB addrpkdb;

        if (!addrpkdb.Open("r"))
        {
            return 1;
        }

        if (!addrpkdb.ReadPK(ckid, cpkOut))
        {
            /* Not working (Compile Error)
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Addrpkdb.Read failed: %s.\n", __FUNCTION__, addrpkdb.ToString().c_str());
            }
            */

            return 2;
        }
    }
    // Global Namespace End
    // cs_smsgDB

    return 0;
}


int SecureMsgAddAddress(std::string& address, std::string& publicKey)
{
    /*
        Add address and matching public key to the database
        address and publicKey are in base58

        returns
            0 success
            1 error
            2 publicKey is invalid
            3 publicKey != address
            4 address is already in db
            5 address is invalid
    */

    CCoinAddress coinAddress(address);

    if (!coinAddress.IsValid())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s - ERROR - Address is not valid: %s. \n", __FUNCTION__, address.c_str());
        }

        return 5;
    }

    CKeyID hashKey;

    if (!coinAddress.GetKeyID(hashKey))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s - ERROR - CoinAddress.GetKeyID failed: %s. \n", __FUNCTION__, coinAddress.ToString().c_str());
        }

        return 5;
    }

    std::vector<uint8_t> vchTest;
    
    DecodeBase58(publicKey, vchTest);
    
    CPubKey pubKey(vchTest);

    // -- check that public key matches address hash
    CPubKey pubKeyT(pubKey);

    if (!pubKeyT.IsValid())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s - ERROR - Invalid PubKey. \n", __FUNCTION__);
        }

        return 2;
    }
    
    CKeyID keyIDT = pubKeyT.GetID();
    CCoinAddress addressT(keyIDT);

    if (addressT.ToString().compare(address) != 0)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s - ERROR - Public key does not hash to address, addressT %s. \n", __FUNCTION__, addressT.ToString().c_str());
        }

        return 3;
    }

    return SecureMsgInsertAddress(hashKey, pubKey);
}


int SecureMsgRetrieve(SecMsgToken &token, std::vector<uint8_t>& vchData)
{
    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - Token.timestamp: %d. \n", __FUNCTION__, token.timestamp);
    }

    // -- has cs_smsg lock from SecureMsgReceiveData

    fs::path pathSmsgDir = GetDataDir(true) / "smsgStore";

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - Token.offset %d. \n", __FUNCTION__, token.offset);
    }

    int64_t bucket = token.timestamp - (token.timestamp % SMSG_BUCKET_LEN);
    
    std::string fileName = boost::lexical_cast<std::string>(bucket) + "_01.dat";
    
    fs::path fullpath = pathSmsgDir / fileName;

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - Bucket %d. \n", __FUNCTION__, bucket);
        LogPrint("smessage", "%s : NOTICE - Bucket d %d. \n", __FUNCTION__, bucket);
        LogPrint("smessage", "%s : NOTICE - FileName %s. \n", __FUNCTION__, fileName.c_str());
    }

    FILE *fp;
    errno = 0;
    
    if (!(fp = fopen(fullpath.string().c_str(), "rb")))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Opening file: %s \n Path %s \n", __FUNCTION__, strerror(errno), fullpath.string().c_str());
        }

        return 1;
    }

    errno = 0;
    
    if (fseek(fp, token.offset, SEEK_SET) != 0)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Fseek, strerror: %s. \n", __FUNCTION__, strerror(errno));
        }

        fclose(fp);
    
        return 1;
    }

    SecureMessage smsg;
    errno = 0;

#if __ANDROID__ 
    if (fread(&smsg.hash[0], sizeof(uint8_t), 4, fp) != (size_t)SMSG_HDR_LEN)
#else
    if (fread(&smsg.hash[0], sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN)
#endif
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Fread header failed: %s \n", __FUNCTION__, strerror(errno));
        }

        fclose(fp);
    
        return 1;
    }

    try
    {
        vchData.resize(SMSG_HDR_LEN + smsg.nPayload);
    }
    catch (std::exception& e)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Could not resize vchData, %u, %s \n", __FUNCTION__, SMSG_HDR_LEN + smsg.nPayload, e.what());
        }

        return 1;
    }

    memcpy(&vchData[0], &smsg.hash[0], SMSG_HDR_LEN);
    
    errno = 0;
    
    if (fread(&vchData[SMSG_HDR_LEN], sizeof(uint8_t), smsg.nPayload, fp) != smsg.nPayload)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Fread data failed: %s. Wanted %u bytes. \n", __FUNCTION__, strerror(errno), smsg.nPayload);
        }

        fclose(fp);
        
        return 1;
    }

    fclose(fp);

    return 0;
}


int SecureMsgReceive(CNode* pfrom, std::vector<uint8_t>& vchData)
{
    if (vchData.size() < 12) // nBunch4 + timestamp8
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Not enough data. \n", __FUNCTION__);
        }

        return 1;
    }

    uint32_t nBunch;
    int64_t bktTime;

    memcpy(&nBunch, &vchData[0], 4);
    memcpy(&bktTime, &vchData[4], 8);

    // -- check bktTime ()
    //    bucket may not exist yet - will be created when messages are added
    int64_t now = GetTime();

    if (bktTime > now + SMSG_TIME_LEEWAY)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : NOTICE - bktTime > now. \n", __FUNCTION__);
        }

        // misbehave?
        return 1;
    }
    else if (bktTime < now - SMSG_RETENTION)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - bktTime < now - SMSG_RETENTION. \n", __FUNCTION__);
        }

        // misbehave?
        return 1;
    }

    std::map<int64_t, SecMsgBucket>::iterator itb;

    if (nBunch == 0
        || nBunch > 500)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : WARNING - Invalid no. messages received in bunch %u, for bucket %d. \n", __FUNCTION__, nBunch, bktTime);
        }

        Misbehaving(pfrom->GetId(), 1);
        
        // Global Namespace Start
        {
            LOCK(cs_smsg);
            
            // -- release lock on bucket if it exists
            itb = smsgBuckets.find(bktTime);
            
            if (itb != smsgBuckets.end())
            {
                itb->second.nLockCount = 0;
            }
        } 
        // Global Namespace End
        // cs_smsg
        return 1;
    }

    uint32_t n = 12;

    for (uint32_t i = 0; i < nBunch; ++i)
    {
        if (vchData.size() - n < SMSG_HDR_LEN)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Not enough data sent, n = %u. \n", __FUNCTION__, n);
            }

            break;
        }

        SecureMessage *psmsg = (SecureMessage*) &vchData[n];

        int rv;
        if ((rv = SecureMsgValidate(&vchData[n], &vchData[n + SMSG_HDR_LEN], psmsg->nPayload)) != 0)
        {
            // message dropped
            if (rv == 2) // invalid proof of work
            {
                Misbehaving(pfrom->GetId(), 1);
            }
            else
            {
                Misbehaving(pfrom->GetId(), 1);
            }

            continue;
        }
        
        // Global Namespace Start
        {
            LOCK(cs_smsg);

            // -- store message, but don't hash bucket
            if (SecureMsgStore(&vchData[n], &vchData[n + SMSG_HDR_LEN], psmsg->nPayload, false) != 0)
            {
                // message dropped
                break; // continue?
            }

            if (SecureMsgScanMessage(&vchData[n], &vchData[n + SMSG_HDR_LEN], psmsg->nPayload, true) != 0)
            {
                // message recipient is not this node (or failed)
            }
        } 
        // Global Namespace End
        // cs_smsg
        
        n += SMSG_HDR_LEN + psmsg->nPayload;
    }
    
    // Global Namespace Start
    {
        LOCK(cs_smsg);
        
        // -- if messages have been added, bucket must exist now
        itb = smsgBuckets.find(bktTime);
        
        if (itb == smsgBuckets.end())
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Don't have bucket %d. \n", __FUNCTION__, bktTime);
            }

            return 1;
        }

        // this node has received data from peer, release lock
        itb->second.nLockCount  = 0;
        itb->second.nLockPeerId = 0;
        itb->second.hashBucket();
    }
    // Global Namespace End
    // cs_smsg
    
    return 0;
}


int SecureMsgStoreUnscanned(uint8_t *pHeader, uint8_t *pPayload, uint32_t nPayload)
{
    /*
    When the wallet is locked a copy of each received message is stored to be scanned later if wallet is unlocked
    */
    if (!pHeader
        || !pPayload)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - null pointer to header or payload. \n", __FUNCTION__);
        }

        return 1;
    }

    SecureMessage* psmsg = (SecureMessage*) pHeader;

    fs::path pathSmsgDir;
    
    try
    {
        pathSmsgDir = GetDataDir(true) / "smsgStore";
        
        fs::create_directory(pathSmsgDir);
    }
    catch (const boost::filesystem::filesystem_error& ex)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Failed to create directory %s - %s \n", __FUNCTION__, pathSmsgDir.string().c_str(), ex.what());
        }

        return 1;
    }

    int64_t now = GetTime();
    
    if (psmsg->timestamp > now + SMSG_TIME_LEEWAY)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Message > now. \n", __FUNCTION__);
        }

        return 1;
    }
    else if (psmsg->timestamp < now - SMSG_RETENTION)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Message < SMSG_RETENTION. \n", __FUNCTION__);
        }

        return 1;
    }

    int64_t bucket = psmsg->timestamp - (psmsg->timestamp % SMSG_BUCKET_LEN);

    std::string fileName = boost::lexical_cast<std::string>(bucket) + "_01_wl.dat";
    fs::path fullpath = pathSmsgDir / fileName;

    FILE *fp;
    errno = 0;
    
    if (!(fp = fopen(fullpath.string().c_str(), "ab")))
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Opening file: %s \n", __FUNCTION__, strerror(errno));
        }

        return 1;
    }

    if (fwrite(pHeader, sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN
        || fwrite(pPayload, sizeof(uint8_t), nPayload, fp) != nPayload)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Fwrite failed: %s \n", __FUNCTION__, strerror(errno));
        }

        fclose(fp);
        
        return 1;
    }

    fclose(fp);

    return 0;
}


int SecureMsgStore(uint8_t *pHeader, uint8_t *pPayload, uint32_t nPayload, bool fUpdateBucket)
{
    if (fDebugSmsg)
    {
        AssertLockHeld(cs_smsg);
    }
    
    if (!pHeader
        || !pPayload)
    {
        return errorN(1, "%s : ERROR - Null pointer to header or payload.", __FUNCTION__);
    }

    SecureMessage* psmsg = (SecureMessage*) pHeader;

    long int ofs;

    fs::path pathSmsgDir;

    try
    {
        pathSmsgDir = GetDataDir(true) / "smsgStore";

        fs::create_directory(pathSmsgDir);
    }
    catch (const boost::filesystem::filesystem_error& ex)
    {
        return errorN(1, "%s : ERROR - Failed to create directory %s - %s.", __FUNCTION__, pathSmsgDir.string().c_str(), ex.what());
    }

    int64_t now = GetTime();
    
    if (psmsg->timestamp > now + SMSG_TIME_LEEWAY)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Message > now. \n", __FUNCTION__);
        }

        return 1;
    }
    else if (psmsg->timestamp < now - SMSG_RETENTION)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Message < SMSG_RETENTION. \n", __FUNCTION__);
        }

        return 1;
    }

    int64_t bucket = psmsg->timestamp - (psmsg->timestamp % SMSG_BUCKET_LEN);

    SecMsgToken token(psmsg->timestamp, pPayload, nPayload, 0);

    std::set<SecMsgToken>& tokenSet = smsgBuckets[bucket].setTokens;
    std::set<SecMsgToken>::iterator it;
    
    it = tokenSet.find(token);
    
    if (it != tokenSet.end())
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : NOTICE - Already have message. \n", __FUNCTION__);
            LogPrint("smessage", "%s : NOTICE - nPayload: %u \n", __FUNCTION__, nPayload);
            LogPrint("smessage", "%s : NOTICE - Bucket: %d \n", __FUNCTION__, bucket);
            LogPrint("smessage", "%s : NOTICE - Message ts: %d", __FUNCTION__, token.timestamp);
        }

        std::vector<uint8_t> vchShow;

        vchShow.resize(8);

        memcpy(&vchShow[0], token.sample, 8);

        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : NOTICE - Sample %s \n", __FUNCTION__, ValueString(vchShow).c_str());
            
            LogPrint("smessage", "%s : NOTICE - Messages in bucket: \n", __FUNCTION__);
        }

        for (it = tokenSet.begin(); it != tokenSet.end(); ++it)
        {   
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : NOTICE - Message ts: %d", __FUNCTION__, (*it).timestamp);
            }

            vchShow.resize(8);

            memcpy(&vchShow[0], (*it).sample, 8);

            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : NOTICE - Sample %s\n", __FUNCTION__, ValueString(vchShow).c_str());
            }
        }

        return 1;
    }

    std::string fileName = boost::lexical_cast<std::string>(bucket) + "_01.dat";
    fs::path fullpath = pathSmsgDir / fileName;

    FILE *fp;
    errno = 0;

    if (!(fp = fopen(fullpath.string().c_str(), "ab")))
    {
        return errorN(1, "%s : ERROR - Fopen failed: %s.", __FUNCTION__, strerror(errno));
    }

    // -- on windows ftell will always return 0 after fopen(ab), call fseek to set.
    errno = 0;

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        return errorN(1, "%s : ERROR - Fseek failed: %s.", __FUNCTION__, strerror(errno));
    }

    ofs = ftell(fp);

    if (fwrite(pHeader, sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN
        || fwrite(pPayload, sizeof(uint8_t), nPayload, fp) != nPayload)
    {
        fclose(fp);

        return errorN(1, "%s : ERROR - Fwrite failed: %s.", __FUNCTION__, strerror(errno));
    }

    fclose(fp);

    token.offset = ofs;

    if (fDebug 
        && fDebugSmsg)
    {
        // DEBUG
        LogPrint("smessage", "%s : NOTICE - token.offset: %d \n", __FUNCTION__, token.offset);
    }

    tokenSet.insert(token);

    if (fUpdateBucket)
    {
        smsgBuckets[bucket].hashBucket();
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : OK - SecureMsg added to bucket %d. \n", __FUNCTION__, bucket);
    }

    return 0;
}

int SecureMsgStore(SecureMessage& smsg, bool fUpdateBucket)
{
    return SecureMsgStore(&smsg.hash[0], smsg.pPayload, smsg.nPayload, fUpdateBucket);
}

int SecureMsgValidate(uint8_t *pHeader, uint8_t *pPayload, uint32_t nPayload)
{
    /*
    returns
        0 success
        1 error
        2 invalid hash
        3 checksum mismatch
        4 invalid version
        5 payload is too large
    */
    SecureMessage *psmsg = (SecureMessage*) pHeader;

    if (psmsg->version[0] != 1)
    {
        return 4;
    }

    if (nPayload > SMSG_MAX_MSG_WORST)
    {
        return 5;
    }

    uint8_t civ[32];
    uint8_t sha256Hash[32];
    
    int rv = 2; // invalid

    uint32_t nonse;
    
    memcpy(&nonse, &psmsg->nonse[0], 4);

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - nonse %u. \n", __FUNCTION__, nonse);
    }

    for (int i = 0; i < 32; i+=4)
    {
        memcpy(civ+i, &nonse, 4);
    }

    uint32_t nBytes;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    if (!HMAC_Init_ex(&ctx, &civ[0], 32, EVP_sha256(), NULL)
        || !HMAC_Update(&ctx, (uint8_t*) pHeader+4, SMSG_HDR_LEN-4)
        || !HMAC_Update(&ctx, (uint8_t*) pPayload, nPayload)
        || !HMAC_Update(&ctx, pPayload, nPayload)
        || !HMAC_Final(&ctx, sha256Hash, &nBytes)
        || nBytes != 32)

#else
// OPENSSL 1.1+

    HMAC_CTX *ctx = HMAC_CTX_new();

    if (!HMAC_Init_ex(ctx, &civ[0], 32, EVP_sha256(), NULL)
        || !HMAC_Update(ctx, (uint8_t*) pHeader+4, SMSG_HDR_LEN-4)
        || !HMAC_Update(ctx, (uint8_t*) pPayload, nPayload)
        || !HMAC_Update(ctx, pPayload, nPayload)
        || !HMAC_Final(ctx, sha256Hash, &nBytes)
        || nBytes != 32)
#endif
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - HMAC issue. \n", __FUNCTION__);
        }

        // error
        rv = 1;
    }
    else
    {
        if (sha256Hash[31] == 0 && sha256Hash[30] == 0
            && (~(sha256Hash[29]) & ((1<0)
            || (1<1)
            || (1<2)) ))
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : OK - Hash Valid. \n", __FUNCTION__);
            }

            // smsg is valid
            rv = 0;
        }

        if (memcmp(psmsg->hash, sha256Hash, 4) != 0)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - Checksum mismatch. \n", __FUNCTION__);
            }

            // checksum mismatch
            rv = 3;
        }
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    HMAC_CTX_cleanup(&ctx);

#else
// OPENSSL 1.1+

    HMAC_CTX_free(ctx);

#endif

    return rv;
}


int SecureMsgSetHash(uint8_t *pHeader, uint8_t *pPayload, uint32_t nPayload)
{
    /*  proof of work and checksum

        May run in a thread, if shutdown detected, return.

        returns:
            0 success
            1 error
            2 stopped due to node shutdown

    */

    SecureMessage* psmsg = (SecureMessage*) pHeader;

    int64_t nStart = GetTimeMillis();
    
    uint8_t civ[32];
    uint8_t sha256Hash[32];

    bool found = false;
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

#else
// OPENSSL 1.1+

    HMAC_CTX *ctx = HMAC_CTX_new();

#endif

    uint32_t nonse = 0;

    //CBigNum bnTarget(2);
    //bnTarget = bnTarget.pow(256 - 40);

    // -- break for HMAC_CTX_cleanup
    for (;;)
    {
        if (!fSecMsgEnabled)
        {
           break;
        }

        //psmsg->timestamp = GetTime();
        //memcpy(&psmsg->timestamp, &now, 8);
        memcpy(&psmsg->nonse[0], &nonse, 4);

        for (int i = 0; i < 32; i+=4)
        {
            memcpy(civ+i, &nonse, 4);
        }

        uint32_t nBytes;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

        if (!HMAC_Init_ex(&ctx, &civ[0], 32, EVP_sha256(), NULL)
            || !HMAC_Update(&ctx, (uint8_t*) pHeader+4, SMSG_HDR_LEN-4)
            || !HMAC_Update(&ctx, (uint8_t*) pPayload, nPayload)
            || !HMAC_Update(&ctx, pPayload, nPayload)
            || !HMAC_Final(&ctx, sha256Hash, &nBytes)
            //|| !HMAC_Final(&ctx, &vchHash[0], &nBytes)
            || nBytes != 32)

#else
// OPENSSL 1.1+
        if (!HMAC_Init_ex(ctx, &civ[0], 32, EVP_sha256(), NULL)
            || !HMAC_Update(ctx, (uint8_t*) pHeader+4, SMSG_HDR_LEN-4)
            || !HMAC_Update(ctx, (uint8_t*) pPayload, nPayload)
            || !HMAC_Update(ctx, pPayload, nPayload)
            || !HMAC_Final(ctx, sha256Hash, &nBytes)
            //|| !HMAC_Final(ctx, &vchHash[0], &nBytes)
            || nBytes != 32)
#endif
        {
            break;
        }

        /*
        if (CBigNum(vchHash) <= bnTarget)
        {
            found = true;
            if (fDebugSmsg)
            {
               LogPrint("smessage", "%s : Match %u\n", nonse);
            }
            break;
        }
        */

        //    && sha256Hash[29] == 0)
        if (sha256Hash[31] == 0
            && sha256Hash[30] == 0
            && (~(sha256Hash[29]) & ((1<0)
            || (1<1)
            || (1<2)) ))
        {
            found = true;
            
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : OK - Match %u \n", __FUNCTION__, nonse);
            }

            break;
        }

        //if (nonse >= UINT32_MAX)
        if (nonse >= 4294967295U)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : WARNING - No match %u \n", __FUNCTION__, nonse);
            }

            break;
            //return 1;
        }

        nonse++;

        MilliSleep(5);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L  
// OPENSSL 1.0  

    HMAC_CTX_cleanup(&ctx);

#else
// OPENSSL 1.1+

    HMAC_CTX_free(ctx);

#endif

    if (!fSecMsgEnabled)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : WARNING - Stopped, shutdown detected. \n", __FUNCTION__);
        }

        return 2;
    }

    if (!found)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Failed, took %d ms, nonse %u \n", __FUNCTION__, GetTimeMillis() - nStart, nonse);
        }

        return 1;
    }

    memcpy(psmsg->hash, sha256Hash, 4);
    //memcpy(psmsg->hash, &vchHash[0], 4);

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : OK - Took %d ms, nonse %u \n", __FUNCTION__, GetTimeMillis() - nStart, nonse);
    }

    return 0;
}


int SecureMsgEncrypt(SecureMessage &smsg, const std::string &addressFrom, const std::string &addressTo, const std::string &message)
{
    /* Create a secure message

        Using similar method to bitmessage.
        If bitmessage is secure this should be too.
        https://bitmessage.org/wiki/Encryption

        Some differences:
        bitmessage seems to use curve sect283r1
        *coin addresses use secp256k1

        returns
            2       message is too long.
            3       addressFrom is invalid.
            4       addressTo is invalid.
            5       Could not get public key for addressTo.
            6       ECDH_compute_key failed
            7       Could not get private key for addressFrom.
            8       Could not allocate memory.
            9       Could not compress message data.
            10      Could not generate MAC.
            11      Encrypt failed.
    */

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : ERROR - SecureMsgEncrypt(%s, %s, ...) \n", __FUNCTION__, addressFrom.c_str(), addressTo.c_str());
    }

    if (message.size() > SMSG_MAX_MSG_BYTES)
    {
        return errorN(2, "%s : ERROR - Message is too long, %u.", __FUNCTION__, message.size());
    }

    smsg.version[0] = 1;
    smsg.version[1] = 1;
    smsg.timestamp = GetTime();

    bool fSendAnonymous;

    CCoinAddress coinAddrFrom;
    CKeyID ckidFrom;
    CKey keyFrom;

    if (addressFrom.compare("anon") == 0)
    {
        fSendAnonymous = true;

    }
    else
    {
        fSendAnonymous = false;

        if (!coinAddrFrom.SetString(addressFrom))
        {
            return errorN(3, "%s : ERROR - AddressFrom is not valid.", __FUNCTION__);
        }

        if (!coinAddrFrom.GetKeyID(ckidFrom))
        {
            return errorN(4, "%s : ERROR - CoinAddrFrom.GetKeyID failed: %s.", __FUNCTION__, coinAddrFrom.ToString().c_str());
        }
    }

    CCoinAddress coinAddrDest;
    CKeyID ckidDest;

    if (!coinAddrDest.SetString(addressTo))
    {
        return errorN(4, "%s : ERROR - AddressTo is not valid.", __FUNCTION__);
    }

    if (!coinAddrDest.GetKeyID(ckidDest))
    {
        return errorN(4, "%s : ERROR - CoinAddrDest.GetKeyID failed: %s.", __FUNCTION__, coinAddrDest.ToString().c_str());
    }

    // -- public key K is the destination address
    CPubKey cpkDestK;

    if (SecureMsgGetStoredKey(ckidDest, cpkDestK) != 0
        && SecureMsgGetLocalKey(ckidDest, cpkDestK) != 0) // maybe it's a local key (outbox?)
    {
        return errorN(5, "%s : ERROR - Could not get public key for destination address.", __FUNCTION__);
    }

    // -- Generate 16 random bytes as IV.
    RandAddSeedPerfmon();
    RAND_bytes(&smsg.iv[0], 16);

    // -- Generate a new random EC key pair with private key called r and public key called R.
    CKey keyR;
    keyR.MakeNewKey(true); // make compressed key

    CECKey ecKeyR;
    ecKeyR.SetSecretBytes(keyR.begin());
    
    // -- Do an EC point multiply with public key K and private key r. This gives you public key P.
    CECKey ecKeyK;

    if (!ecKeyK.SetPubKey(cpkDestK.begin(), cpkDestK.size()))
    {
        // address to is invalid
        return errorN(4, "%s : ERROR - Could not set pubkey for K: %s.", __FUNCTION__, HexStr(cpkDestK).c_str());
    }

    std::vector<uint8_t> vchP;
    vchP.resize(32);
    EC_KEY *pkeyr = ecKeyR.GetECKey();
    EC_KEY *pkeyK = ecKeyK.GetECKey();

    // always seems to be 32, worth checking?
    //int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pkeyr));
    //int secret_len = (field_size+7)/8;
    /* ERROR (compile)
    if (fDebug)
    {
        LogPrint("smessage", "%s : secret_len %d.\n", secret_len);
    }
    */

    // -- ECDH_compute_key returns the same P if fed compressed or uncompressed public keys

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    ECDH_set_method(pkeyr, ECDH_OpenSSL());

#else
// OPENSSL 1.1+

    EC_KEY_set_method(pkeyr, EC_KEY_OpenSSL());

#endif
    
    int lenP = ECDH_compute_key(&vchP[0], 32, EC_KEY_get0_public_key(pkeyK), pkeyr, NULL);

    if (lenP != 32)
    {
        return errorN(6, "%s : ERROR - ECDH_compute_key failed, lenP: %d.", __FUNCTION__, lenP);
    }

    CPubKey cpkR = keyR.GetPubKey();
    
    if (!cpkR.IsValid()
        || !cpkR.IsCompressed())
    {
        return errorN(1, "%s : ERROR - Could not get public key for key R.", __FUNCTION__);
    }

    memcpy(smsg.cpkR, cpkR.begin(), 33);
    
    // -- Use public key P and calculate the SHA512 hash H.
    //    The first 32 bytes of H are called key_e and the last 32 bytes are called key_m.
    std::vector<uint8_t> vchHashed;
    
    vchHashed.resize(64); // 512
    
    SHA512(&vchP[0], vchP.size(), (uint8_t*)&vchHashed[0]);
    
    std::vector<uint8_t> key_e(&vchHashed[0], &vchHashed[0]+32);
    std::vector<uint8_t> key_m(&vchHashed[32], &vchHashed[32]+32);

    std::vector<uint8_t> vchPayload;
    std::vector<uint8_t> vchCompressed;
    
    uint8_t *pMsgData;
    uint32_t lenMsgData;
    uint32_t lenMsg = message.size();
    
    if (lenMsg > 128)
    {
        // -- only compress if over 128 bytes
        int worstCase = LZ4_compressBound(message.size());
        
        try
        {
            vchCompressed.resize(worstCase);
        }
        catch (std::exception& e)
        {
            return errorN(8, "%s : ERROR - vchCompressed.resize %u threw: %s.", __FUNCTION__, worstCase, e.what());
        }

        int lenComp = LZ4_compress((char*)message.c_str(), (char*)&vchCompressed[0], lenMsg);
        
        if (lenComp < 1)
        {
            return errorN(9, "%s : ERROR - Could not compress message data.", __FUNCTION__);
        }

        pMsgData = &vchCompressed[0];
        lenMsgData = lenComp;

    }
    else
    {
        // -- no compression
        pMsgData = (uint8_t*)message.c_str();
        lenMsgData = lenMsg;
    }

    if (fSendAnonymous)
    {
        try
        {
            vchPayload.resize(9 + lenMsgData);
        }
        catch (std::exception& e)
        {
            return errorN(8, "%s: ERROR - vchPayload.resize %u threw: %s.", __func__, 9 + lenMsgData, e.what());
        }

        memcpy(&vchPayload[9], pMsgData, lenMsgData);

        vchPayload[0] = 250; // id as anonymous message

        // -- next 4 bytes are unused - there to ensure encrypted payload always > 8 bytes
        // length of uncompressed plain text
        memcpy(&vchPayload[5], &lenMsg, 4); 
    }
    else
    {
        try
        {
            vchPayload.resize(SMSG_PL_HDR_LEN + lenMsgData);
        } 
        catch (std::exception& e)
        {
            return errorN(8, "%s: ERROR - vchPayload.resize %u threw: %s.", __func__, SMSG_PL_HDR_LEN + lenMsgData, e.what());
        }
        
        memcpy(&vchPayload[SMSG_PL_HDR_LEN], pMsgData, lenMsgData);
        
        // -- compact signature proves ownership of from address and allows the public key to be recovered, recipient can always reply.
        if (!pwalletMain->GetKey(ckidFrom, keyFrom))
        {
            return errorN(7, "%s: ERROR - Could not get private key for addressFrom.", __func__);
        }

        // -- sign the plaintext
        std::vector<uint8_t> vchSignature;
        vchSignature.resize(65);
        keyFrom.SignCompact(Hash(message.begin(), message.end()), vchSignature);

        // -- Save some bytes by sending address raw
        vchPayload[0] = (static_cast<CCoinAddress_B*>(&coinAddrFrom))->getVersion();
        // vchPayload[0] = coinAddrDest.nVersion;
        
        memcpy(&vchPayload[1], (static_cast<CKeyID_B*>(&ckidFrom))->GetPPN(), 20);
        // memcpy(&vchPayload[1], ckidDest.pn, 20);

        memcpy(&vchPayload[1+20], &vchSignature[0], vchSignature.size());

        // length of uncompressed plain text
        memcpy(&vchPayload[1+20+65], &lenMsg, 4);
    }

    SecMsgCrypter crypter;

    crypter.SetKey(key_e, smsg.iv);

    std::vector<uint8_t> vchCiphertext;

    if (!crypter.Encrypt(&vchPayload[0], vchPayload.size(), vchCiphertext))
    {
        return errorN(11, "%s : ERROR - crypter.Encrypt failed.", __FUNCTION__);
    }

    try
    {
        smsg.pPayload = new uint8_t[vchCiphertext.size()];
    }
    catch (std::exception& e)
    {
        return errorN(8, "%s : ERROR - Could not allocate pPayload, exception: %s.", __FUNCTION__, e.what());
    }

    memcpy(smsg.pPayload, &vchCiphertext[0], vchCiphertext.size());

    smsg.nPayload = vchCiphertext.size();

    // -- Calculate a 32 byte MAC with HMACSHA256, using key_m as salt
    //    Message authentication code, (hash of timestamp + destination + payload)
    bool fHmacOk = true;
   
    uint32_t nBytes = 32;
   
#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    if (!HMAC_Init_ex(&ctx, &key_m[0], 32, EVP_sha256(), NULL)
        || !HMAC_Update(&ctx, (uint8_t*) &smsg.timestamp, sizeof(smsg.timestamp))
        || !HMAC_Update(&ctx, &vchCiphertext[0], vchCiphertext.size())
        || !HMAC_Final(&ctx, smsg.mac, &nBytes)
        || nBytes != 32)
    {
        fHmacOk = false;
    }

    HMAC_CTX_cleanup(&ctx);

#else
// OPENSSL 1.1+

    HMAC_CTX *ctx = HMAC_CTX_new();

    if (!HMAC_Init_ex(ctx, &key_m[0], 32, EVP_sha256(), NULL)
        || !HMAC_Update(ctx, (uint8_t*) &smsg.timestamp, sizeof(smsg.timestamp))
        || !HMAC_Update(ctx, &vchCiphertext[0], vchCiphertext.size())
        || !HMAC_Final(ctx, smsg.mac, &nBytes)
        || nBytes != 32)
    {
        fHmacOk = false;
    }

    HMAC_CTX_free(ctx);

#endif

    if (!fHmacOk)
    {
        return errorN(10, "%s : ERROR - Could not generate MAC.", __FUNCTION__);
    }

    return 0;
}


int SecureMsgSend(std::string &addressFrom, std::string &addressTo, std::string &message, std::string &sError)
{
    /* Encrypt secure message, and place it on the network
        Make a copy of the message to sender's first address and place in send queue db
        proof of work thread will pick up messages from  send queue db

    */

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - SecureMsgSend(%s, %s, %s) \n", __FUNCTION__, addressFrom.c_str(), addressTo.c_str(), message.c_str());
    }

    if (pwalletMain->IsLocked())
    {
        sError = "Wallet is locked, wallet must be unlocked to send and recieve messages.";
      
        if (fDebug
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Wallet is locked, wallet must be unlocked to send and recieve messages.\n", __FUNCTION__);
        }

        return 1;
    }

    if (message.size() > SMSG_MAX_MSG_BYTES)
    {
        std::ostringstream oss;
        
        oss << message.size() << " > " << SMSG_MAX_MSG_BYTES;
        
        sError = "Message is too long, " + oss.str();
        
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - Message is too long, %u. \n", __FUNCTION__, message.size());
        }

        return 1;
    }

    int rv;
    SecureMessage smsg;

    if ((rv = SecureMsgEncrypt(smsg, addressFrom, addressTo, message)) != 0)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - SecureMsgSend(), encrypt for recipient failed. \n", __FUNCTION__);
        }

        switch(rv)
        {
            case 2:
            {
                sError = "Message is too long.";
            }
            break;
            
            case 3:
            {
                sError = "Invalid addressFrom.";
            } 
            break;
            
            case 4:
            {
                sError = "Invalid addressTo.";
            }
            break;
            
            case 5:
            {
                sError = "Could not get public key for addressTo.";
            }
            break;
            
            case 6:
            {
                sError = "ECDH_compute_key failed.";
            }
            break;
            
            case 7:
            {
                sError = "Could not get private key for addressFrom.";
            }
            break;
            
            case 8:
            {
                sError = "Could not allocate memory.";
            }
            break;
            
            case 9:
            {
                sError = "Could not compress message data.";
            }
            break;
            
            case 10:
            {
                sError = "Could not generate MAC.";
            }
            break;
            
            case 11:
            {
                sError = "Encrypt failed.";
            }
            break;
            
            default:
            {
                sError = "Unspecified Error."; 
            }
            break;
        }

        return rv;
    }

    // -- Place message in send queue, proof of work will happen in a thread.
    std::string sPrefix("qm");
    
    uint8_t chKey[18];
    
    memcpy(&chKey[0],  sPrefix.data(),  2);
    memcpy(&chKey[2],  &smsg.timestamp, 8);
    memcpy(&chKey[10], &smsg.pPayload,  8);

    SecMsgStored smsgSQ;

    smsgSQ.timeReceived  = GetTime();
    smsgSQ.sAddrTo       = addressTo;

    try
    {
        smsgSQ.vchMessage.resize(SMSG_HDR_LEN + smsg.nPayload);
    }
    catch (std::exception& e)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : ERROR - SmsgSQ.vchMessage.resize %u threw: %s. \n", __FUNCTION__, SMSG_HDR_LEN + smsg.nPayload, e.what());
        }

        sError = "Could not allocate memory.";
    
        return 8;
    }

    memcpy(&smsgSQ.vchMessage[0], &smsg.hash[0], SMSG_HDR_LEN);
    memcpy(&smsgSQ.vchMessage[SMSG_HDR_LEN], smsg.pPayload, smsg.nPayload);

    // Global Namespace Start
    {
        LOCK(cs_smsgDB);

        SecMsgDB dbSendQueue;

        if (dbSendQueue.Open("cw"))
        {
            dbSendQueue.WriteSmesg(chKey, smsgSQ);
            //NotifySecMsgSendQueueChanged(smsgOutbox);
        }
    }
    // Global Namespace End
    // cs_smsgDB

    // TODO: only update outbox when proof of work thread is done.

    //  -- for outbox create a copy encrypted for owned address
    //     if the wallet is encrypted private key needed to decrypt will be unavailable

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : WARNING - Encrypting message for outbox. \n", __FUNCTION__);
    }

    std::string addressOutbox = "None";

    CCoinAddress coinAddrOutbox;

    for(const PAIRTYPE(CTxDestination, std::string)& entry: pwalletMain->mapAddressBook)
    {
        // -- get first owned address
        if (!IsMine(*pwalletMain, entry.first))
        {
            continue;
        }

        const CCoinAddress& address = entry.first;

        addressOutbox = address.ToString();

        if (!coinAddrOutbox.SetString(addressOutbox))
        {
            // test valid
            continue;
        } 

        break;
    }

    if (addressOutbox == "None")
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : WARNING - SecureMsgSend() could not find an address to encrypt outbox message with. \n", __FUNCTION__);
        }
    }
    else
    {
        if (fDebug 
            && fDebugSmsg)
        {
            LogPrint("smessage", "%s : OK - Encrypting a copy for outbox, using address %s \n", __FUNCTION__, addressOutbox.c_str());
        }

        SecureMessage smsgForOutbox;

        if ((rv = SecureMsgEncrypt(smsgForOutbox, addressFrom, addressOutbox, message)) != 0)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - SecureMsgSend(), encrypt for outbox failed, %d. \n", __FUNCTION__, rv);
            }
        } 
        else
        {
            // -- save sent message to db
            std::string sPrefix("sm");
            
            uint8_t chKey[18];
            
            memcpy(&chKey[0],  sPrefix.data(),           2);
            memcpy(&chKey[2],  &smsgForOutbox.timestamp, 8);
            memcpy(&chKey[10], &smsgForOutbox.pPayload,  8);   // sample

            SecMsgStored smsgOutbox;

            smsgOutbox.timeReceived  = GetTime();
            smsgOutbox.sAddrTo       = addressTo;
            smsgOutbox.sAddrOutbox   = addressOutbox;

            try
            {
                smsgOutbox.vchMessage.resize(SMSG_HDR_LEN + smsgForOutbox.nPayload);
            }
            catch (std::exception& e)
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : ERROR - SmsgOutbox.vchMessage.resize %u threw: %s. \n", __FUNCTION__, SMSG_HDR_LEN + smsgForOutbox.nPayload, e.what());
                }

                sError = "Could not allocate memory.";
            
                return 8;
            }

            memcpy(&smsgOutbox.vchMessage[0], &smsgForOutbox.hash[0], SMSG_HDR_LEN);
            memcpy(&smsgOutbox.vchMessage[SMSG_HDR_LEN], smsgForOutbox.pPayload, smsgForOutbox.nPayload);

            // Global Namespace Start
            {
                LOCK(cs_smsgDB);
                
                SecMsgDB dbSent;

                if (dbSent.Open("cw"))
                {
                    dbSent.WriteSmesg(chKey, smsgOutbox);

                    NotifySecMsgOutboxChanged(smsgOutbox);
                }
            }
            // Global Namespace End
            // cs_smsgDB
        }
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : OK - Secure message queued for sending to %s. \n", __FUNCTION__, addressTo.c_str());
    }

    return 0;
}


int SecureMsgDecrypt(bool fTestOnly, std::string &address, uint8_t *pHeader, uint8_t *pPayload, uint32_t nPayload, MessageData &msg)
{
    /* Decrypt secure message

        address is the owned address to decrypt with.

        validate first in SecureMsgValidate

        returns
            1       Error
            2       Unknown version number
            3       Decrypt address is not valid.
            8       Could not allocate memory
    */

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : NOTICE - Using %s, testonly %d. \n", __FUNCTION__, address.c_str(), fTestOnly);
    }

    if (!pHeader
        || !pPayload)
    {
        return errorN(1, "%s : ERROR - Null pointer to header or payload.", __FUNCTION__);
    }

    SecureMessage* psmsg = (SecureMessage*) pHeader;

    if (psmsg->version[0] != 1)
    {
        return errorN(2, "%s : ERROR - Unknown version number.", __FUNCTION__);
    }

    // -- Fetch private key k, used to decrypt
    CCoinAddress coinAddrDest;
    CKeyID ckidDest;
    CKey keyDest;
    
    if (!coinAddrDest.SetString(address))
    {
        return errorN(3, "%s : ERROR - Address is not valid.", __FUNCTION__);
    }

    if (!coinAddrDest.GetKeyID(ckidDest))
    {
        return errorN(3, "%s : ERROR - CoinAddrDest.GetKeyID failed: %s.", __FUNCTION__, coinAddrDest.ToString().c_str());
    }

    if (!pwalletMain->GetKey(ckidDest, keyDest))
    {
        return errorN(3, "%s : ERROR - Could not get private key for addressDest.", __FUNCTION__);
    }

    CPubKey cpkR(psmsg->cpkR, psmsg->cpkR+33);

    if (!cpkR.IsValid())
    {
        return errorN(1, "%s : ERROR - Could not get pubkey for key R.", __FUNCTION__);
    }

    CECKey ecKeyR;
    
    if (!ecKeyR.SetPubKey(cpkR.begin(), cpkR.size()))
    {
        return errorN(1, "%s : ERROR - Could not set pubkey for key R: %s.", __FUNCTION__, HexStr(cpkR).c_str());
    }

    CECKey ecKeyDest;
    ecKeyDest.SetSecretBytes(keyDest.begin());
    
    // -- Do an EC point multiply with private key k and public key R. This gives you public key P.
    std::vector<uint8_t> vchP;
    
    vchP.resize(32);
    
    EC_KEY* pkeyk = ecKeyDest.GetECKey();
    EC_KEY* pkeyR = ecKeyR.GetECKey();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    ECDH_set_method(pkeyk, ECDH_OpenSSL());

#else
//OPENSSL 1.1+

    EC_KEY_set_method(pkeyk, EC_KEY_OpenSSL());

#endif    

    int lenPdec = ECDH_compute_key(&vchP[0], 32, EC_KEY_get0_public_key(pkeyR), pkeyk, NULL);

    if (lenPdec != 32)
    {
        return errorN(1, "%s : ERROR - ECDH_compute_key failed, lenPdec: %d.", __FUNCTION__, lenPdec);
    }

    // -- Use public key P to calculate the SHA512 hash H.
    //    The first 32 bytes of H are called key_e and the last 32 bytes are called key_m.
    std::vector<uint8_t> vchHashedDec;

    // 512 bits
    vchHashedDec.resize(64);

    SHA512(&vchP[0], vchP.size(), (uint8_t*)&vchHashedDec[0]);

    std::vector<uint8_t> key_e(&vchHashedDec[0], &vchHashedDec[0]+32);
    std::vector<uint8_t> key_m(&vchHashedDec[32], &vchHashedDec[32]+32);

    // -- Message authentication code, (hash of timestamp + destination + payload)
    uint8_t MAC[32];
    
    bool fHmacOk = true;
    
    uint32_t nBytes = 32;
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    if (!HMAC_Init_ex(&ctx, &key_m[0], 32, EVP_sha256(), NULL)
	|| !HMAC_Update(&ctx, (uint8_t*) &psmsg->timestamp, sizeof(psmsg->timestamp))
	|| !HMAC_Update(&ctx, pPayload, nPayload)
	|| !HMAC_Final(&ctx, MAC, &nBytes)
	|| nBytes != 32)
	{
		fHmacOk = false;
	}
	
	HMAC_CTX_cleanup(&ctx);

#else
// OPENSSL 1.1+

    HMAC_CTX *ctx = HMAC_CTX_new();

    if (!HMAC_Init_ex(ctx, &key_m[0], 32, EVP_sha256(), NULL)
        || !HMAC_Update(ctx, (uint8_t*) &psmsg->timestamp, sizeof(psmsg->timestamp))
        || !HMAC_Update(ctx, pPayload, nPayload)
        || !HMAC_Final(ctx, MAC, &nBytes)
        || nBytes != 32)
    {
        fHmacOk = false;
    }

	HMAC_CTX_free(ctx);
#endif

    if (!fHmacOk)
    {
        return errorN(1, "%s : ERROR - Could not generate MAC.", __FUNCTION__);
    }

    if (memcmp(MAC, psmsg->mac, 32) != 0)
    {
        if (fDebug 
            && fDebugSmsg)
        {
            // expected if message is not to address on node
            LogPrint("smessage", "%s : ERROR - MAC does not match. \n", __FUNCTION__);
        }

        return 1;
    }

    if (fTestOnly)
    {
        return 0;
    }

    SecMsgCrypter crypter;
    
    crypter.SetKey(key_e, psmsg->iv);
    
    std::vector<uint8_t> vchPayload;
    
    if (!crypter.Decrypt(pPayload, nPayload, vchPayload))
    {
        return errorN(1, "%s : ERROR - Decrypt failed.", __FUNCTION__);
    }

    msg.timestamp = psmsg->timestamp;
    
    uint32_t lenData;
    uint32_t lenPlain;

    uint8_t* pMsgData;
    
    bool fFromAnonymous;
    
    if ((uint32_t)vchPayload[0] == 250)
    {
        fFromAnonymous = true;
        lenData = vchPayload.size() - (9);

        memcpy(&lenPlain, &vchPayload[5], 4);

        pMsgData = &vchPayload[9];
    }
    else
    {
        fFromAnonymous = false;
        lenData = vchPayload.size() - (SMSG_PL_HDR_LEN);

        memcpy(&lenPlain, &vchPayload[1+20+65], 4);

        pMsgData = &vchPayload[SMSG_PL_HDR_LEN];
    }

    try
    {
        msg.vchMessage.resize(lenPlain + 1);
    }
    catch (std::exception& e)
    {
        return errorN(8, "%s : ERROR - msg.vchMessage.resize %u threw: %s.", __FUNCTION__, lenPlain + 1, e.what());
    }

    if (lenPlain > 128)
    {
        // -- decompress
        if (LZ4_decompress_safe((char*) pMsgData, (char*) &msg.vchMessage[0], lenData, lenPlain) != (int) lenPlain)
        {
            return errorN(1, "%s : ERROR - Could not decompress message data.", __FUNCTION__);
        }
    }
    else
    {
        // -- plaintext
        memcpy(&msg.vchMessage[0], pMsgData, lenPlain);
    }

    msg.vchMessage[lenPlain] = '\0';

    if (fFromAnonymous)
    {
        // -- Anonymous sender
        msg.sFromAddress = "anon";
    }
    else
    {
        std::vector<uint8_t> vchUint160;
        vchUint160.resize(20);

        memcpy(&vchUint160[0], &vchPayload[1], 20);

        uint160 ui160(vchUint160);
        CKeyID ckidFrom(ui160);
        CCoinAddress coinAddrFrom;
        coinAddrFrom.Set(ckidFrom);
        
        if (!coinAddrFrom.IsValid())
        {
            return errorN(1, "%s : ERROR - From Address is invalid.", __FUNCTION__);
        }

        std::vector<uint8_t> vchSig;
        vchSig.resize(65);

        memcpy(&vchSig[0], &vchPayload[1+20], 65);

        CPubKey cpkFromSig;
        cpkFromSig.RecoverCompact(Hash(msg.vchMessage.begin(), msg.vchMessage.end()-1), vchSig);
        
        if (!cpkFromSig.IsValid())
        {
            return errorN(1, "%s : ERROR - Signature validation failed.", __FUNCTION__);
        }

        // -- get address for the compressed public key
        CCoinAddress coinAddrFromSig;
        coinAddrFromSig.Set(cpkFromSig.GetID());

        if (!(coinAddrFrom == coinAddrFromSig))
        {
            return errorN(1, "%s : ERROR - Signature validation failed.", __FUNCTION__);
        }

        int rv = 5;
        
        try
        {
            rv = SecureMsgInsertAddress(ckidFrom, cpkFromSig);
        }
        catch (std::exception& e)
        {
            if (fDebug 
                && fDebugSmsg)
            {
                LogPrint("smessage", "%s : ERROR - SecureMsgInsertAddress(), exception: %s. \n", __FUNCTION__, e.what());
            }

            //return 1;
        }

        switch(rv)
        {
            case 0:
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : OK - Sender public key added to db. \n", __FUNCTION__);
                }
            }
            break;

            case 4:
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : OK - Sender public key already in db. \n", __FUNCTION__);
                }
            }
            break;

            default:
            {
                if (fDebug 
                    && fDebugSmsg)
                {
                    LogPrint("smessage", "%s : OK - Adding sender public key to db. \n", __FUNCTION__);
                }
            }
            break;
        }

        msg.sFromAddress = coinAddrFrom.ToString();
    }

    if (fDebug 
        && fDebugSmsg)
    {
        LogPrint("smessage", "%s : OK - Decrypted message for %s. \n", __FUNCTION__, address.c_str());
    }

    return 0;
}


int SecureMsgDecrypt(bool fTestOnly, std::string &address, SecureMessage &smsg, MessageData &msg)
{
    return SecureMsgDecrypt(fTestOnly, address, &smsg.hash[0], smsg.pPayload, smsg.nPayload, msg);
}

