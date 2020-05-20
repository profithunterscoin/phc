// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "core.h"
#include "bignum.h"
#include "sync.h"
#include "txmempool.h"
#include "net.h"
#include "script.h"
#include "scrypt.h"
#include "uint256.h"
#include <list>
#include <iostream>
#include <string>
#include <sstream>

class CValidationState;

//GMT: Sunday, December 17, 2017 5:03:12 AM
#define START_MASTERNODE_PAYMENTS_TESTNET 1513486992

//GMT: Monday, January 15, 2018 7:37:20 AM
#define START_MASTERNODE_PAYMENTS 1516001840 

static const int64_t DARKSEND_COLLATERAL = (10*COIN);
static const int64_t DARKSEND_POOL_MAX = (49.99*COIN);

//Constant reward of 10 PHC per COIN i.e. 8%
//static const int64_t STATIC_POS_REWARD = 1000 * COIN;

static const int64_t TARGET_SPACING = 60; //60 sec

#define INSTANTX_SIGNATURES_REQUIRED           10
#define INSTANTX_SIGNATURES_TOTAL              15

class CBlock;
class CBlockIndex;
class CInv;
class CKeyItem;
class CNode;
class CReserveKey;
class CWallet;

/** The maximum allowed size for a serialized block, in bytes (network rule) 30 MB default */
static const unsigned int MAX_BLOCK_SIZE = 30000000;

/** The maximum size for mined blocks */
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;

/** Default for -blockprioritysize, maximum space for zero/low-fee transactions **/
static const unsigned int DEFAULT_BLOCK_PRIORITY_SIZE = 50000;

/** The maximum size for transactions we're willing to relay/mine **/
static const unsigned int MAX_STANDARD_TX_SIZE = MAX_BLOCK_SIZE_GEN/5;

/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;

/** Maxiumum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;

/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const unsigned int MAX_TX_SIGOPS = MAX_BLOCK_SIGOPS/5;

/** The maximum number of orphan transactions kept in memory */
static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100;

/** Default for -maxorphanblocks, maximum number of orphan blocks kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_BLOCKS = 6;

/** Fees smaller than this (in satoshi) are considered zero fee (for transaction creation) */
static const int64_t MIN_TX_FEE = 1000;

/** Fees smaller than this (in satoshi) are considered zero fee (for relaying) */
static const int64_t MIN_RELAY_TX_FEE = MIN_TX_FEE;

/** No amount larger than this (in satoshi) is valid (100 Million coins) */
static const int64_t MAX_MONEY = 100000000 * COIN;

/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached its tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;

inline bool MoneyRange(int64_t nValue)
{
    return (nValue >= 0
        && nValue <= MAX_MONEY);
}

/** Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp. */
// Tue Nov  5 00:53:20 1985 UTC
static const unsigned int LOCKTIME_THRESHOLD = 500000000;

// 5 minutes drift into the future
static const int64_t DRIFT = 5 * 60; 
inline int64_t FutureDrift(int64_t nTime)
{ 
    return nTime + DRIFT;
}

static const int64_t COIN_YEAR_REWARD = 1000 * CENT;

/** "reject" message codes **/
static const unsigned char REJECT_INVALID = 0x10;

inline int64_t GetMNCollateral(int nHeight)
{
    return 10000;
}

extern int64_t TURBOSYNC_MAX;

// Dynamic Checkpoints Interval (1 minute)
static const int64_t DYNAMICCHECKPOINTS_INTERVAL = 60;  

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern CTxMemPool mempool;
extern std::map<uint256, CBlockIndex*> mapBlockIndex;
extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
extern CBlockIndex* pindexGenesisBlock;
extern int nStakeMinConfirmations;
extern unsigned int nStakeMinAge;
extern unsigned int nNodeLifespan;
extern int nCoinbaseMaturity;
extern int nBestHeight;
extern uint256 nBestChainTrust;
extern uint256 nBestInvalidTrust;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockSize;
extern int64_t nLastCoinStakeSearchInterval;
extern const std::string strMessageMagic;
extern double dHashesPerSec;
extern int64_t nHPSTimerStart;
extern int64_t nTimeBestReceived;
extern bool fImporting;
extern bool fReindex;
struct COrphanBlock;
extern std::map<uint256, COrphanBlock*> mapOrphanBlocks;
extern bool fHaveGUI;

// Settings
extern bool fUseFastIndex;
extern unsigned int nDerivationMethodIndex;

extern bool fLargeWorkForkFound;
extern bool fLargeWorkInvalidChainFound;

// Minimum disk space required - used in CheckDiskSpace()
static const uint64_t nMinDiskSpace = 52428800;

class CReserveKey;
class CTxDB;
class CTxIndex;
class CWalletInterface;

struct CNodeStateStats {
    int nMisbehavior;
    int nSyncHeight;
    int nCommonHeight;
    std::vector<int> vHeightInFlight;
};


//////////////////////////////////////////////////////////////////////////////
//
// CChain
//

namespace CChain
{

    /** Backtoblock X Blockchain Index*/
    int Backtoblock(int nNewHeight);

    /** Rollback Blockchain Index */
    int RollbackChain(int nBlockCount);

    /** Force Random Sync from current Block (Request all connected nodes) */
    int ForceRandomSync(CNode* pfrom, uint256 hashfilter, int maxrandom);

    /** Force Sync from current Block (Request all connected nodes) */
    int ForceSync(CNode* pfrom, uint256 hashfilter);

    /** Force Block Broadcast (Send to all connected nodes) */
    int BlockBroadCast(CBlock* pblock);

    /** Prune Orphan blocks from index */
    void PruneOrphanBlocks();

    /** Reorganize the chain index */
    bool Reorganize(CTxDB& txdb, CBlockIndex* pindexNew);

};


/** Register a wallet to receive updates from core */
void RegisterWallet(CWalletInterface* pwalletIn);

/** Unregister a wallet from core */
void UnregisterWallet(CWalletInterface* pwalletIn);

/** Unregister all wallets from core */
void UnregisterAllWallets();

/** Push an updated transaction to all registered wallets */
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fConnect = true, bool fFixSpentCoins = false);

/** Ask wallets to resend their transactions */
void ResendWalletTransactions(bool fForce = false);

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);

/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);

/** Process an incoming block */
bool ProcessBlock(CNode* pfrom, CBlock* pblock);

/** Check whether enough disk space is available for an incoming block */
bool CheckDiskSpace(uint64_t nAdditionalBytes=0);

/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");

FILE* AppendBlockFile(unsigned int& nFileRet);

/** Load the block tree and coins database from disk */
bool LoadBlockIndex();

/** Load the block tree and coins database from file X on disk */
bool LoadExternalBlockFile(FILE* fileIn);

/** Print the loaded block tree */
void PrintBlockTree();

/** Find a block by height in the currently-connected chain */
CBlockIndex* FindBlockByHeight(int nHeight);

/** Process protocol messages received from a given node */
bool ProcessMessages(CNode* pfrom);

/** Send queued protocol messages to be sent to a give node */
bool SendMessages(CNode* pto, bool fSendTrickle);

void ThreadImport(std::vector<boost::filesystem::path> vImportFiles);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits);

/** Calculate the minimum amount of work a received block needs, without knowing its direct parent */
unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime);

/** Calculate the minimum amount of work a received block needs, without knowing its direct parent */
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake);

void UpdateTime(CBlock& block, const CBlockIndex* pindexPrev);

/** Run the internal miner threads */
void GeneratePoWcoins(bool fGenerate, CWallet* pwallet, bool fDebugConsoleMining);

int64_t GetProofOfWorkReward(int nHeight, int64_t nFees);
int64_t GetProofOfStakeReward(const CBlockIndex* pindexPrev, int64_t nCoinAge, int64_t nFees);

/** Check whether we are doing an initial block download (synchronizing from disk or network) */
bool IsInitialBlockDownload();

bool IsConfirmedInNPrevBlocks(const CTxIndex& txindex, const CBlockIndex* pindexFrom, int nMaxDepth, int& nActualDepth);

/** Format a string that describes several potential problems detected by the core */
std::string GetWarnings(std::string strFor);

/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock);

uint256 WantedByOrphan(const COrphanBlock* pblockOrphan);

const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake);

void ThreadStakeMiner(CWallet *pwallet);

string getDevRewardAddress(int nHeight);

/** (try to) add transaction to memory pool **/
bool AcceptToMemoryPool(CTxMemPool& pool, CTransaction &tx, bool fLimitFree, bool* pfMissingInputs, bool fRejectInsaneFee=false, bool ignoreFees=false, bool fFixSpentCoins=false);

bool AcceptableInputs(CTxMemPool& pool, const CTransaction &txo, bool fLimitFree, bool* pfMissingInputs, bool fRejectInsaneFee=false, bool isDSTX=false);

bool FindTransactionsByDestination(const CTxDestination &dest, std::vector<uint256> &vtxhash);

int GetInputAge(CTxIn& vin);
int GetInputAgeIX(uint256 nTXHash, CTxIn& vin);
int GetIXConfirmations(uint256 nTXHash);

/** Abort with a message */
bool AbortNode(const std::string &msg, const std::string &userMessage="");

/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);

int64_t GetMasternodePayment(int nHeight, int64_t blockValue);

/** Position on disk for a particular transaction. */
class CDiskTxPos
{
    public:

        unsigned int nFile;
        unsigned int nBlockPos;
        unsigned int nTxPos;

        CDiskTxPos()
        {
            SetNull();
        }

        CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
        {
            nFile = nFileIn;
            nBlockPos = nBlockPosIn;
            nTxPos = nTxPosIn;
        }

        IMPLEMENT_SERIALIZE(READWRITE(FLATDATA(*this));)
        void SetNull()
        {
            nFile = (unsigned int) -1; nBlockPos = 0; nTxPos = 0;
        }

        bool IsNull() const
        {
            return (nFile == (unsigned int) -1);
        }

        friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
        {
            return (a.nFile     == b.nFile &&
                    a.nBlockPos == b.nBlockPos &&
                    a.nTxPos    == b.nTxPos);
        }

        friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
        {
            return !(a == b);
        }

        std::string ToString() const
        {
            if (IsNull())
            {
                return "null";
            }
            else
            {
                return strprintf("(nFile=%u, nBlockPos=%u, nTxPos=%u)", nFile, nBlockPos, nTxPos);
            }
        }
};


enum GetMinFee_mode
{
    GMF_BLOCK,
    GMF_RELAY,
    GMF_SEND,
};


typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;

int64_t GetMinFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree, enum GetMinFee_mode mode);


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
    public:

        static const int CURRENT_VERSION=1;

        int nVersion;
        unsigned int nTime;

        std::vector<CTxIn> vin;
        std::vector<CTxOut> vout;

        unsigned int nLockTime;

        // Denial-of-service detection:
        mutable int nDoS;
        bool DoS(int nDoSIn, bool fIn) const
        {
            nDoS += nDoSIn;

            return fIn;
        }

        CTransaction()
        {
            SetNull();
        }

        CTransaction(int nVersion, unsigned int nTime, const std::vector<CTxIn>& vin, const std::vector<CTxOut>& vout, unsigned int nLockTime)
            : nVersion(nVersion), nTime(nTime), vin(vin), vout(vout), nLockTime(nLockTime), nDoS(0)
        {
        }

        IMPLEMENT_SERIALIZE
        (
            READWRITE(this->nVersion);
            nVersion = this->nVersion;
            READWRITE(nTime);
            READWRITE(vin);
            READWRITE(vout);
            READWRITE(nLockTime);
        )

        void SetNull()
        {
            nVersion = CTransaction::CURRENT_VERSION;
            nTime = GetAdjustedTime();
            vin.clear();
            vout.clear();
            nLockTime = 0;
            nDoS = 0;  // Denial-of-service prevention
        }

        bool IsNull() const
        {
            return (vin.empty()
            && vout.empty());
        }

        uint256 GetHash() const
        {
            return SerializeHash(*this);
        }

        bool IsCoinBase() const
        {
            return (vin.size() == 1
                && vin[0].prevout.IsNull()
                && vout.size() >= 1);
        }

        bool IsCoinStake() const
        {
            // ppcoin: the coin stake transaction is marked with the first output empty
            return (vin.size() > 0
                && (!vin[0].prevout.IsNull())
                && vout.size() >= 2
                && vout[0].IsEmpty());
        }

        // Compute priority, given priority of inputs and (optionally) tx size
        double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

        /** Amount of bitcoins spent by this transaction.
            @return sum of all outputs (note: does not include fees)
        */
        int64_t GetValueOut() const
        {
            int64_t nValueOut = 0;

            for(const CTxOut& txout: vout)
            {
                nValueOut += txout.nValue;

                if (!MoneyRange(txout.nValue)
                    || !MoneyRange(nValueOut))
                {
                    throw std::runtime_error(strprintf("%s : value out of range", __FUNCTION__));
                }

            }

            return nValueOut;
        }

        /** Amount of bitcoins coming in to this transaction
            Note that lightweight clients may not know anything besides the hash of previous transactions,
            so may not be able to calculate this.

            @param[in] mapInputs    Map of previous transactions that have outputs we're spending
            @return Sum of value of all inputs (scriptSigs)
            @see CTransaction::FetchInputs
        */
        int64_t GetValueIn(const MapPrevTx& mapInputs) const;

        bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
        {
            CAutoFile filein = CAutoFile(OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);

            if (filein.IsNull())
            {
                return error("%s : OpenBlockFile failed", __FUNCTION__);
            }

            // Read transaction
            if (fseek(filein.Get(), pos.nTxPos, SEEK_SET) != 0)
            {
                return error("%s : fseek failed", __FUNCTION__);
            }

            try
            {
                filein >> *this;
            }
            catch (std::exception &e)
            {
                return error("%s : deserialize or I/O error", __FUNCTION__);
            }

            // Return file pointer
            if (pfileRet)
            {
                if (fseek(filein.Get(), pos.nTxPos, SEEK_SET) != 0)
                {
                    return error("%s : second fseek failed", __FUNCTION__);
                }

                *pfileRet = filein.release();
            }

            return true;
        }

        friend bool operator==(const CTransaction& a, const CTransaction& b)
        {
            return (a.nVersion  == b.nVersion &&
                    a.nTime == b.nTime &&
                    a.vin       == b.vin &&
                    a.vout      == b.vout &&
                    a.nLockTime == b.nLockTime);
        }

        friend bool operator!=(const CTransaction& a, const CTransaction& b)
        {
            return !(a == b);
        }

        std::string ToString() const
        {
            std::string str;
            str += IsCoinBase()? "Coinbase" : (IsCoinStake()? "Coinstake" : "CTransaction");
            str += strprintf("(hash=%s, nTime=%d, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%d)\n",
                GetHash().ToString(), nTime, nVersion, vin.size(), vout.size(), nLockTime);

            for (unsigned int i = 0; i < vin.size(); i++)
            {
                str += "    " + vin[i].ToString() + "\n";

                for (unsigned int i = 0; i < vout.size(); i++)
                {
                    str += "    " + vout[i].ToString() + "\n";
                }
            }

            return str;
        }

        bool ReadFromDisk(CTxDB& txdb, const uint256& hash, CTxIndex& txindexRet);
        bool ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet);
        bool ReadFromDisk(CTxDB& txdb, COutPoint prevout);
        bool ReadFromDisk(COutPoint prevout);
        bool DisconnectInputs(CTxDB& txdb);

        /** Fetch from memory and/or disk. inputsRet keys are transaction hashes.

        @param[in] txdb    Transaction database
        @param[in] mapTestPool List of pending changes to the transaction index database
        @param[in] fBlock  True if being called to add a new best-block to the chain
        @param[in] fMiner  True if being called by CreateNewBlock
        @param[out] inputsRet  Pointers to this transaction's inputs
        @param[out] fInvalid   returns true if transaction is invalid
        @return    Returns true if all inputs are in txdb or mapTestPool
        */
        bool FetchInputs(CTxDB& txdb, const std::map<uint256, CTxIndex>& mapTestPool, bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid);

        /** Sanity check previous transactions, then, if all checks succeed,
            mark them as spent by this transaction.

            @param[in] inputs   Previous transactions (from FetchInputs)
            @param[out] mapTestPool Keeps track of inputs that need to be updated on disk
            @param[in] posThisTx    Position of this transaction on disk
            @param[in] pindexBlock
            @param[in] fBlock   true if called from ConnectBlock
            @param[in] fMiner   true if called from CreateNewBlock
            @return Returns true if all checks succeed
        */
        bool ConnectInputs(CTxDB& txdb, MapPrevTx inputs, std::map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS, bool fValidateSig = true);
        bool CheckTransaction() const;
        bool GetCoinAge(CTxDB& txdb, const CBlockIndex* pindexPrev, uint64_t& nCoinAge) const;

        const CTxOut& GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const;
};


/** wrapper for CTxOut that provides a more compact serialization */
class CTxOutCompressor
{
    private:

        CTxOut &txout;
    
    public:

        CTxOutCompressor(CTxOut &txoutIn) : txout(txoutIn)
        {
        }

        IMPLEMENT_SERIALIZE(
            READWRITE(VARINT(txout.nValue));
            CScriptCompressor cscript(REF(txout.scriptPubKey));
            READWRITE(cscript);
        )
};


/** Check for standard transaction types
    @param[in] mapInputs    Map of previous transactions that have outputs we're spending
    @return True if all inputs (scriptSigs) use only standard transaction forms
    @see CTransaction::FetchInputs
*/
bool AreInputsStandard(const CTransaction& tx, const MapPrevTx& mapInputs);

/** Count ECDSA signature operations the old-fashioned (pre-0.6) way
    @return number of sigops this transaction's outputs will produce when spent
    @see CTransaction::FetchInputs
*/
unsigned int GetLegacySigOpCount(const CTransaction& tx);

/** Count ECDSA signature operations in pay-to-script-hash inputs.

    @param[in] mapInputs    Map of previous transactions that have outputs we're spending
    @return maximum number of sigops required to validate this transaction's inputs
    @see CTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const MapPrevTx& mapInputs);

inline bool AllowFree(double dPriority)
{
    // Large (in bytes) low-priority (new, small-coin) transactions
    // need a fee.
    return dPriority > COIN * 576 / 250;
}

/** Check for standard transaction types
    @return True if all outputs (scriptPubKeys) use only standard transaction forms
*/
bool IsStandardTx(const CTransaction& tx, std::string& reason);

bool IsFinalTx(const CTransaction &tx, int nBlockHeight = 0, int64_t nBlockTime = 0);


/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
    private:

        int GetDepthInMainChainINTERNAL(CBlockIndex* &pindexRet) const;
    
    public:

        uint256 hashBlock;
        std::vector<uint256> vMerkleBranch;
        
        int nIndex;

        // memory only
        mutable bool fMerkleVerified;


        CMerkleTx()
        {
            Init();
        }

        CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
        {
            Init();
        }

        void Init()
        {
            hashBlock = 0;
            nIndex = -1;
            fMerkleVerified = false;
        }


        IMPLEMENT_SERIALIZE
        (
            nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
            nVersion = this->nVersion;
            READWRITE(hashBlock);
            READWRITE(vMerkleBranch);
            READWRITE(nIndex);
        )

        int SetMerkleBranch(const CBlock* pblock=NULL);

        // Return depth of transaction in blockchain:
        // -1  : not in blockchain, and not in memory pool (conflicted transaction)
        //  0  : in memory pool, waiting to be included in a block
        // >=1 : this many blocks deep in the main chain
        int GetDepthInMainChain(CBlockIndex* &pindexRet, bool enableIX=true) const;
        int GetDepthInMainChain(bool enableIX=true) const
        {
            CBlockIndex *pindexRet;

            return GetDepthInMainChain(pindexRet, enableIX);
        }
        bool IsInMainChain() const 
        {
            CBlockIndex *pindexRet;

            return GetDepthInMainChainINTERNAL(pindexRet) > 0;
        }
        int GetBlocksToMaturity() const;
        bool AcceptToMemoryPool(bool fLimitFree=true, bool fRejectInsaneFee=true, bool ignoreFees=false);
        int GetTransactionLockSignatures() const;
        bool IsTransactionLockTimedOut() const;
};


/**  A txdb record that contains the disk location of a transaction and the
 * locations of transactions that spend its outputs.  vSpent is really only
 * used as a flag, but having the location is very helpful for debugging.
 */
class CTxIndex
{
    public:

        CDiskTxPos pos;
        std::vector<CDiskTxPos> vSpent;

        CTxIndex()
        {
            SetNull();
        }

        CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
        {
            pos = posIn;
            vSpent.resize(nOutputs);
        }

        IMPLEMENT_SERIALIZE
        (
            if (!(nType & SER_GETHASH))
            {
                READWRITE(nVersion);
            }

            READWRITE(pos);
            READWRITE(vSpent);
        )

        void SetNull()
        {
            pos.SetNull();
            vSpent.clear();
        }

        bool IsNull()
        {
            return pos.IsNull();
        }

        friend bool operator==(const CTxIndex& a, const CTxIndex& b)
        {
            return (a.pos    == b.pos &&
                    a.vSpent == b.vSpent);
        }

        friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
        {
            return !(a == b);
        }

        int GetDepthInMainChain() const;

};


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 *
 * Blocks are appended to blk0001.dat files on disk.  Their location on disk
 * is indexed by CBlockIndex objects in memory.
 */
class CBlock
{

    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;

    public:

        // header
        static const int CURRENT_VERSION = 7;

        int nVersion;

        uint256 hashPrevBlock;
        uint256 hashMerkleRoot;

        unsigned int nTime;
        unsigned int nBits;
        unsigned int nNonce;

        // network and disk
        std::vector<CTransaction> vtx;

        // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
        std::vector<unsigned char> vchBlockSig;

        // memory only
        mutable std::vector<uint256> vMerkleTree;

        // Denial-of-service detection:
        mutable int nDoS;
        bool DoS(int nDoSIn, bool fIn) const
        {
            nDoS += nDoSIn;
            
            return fIn;
        }

        CBlock()
        {
            SetNull();
        }

        IMPLEMENT_SERIALIZE
        (
            READWRITE(this->nVersion);
            nVersion = this->nVersion;
            READWRITE(hashPrevBlock);
            READWRITE(hashMerkleRoot);
            READWRITE(nTime);
            READWRITE(nBits);
            READWRITE(nNonce);

            // ConnectBlock depends on vtx following header to generate CDiskTxPos
            if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
            {
                READWRITE(vtx);
                READWRITE(vchBlockSig);
            }
            else if (fRead)
            {
                const_cast<CBlock*>(this)->vtx.clear();
                const_cast<CBlock*>(this)->vchBlockSig.clear();
            }
        )

        void SetNull()
        {
            nVersion = CBlock::CURRENT_VERSION;
            hashPrevBlock = 0;
            hashMerkleRoot = 0;
            nTime = 0;
            nBits = 0;
            nNonce = 0;
            vtx.clear();
            vchBlockSig.clear();
            vMerkleTree.clear();
            nDoS = 0;
        }

        bool IsNull() const
        {
            return (nBits == 0);
        }

        int GetVersion() const
        {
            return nVersion;
        }

        uint256 GetHashPrevBlock() const
        {
            return hashPrevBlock;
        }

        uint256 GetHashMerkleRoot() const
        {
            return hashMerkleRoot;
        }

        int GetBits() const
        {
            return nBits;
        }

        int GetNonce() const
        {
            return nNonce;
        }

        uint256 GetHash() const
        {
            return Hash(BEGIN(nVersion), END(nNonce));
        }

        uint256 GetPoWHash() const
        {
            return scrypt_blockhash(CVOIDBEGIN(nVersion));
        }

        int64_t GetBlockTime() const
        {
            return (int64_t)nTime;
        }

        void UpdateTime(const CBlockIndex* pindexPrev);

        // entropy bit for stake modifier if chosen by modifier
        unsigned int GetStakeEntropyBit() const
        {
            // Take last bit of block hash as entropy bit
            unsigned int nEntropyBit = ((GetHash().Get64()) & 1llu);

            if (fDebug)
            {
                LogPrint("stakemodifier", "%s : ERROR - GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u \n", __FUNCTION__, GetHash().ToString(), nEntropyBit);
            }
            
            return nEntropyBit;
        }

        // ppcoin: two types of block: proof-of-work or proof-of-stake
        bool IsProofOfStake() const
        {
            return (vtx.size() > 1 && vtx[1].IsCoinStake());
        }

        bool IsProofOfWork() const
        {
            return !IsProofOfStake();
        }

        std::pair<COutPoint, unsigned int> GetProofOfStake() const
        {
            return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
        }

        // ppcoin: get max transaction timestamp
        int64_t GetMaxTransactionTime() const
        {
            int64_t maxTransactionTime = 0;

            for(const CTransaction& tx: vtx)
            {
                maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.nTime);
            }

            return maxTransactionTime;
        }

        uint256 BuildMerkleTree() const
        {
            vMerkleTree.clear();

            for(const CTransaction& tx: vtx)
            {
                vMerkleTree.push_back(tx.GetHash());
            }

            int j = 0;

            for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
            {
                for (int i = 0; i < nSize; i += 2)
                {
                    int i2 = std::min(i+1, nSize-1);

                    vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]), BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
                }

                j += nSize;
            }

            return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
        }

        std::vector<uint256> GetMerkleBranch(int nIndex) const
        {
            if (vMerkleTree.empty())
            {
                BuildMerkleTree();
            }

            std::vector<uint256> vMerkleBranch;

            int j = 0;

            for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
            {
                int i = std::min(nIndex^1, nSize-1);

                vMerkleBranch.push_back(vMerkleTree[j+i]);

                nIndex >>= 1;

                j += nSize;
            }

            return vMerkleBranch;
        }

        static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
        {
            if (nIndex == -1)
            {
                return 0;
            }

            for(const uint256& otherside: vMerkleBranch)
            {
                if (nIndex & 1)
                {
                    hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
                }
                else
                {
                    hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
                }

                nIndex >>= 1;
            }

            return hash;
        }

        bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
        {
            // Open history file to append
            CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);

            if (fileout.IsNull())
            {
                return error("%s : AppendBlockFile failed", __FUNCTION__);
            }

            // Write index header
            unsigned int nSize = fileout.GetSerializeSize(*this);
            fileout << FLATDATA(Params().MessageStart()) << nSize;

            // Write block
            long fileOutPos = ftell(fileout.Get());

            if (fileOutPos < 0)
            {
                return error("%s : ftell failed", __FUNCTION__);
            }

            nBlockPosRet = fileOutPos;
            fileout << *this;

            // Flush stdio buffers and commit to disk before returning
            fflush(fileout.Get());

            if (!IsInitialBlockDownload()
                || (nBestHeight+1) % 500 == 0)
            {
                FileCommit(fileout.Get());
            }

            return true;
        }

        bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true)
        {
            SetNull();

            // Open history file to read
            CAutoFile filein = CAutoFile(OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, CLIENT_VERSION);

            if (filein.IsNull())
            {
                return error("%s : OpenBlockFile failed", __FUNCTION__);
            }

            if (!fReadTransactions)
            {
                filein.nType |= SER_BLOCKHEADERONLY;
            }

            // Read block
            try
            {
                filein >> *this;
            }
            catch (std::exception &e)
            {
                return error("%s : deserialize or I/O error", __FUNCTION__);
            }

            // Check the header
            if (fReadTransactions
                && IsProofOfWork()
                && !CheckProofOfWork(GetPoWHash(), nBits))
            {
                return error("%s : errors in block header", __FUNCTION__);
            }

            return true;
        }

        std::string ToString() const
        {
            std::stringstream s;
            s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u, vchBlockSig=%s)\n",
                GetHash().ToString(), nVersion, hashPrevBlock.ToString(), hashMerkleRoot.ToString(), nTime, nBits, nNonce, vtx.size(), HexStr(vchBlockSig.begin(), vchBlockSig.end()));

            for (unsigned int i = 0; i < vtx.size(); i++)
            {
                s << "  " << vtx[i].ToString() << "\n";
            }

            s << "  vMerkleTree: ";
            
            for (unsigned int i = 0; i < vMerkleTree.size(); i++)
            {
                s << " " << vMerkleTree[i].ToString();
            }
            
            s << "\n";
            
            return s.str();
        }
        
        bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
        bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck=false);
        bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true);
        bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew);
        bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, const uint256& hashProof);
        bool BlockShield(int Block_nHeight) const;
        bool CheckBlock(bool fCheckPOW=true, bool fCheckMerkleRoot=true, bool fCheckSig=true) const;
        bool AcceptBlock();
        bool SignBlock(CWallet& keystore, int64_t nFees);
        bool CheckBlockSignature() const;
        void RebuildAddressIndex(CTxDB& txdb);

    private:

        bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew);
};


/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 */
class CBlockIndex
{
    public:

        const uint256* phashBlock;
        CBlockIndex* pprev;
        CBlockIndex* pnext;
        unsigned int nFile;
        unsigned int nBlockPos;

        // ppcoin: trust score of block chain
        uint256 nChainTrust;

        int nHeight;
    #ifndef LOWMEM
        int64_t nPOWMint;
        int64_t nPOSMint;
        int64_t nMoneySupply;
    #endif
        // ppcoin: block index flags
        unsigned int nFlags;

        enum
        {
            BLOCK_PROOF_OF_STAKE = (1 << 0), // is proof-of-stake block
            BLOCK_STAKE_ENTROPY  = (1 << 1), // entropy bit for stake modifier
            BLOCK_STAKE_MODIFIER = (1 << 2), // regenerated stake modifier
        };

        // hash modifier for proof-of-stake
        uint64_t nStakeModifier;
    #ifndef LOWMEM
        uint256 bnStakeModifierV2;
    #endif
        // proof-of-stake specific fields
        COutPoint prevoutStake;
        unsigned int nStakeTime;

        uint256 hashProof;

        // block header
        int nVersion;
        uint256 hashMerkleRoot;
        unsigned int nTime;
        unsigned int nBits;
        unsigned int nNonce;

        CBlockIndex()
        {
            phashBlock = NULL;
            pprev = NULL;
            pnext = NULL;
            nFile = 0;
            nBlockPos = 0;
            nHeight = 0;
            nChainTrust = 0;
    #ifndef LOWMEM
            nPOWMint = 0;
            nPOSMint = 0;
            nMoneySupply = 0;
    #endif
            nFlags = 0;
            nStakeModifier = 0;
    #ifndef LOWMEM
            bnStakeModifierV2 = 0;
    #endif
            hashProof = 0;

            prevoutStake.SetNull();
            nStakeTime = 0;

            nVersion       = 0;
            hashMerkleRoot = 0;
            nTime          = 0;
            nBits          = 0;
            nNonce         = 0;
        }

        CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
        {
            phashBlock = NULL;
            pprev = NULL;
            pnext = NULL;
            nFile = nFileIn;
            nBlockPos = nBlockPosIn;
            nHeight = 0;
            nChainTrust = 0;
    #ifndef LOWMEM
            nPOWMint = 0;
            nPOSMint = 0;
            nMoneySupply = 0;
    #endif
            nFlags = 0;
            nStakeModifier = 0;
    #ifndef LOWMEM
            bnStakeModifierV2 = 0;
    #endif
            hashProof = 0;

            if (block.IsProofOfStake())
            {
                SetProofOfStake();

                prevoutStake = block.vtx[1].vin[0].prevout;
                nStakeTime = block.vtx[1].nTime;
            }
            else
            {
                prevoutStake.SetNull();
                nStakeTime = 0;
            }

            nVersion       = block.nVersion;
            hashMerkleRoot = block.hashMerkleRoot;
            nTime          = block.nTime;
            nBits          = block.nBits;
            nNonce         = block.nNonce;
        }

        CBlock GetBlockHeader() const
        {
            CBlock block;

            block.nVersion       = nVersion;

            if (pprev)
            {
                block.hashPrevBlock = pprev->GetBlockHash();
            }

            block.hashMerkleRoot = hashMerkleRoot;
            block.nTime          = nTime;
            block.nBits          = nBits;
            block.nNonce         = nNonce;

            return block;
        }

        CBlock GetBlock() const
        {
            CBlock block;

            block.nVersion       = nVersion;

            if (pprev)
            {
                block.hashPrevBlock = pprev->GetBlockHash();
            }

            block.hashMerkleRoot = hashMerkleRoot;
            block.nTime          = nTime;
            block.nBits          = nBits;
            block.nNonce         = nNonce;

            return block;
        }

        uint256 GetBlockHash() const
        {
            if (phashBlock)
            {
                return *phashBlock;
            }

            return 0;
        }

        int64_t GetBlockTime() const
        {
            return (int64_t)nTime;
        }

        uint256 GetBlockTrust() const;

        bool IsInMainChain() const
        {
            return (pnext
                    || this == pindexBest);
        }

        bool CheckIndex() const
        {
            return true;
        }

        int64_t GetPastTimeLimit() const
        {
            return GetBlockTime() - DRIFT;
        }

        enum { nMedianTimeSpan=11 };

        int64_t GetMedianTimePast() const
        {
            int64_t pmedian[nMedianTimeSpan];
            int64_t* pbegin = &pmedian[nMedianTimeSpan];
            int64_t* pend = &pmedian[nMedianTimeSpan];

            const CBlockIndex* pindex = this;

            for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            {
                *(--pbegin) = pindex->GetBlockTime();
            }

            std::sort(pbegin, pend);

            return pbegin[(pend - pbegin)/2];
        }

        bool IsProofOfWork() const
        {
            return !(nFlags & BLOCK_PROOF_OF_STAKE);
        }

        bool IsProofOfStake() const
        {
            return (nFlags & BLOCK_PROOF_OF_STAKE);
        }

        void SetProofOfStake()
        {
            nFlags |= BLOCK_PROOF_OF_STAKE;
        }

        unsigned int GetStakeEntropyBit() const
        {
            return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
        }

        bool SetStakeEntropyBit(unsigned int nEntropyBit)
        {
            if (nEntropyBit > 1)
            {
                return false;
            }

            nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);

            return true;
        }

        bool GeneratedStakeModifier() const
        {
            return (nFlags & BLOCK_STAKE_MODIFIER);
        }

        void SetStakeModifier(uint64_t nModifier, bool fGeneratedStakeModifier)
        {
            nStakeModifier = nModifier;

            if (fGeneratedStakeModifier)
            {
                nFlags |= BLOCK_STAKE_MODIFIER;
            }
        }

        std::string ToString() const
        {

#ifndef LOWMEM
            return strprintf("CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d nHeight=%d, nPOWMint=%s, nMoneySupply=%s, nFlags=(%s)(%d)(%s), nStakeModifier=%016x, hashProof=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, hashBlock=%s)",
                pprev, pnext, nFile, nBlockPos, nHeight,
                FormatMoney(nPOWMint), FormatMoney(nMoneySupply),
                GeneratedStakeModifier() ? "MOD" : "-", GetStakeEntropyBit(), IsProofOfStake()? "PoS" : "PoW",
                nStakeModifier,
                hashProof.ToString(),
                prevoutStake.ToString(),
                nStakeTime,
                hashMerkleRoot.ToString(),
                GetBlockHash().ToString());
#else
            return strprintf("CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d nHeight=%d, nFlags=(%s)(%d)(%s), nStakeModifier=%016x, hashProof=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, hashBlock=%s)",
                pprev, pnext, nFile, nBlockPos, nHeight,
                GeneratedStakeModifier() ? "MOD" : "-", GetStakeEntropyBit(), IsProofOfStake()? "PoS" : "PoW",
                nStakeModifier,
                hashProof.ToString(),
                prevoutStake.ToString(),
                nStakeTime,
                hashMerkleRoot.ToString(),
                GetBlockHash().ToString());
#endif     

        }
};


/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
    private:

        uint256 blockHash;

    public:

        uint256 hashPrev;
        uint256 hashNext;

        CDiskBlockIndex()
        {
            hashPrev = 0;
            hashNext = 0;
            blockHash = 0;
        }

        explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
        {
            hashPrev = (pprev ? pprev->GetBlockHash() : 0);
            hashNext = (pnext ? pnext->GetBlockHash() : 0);
        }

        IMPLEMENT_SERIALIZE
        (
            if (!(nType & SER_GETHASH))
            {
                READWRITE(nVersion);
            }

            READWRITE(hashNext);
            READWRITE(nFile);
            READWRITE(nBlockPos);
            READWRITE(nHeight);
    #ifndef LOWMEM
            READWRITE(nPOWMint);
            READWRITE(nPOSMint);
            READWRITE(nMoneySupply);
    #endif
            READWRITE(nFlags);
            READWRITE(nStakeModifier);
    #ifndef LOWMEM
            READWRITE(bnStakeModifierV2);
    #endif
            if (IsProofOfStake())
            {
                READWRITE(prevoutStake);
                READWRITE(nStakeTime);

            }
            else if (fRead)
            {
                const_cast<CDiskBlockIndex*>(this)->prevoutStake.SetNull();
                const_cast<CDiskBlockIndex*>(this)->nStakeTime = 0;
            }

            READWRITE(hashProof);

            // block header
            READWRITE(this->nVersion);
            READWRITE(hashPrev);
            READWRITE(hashMerkleRoot);
            READWRITE(nTime);
            READWRITE(nBits);
            READWRITE(nNonce);
            READWRITE(blockHash);
        )

        uint256 GetBlockHash() const
        {
            if (fUseFastIndex
                && (nTime < GetAdjustedTime() - 24 * 60 * 60)
                && blockHash != 0)
            {
                return blockHash;
            }

            CBlock block;
            block.nVersion        = nVersion;
            block.hashPrevBlock   = hashPrev;
            block.hashMerkleRoot  = hashMerkleRoot;
            block.nTime           = nTime;
            block.nBits           = nBits;
            block.nNonce          = nNonce;

            const_cast<CDiskBlockIndex*>(this)->blockHash = block.GetHash();

            return blockHash;
        }

        std::string ToString() const
        {
            std::string str = "CDiskBlockIndex(";
            str += CBlockIndex::ToString();
            str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)", GetBlockHash().ToString(), hashPrev.ToString(), hashNext.ToString());

            return str;
        }
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{
    protected:

        std::vector<uint256> vHave;
    
    public:

        CBlockLocator()
        {
        }

        explicit CBlockLocator(const CBlockIndex* pindex)
        {
            Set(pindex);
        }

        explicit CBlockLocator(uint256 hashBlock)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);

            if (mi != mapBlockIndex.end())
            {
                Set((*mi).second);
            }
        }

        CBlockLocator(const std::vector<uint256>& vHaveIn)
        {
            vHave = vHaveIn;
        }

        IMPLEMENT_SERIALIZE
        (
            if (!(nType & SER_GETHASH))
            {
                READWRITE(nVersion);
            }

            READWRITE(vHave);
        )

        void SetNull()
        {
            vHave.clear();
        }

        bool IsNull()
        {
            return vHave.empty();
        }

        void Set(const CBlockIndex* pindex)
        {
            vHave.clear();

            int nStep = 1;

            while (pindex)
            {
                vHave.push_back(pindex->GetBlockHash());

                // Exponentially larger steps back
                for (int i = 0; pindex && i < nStep; i++)
                {
                    pindex = pindex->pprev;
                }

                if (vHave.size() > 10)
                {
                    nStep *= 2;
                }
            }

            vHave.push_back(Params().HashGenesisBlock());
        }

        int GetDistanceBack()
        {
            // Retrace how far back it was in the sender's branch
            int nDistance = 0;
            int nStep = 1;

            for(const uint256& hash: vHave)
            {
                std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);

                if (mi != mapBlockIndex.end())
                {
                    CBlockIndex* pindex = (*mi).second;

                    if (pindex->IsInMainChain())
                    {
                        return nDistance;
                    }

                }

                nDistance += nStep;

                if (nDistance > 100)
                {
                    nStep *= 2;
                }

            }

            return nDistance;
        }

        CBlockIndex* GetBlockIndex()
        {
            // Find the first block the caller has in the main chain
            for(const uint256& hash: vHave)
            {
                std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);

                if (mi != mapBlockIndex.end())
                {
                    CBlockIndex* pindex = (*mi).second;

                    if (pindex->IsInMainChain())
                    {
                        return pindex;
                    }
                }
            }

            return pindexGenesisBlock;
        }

        uint256 GetBlockHash()
        {
            // Find the first block the caller has in the main chain
            for(const uint256& hash: vHave)
            {
                std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);

                if (mi != mapBlockIndex.end())
                {
                    CBlockIndex* pindex = (*mi).second;

                    if (pindex->IsInMainChain())
                    {
                        return hash;
                    }
                }
            }

            return Params().HashGenesisBlock();
        }

        int GetHeight()
        {
            CBlockIndex* pindex = GetBlockIndex();
            
            if (!pindex)
            {
                return 0;
            }

            return pindex->nHeight;
        }
};


/** Capture information about block/transaction validation */
class CValidationState
{
    private:

        enum mode_state
        {
            MODE_VALID,   //! everything ok
            MODE_INVALID, //! network rule violation (DoS value may be set)
            MODE_ERROR,   //! run-time error
        } mode;

        int nDoS;
        std::string strRejectReason;
        unsigned char chRejectCode;
        bool corruptionPossible;
    
    public:

        CValidationState() : mode(MODE_VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}

        bool DoS(int level, bool ret = false, unsigned char chRejectCodeIn=0, std::string strRejectReasonIn="", bool corruptionIn=false)
        {
            chRejectCode = chRejectCodeIn;
            strRejectReason = strRejectReasonIn;
            corruptionPossible = corruptionIn;

            if (mode == MODE_ERROR)
            {
                return ret;
            }
            
            nDoS += level;
            mode = MODE_INVALID;
            
            return ret;
        }

        bool Invalid(bool ret = false, unsigned char _chRejectCode=0, std::string _strRejectReason="")
        {
            return DoS(0, ret, _chRejectCode, _strRejectReason);
        }

        bool Error(std::string strRejectReasonIn="")
        {
            if (mode == MODE_VALID)
            {
                strRejectReason = strRejectReasonIn;
            }
            
            mode = MODE_ERROR;

            return false;
        }

        bool Abort(const std::string &msg)
        {
            AbortNode(msg);
            return Error(msg);
        }

        bool IsValid() const
        {
            return mode == MODE_VALID;
        }

        bool IsInvalid() const
        {
            return mode == MODE_INVALID;
        }

        bool IsError() const
        {
            return mode == MODE_ERROR;
        }

        bool IsInvalid(int &nDoSOut) const
        {
            if (IsInvalid())
            {
                nDoSOut = nDoS;
                return true;
            }

            return false;
        }

        bool CorruptionPossible() const
        {
            return corruptionPossible;
        }

        unsigned char GetRejectCode() const
        {
            return chRejectCode;
        }
        
        std::string GetRejectReason() const
        {
            return strRejectReason;
        }
};


class CWalletInterface
{
    protected:

        virtual void SyncTransaction(const CTransaction &tx, const CBlock *pblock, bool fConnect, bool fFixSpentCoins) =0;
        virtual void EraseFromWallet(const uint256 &hash) =0;
        virtual void SetBestChain(const CBlockLocator &locator) =0;
        virtual bool UpdatedTransaction(const uint256 &hash) =0;
        virtual void Inventory(const uint256 &hash) =0;
        virtual void ResendWalletTransactions(bool fForce) =0;
        friend void ::RegisterWallet(CWalletInterface*);
        friend void ::UnregisterWallet(CWalletInterface*);
        friend void ::UnregisterAllWallets();
};

 class CBlockHeader
 {
    public:

        // header
        int32_t nVersion;
        uint256 hashPrevBlock;
        uint256 hashMerkleRoot;
        uint32_t nTime;
        uint32_t nBits;
        uint32_t nNonce;
    
        CBlockHeader()
        {
            SetNull();
        }
    
        IMPLEMENT_SERIALIZE
        (
            READWRITE(this->nVersion);
            READWRITE(hashPrevBlock);
            READWRITE(hashMerkleRoot);
            READWRITE(nTime);
            READWRITE(nBits);
            READWRITE(nNonce);
        )
    
        void SetNull()
        {
            nVersion = 0;
            hashPrevBlock.SetNull();
            hashMerkleRoot.SetNull();
            nTime = 0;
            nBits = 0;
            nNonce = 0;
        }
    
        bool IsNull() const
        {
            return (nBits == 0);
        }
    
        uint256 GetHash() const;
    
        int64_t GetBlockTime() const
        {
            return (int64_t)nTime;
        }
 };
 
 /* To Upgrade for CBlockHeader
 class CBlock : public CBlockHeader
 {
 public:
     // network and disk
     std::vector<CTransactionRef> vtx;
 
     // memory only
     mutable bool fChecked;
 
     CBlock()
     {
         SetNull();
     }
 
     CBlock(const CBlockHeader &header)
     {
         SetNull();
         *(static_cast<CBlockHeader*>(this)) = header;
     }
 
     ADD_SERIALIZE_METHODS;
 
     template <typename Stream, typename Operation>
     inline void SerializationOp(Stream& s, Operation ser_action) {
         READWRITEAS(CBlockHeader, *this);
         READWRITE(vtx);
     }
 
     void SetNull()
     {
         CBlockHeader::SetNull();
         vtx.clear();
         fChecked = false;
     }
 
     CBlockHeader GetBlockHeader() const
     {
         CBlockHeader block;
         block.nVersion       = nVersion;
         block.hashPrevBlock  = hashPrevBlock;
         block.hashMerkleRoot = hashMerkleRoot;
         block.nTime          = nTime;
         block.nBits          = nBits;
         block.nNonce         = nNonce;
         return block;
     }
 
     std::string ToString() const;
 };
 */

/* End of Main.h
    Do not remove endif below
*/
#endif
