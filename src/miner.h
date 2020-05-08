// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (C) 2017-2018 Crypostle Core developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "main.h"
#include "script.h"
#include "wallet.h"

extern bool fGenerating;
extern int GenerateProcLimit;

extern bool fStaking;

// LogCache for Miner
extern std::string MinerLogCache;

// Log for InternalStakeMiner
extern int LastBlockStake;
extern int LastBlockStakeTime;

/* Generate a new block, without valid proof-of-work */
CBlock* CreateNewBlock(CReserveKey& reservekey, bool fProofOfStake=false, int64_t* pFees = 0);

/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);

/** Do mining precalculation */
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);

/** Check mined proof-of-work block */
bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);

/** Check mined proof-of-stake block */
bool ProcessBlockStake(CBlock* pblock, CWallet& wallet);

/** Base sha256 mining transform */
void SHA256Transform(void* pstate, void* pinput, const void* pinit);

void GeneratePoWcoins(bool fGenerate, CWallet* pwallet);

#endif // BITCOIN_MINER_H
