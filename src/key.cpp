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


#include "key.h"

#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "pubkey.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "util.h"

/* ONLY NEEDED FOR UNIT TESTING */
#include <iostream>
using namespace std;

// Global Namespace Start
namespace
{
    class CSecp256k1Init
    {
        ECCVerifyHandle globalVerifyHandle;
        ECCryptoClosure instance_of_eccryptoclosure;

        public:

            CSecp256k1Init()
            {
                ECC_Start();
            }
            ~CSecp256k1Init()
            { 
                ECC_Stop();
            }
};

} // Global Namespace End


static secp256k1_context* secp256k1_context_sign = NULL;


/** These functions are taken from the libsecp256k1 distribution and are very ugly. */
static int ec_privkey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *privkey, size_t privkeylen)
{
    const unsigned char *end = privkey + privkeylen;

    int lenb = 0;
    int len = 0;

    memset(out32, 0, 32);
    
    /* sequence header */
    if (end < privkey+1 || *privkey != 0x30)
    {
        return 0;
    }

    privkey++;
    /* sequence length constructor */
    if (end < privkey+1 || !(*privkey & 0x80))
    {
        return 0;
    }

    lenb = *privkey & ~0x80; privkey++;
    if (lenb < 1 || lenb > 2)
    {
        return 0;
    }

    if (end < privkey+lenb)
    {
        return 0;
    }

    /* sequence length */
    len = privkey[lenb-1] | (lenb > 1 ? privkey[lenb-2] << 8 : 0);
    privkey += lenb;

    if (end < privkey+len)
    {
        return 0;
    }

    /* sequence element 0: version number (=1) */
    if (end < privkey+3 || privkey[0] != 0x02 || privkey[1] != 0x01 || privkey[2] != 0x01)
    {
       return 0;
    }

    privkey += 3;

    /* sequence element 1: octet string, up to 32 bytes */
    if (end < privkey+2 || privkey[0] != 0x04 || privkey[1] > 0x20 || end < privkey+2+privkey[1])
    {
        return 0;
    }

    memcpy(out32 + 32 - privkey[1], privkey + 2, privkey[1]);

    if (!secp256k1_ec_seckey_verify(ctx, out32))
    {
        memset(out32, 0, 32);

        return 0;
    }

    return 1;
}


static int ec_privkey_export_der(const secp256k1_context *ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, int compressed)
{
    secp256k1_pubkey pubkey;

    size_t pubkeylen = 0;

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32))
    {
        *privkeylen = 0;

        return 0;
    }

    if (compressed)
    {
        static const unsigned char begin[] =
        {
            0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
        };

        static const unsigned char middle[] =
        {
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        };

        unsigned char *ptr = privkey;

        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);

        pubkeylen = 33;

        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);

        ptr += pubkeylen;
        
        *privkeylen = ptr - privkey;
    }
    else
    {
        static const unsigned char begin[] =
        {
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        };

        static const unsigned char middle[] =
        {
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        };

        unsigned char *ptr = privkey;

        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);

        pubkeylen = 65;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    }

    return 1;
}


bool CKey::Check(const unsigned char *vch)
{
    return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}


void CKey::MakeNewKey(bool fCompressedIn)
{
    RandAddSeedPerfmon();

    do
    {
        GetRandBytes(vch, sizeof(vch));
    }
    while (!Check(vch));
    
    fValid = true;
    fCompressed = fCompressedIn;
}


bool CKey::SetPrivKey(const CPrivKey &privkey, bool fCompressedIn)
{
    if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char*)begin(), &privkey[0], privkey.size()))
    {
        return false;
    }

    fCompressed = fCompressedIn;
    fValid = true;

    return true;
}


CPrivKey CKey::GetPrivKey() const
{
    if (fValid == false)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : fValid == false (assert-1)\n", __FUNCTION__);
        }
        
        cout << __FUNCTION__ << " (assert-1)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        CPrivKey privkey;
        
        return privkey;
    }

    CPrivKey privkey;

    int ret;
    size_t privkeylen;

    privkey.resize(279);
    privkeylen = 279;

    ret = ec_privkey_export_der(secp256k1_context_sign, (unsigned char*)&privkey[0], &privkeylen, begin(), fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    
    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ret == 0 (assert-2)\n", __FUNCTION__);
        }
        
        cout << __FUNCTION__ << " (assert-2)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        CPrivKey privkey;
        
        return privkey;
    }

    privkey.resize(privkeylen);

    return privkey;
}


CPubKey CKey::GetPubKey() const
{
    if (fValid == false)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : fValid == false (assert-3)\n", __FUNCTION__);
        }
        
        cout << __FUNCTION__ << " (assert-3)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        CPubKey null_key;
        
        return null_key; // Fail (NULL)
    }

    secp256k1_pubkey pubkey;
    size_t clen = 65;
    CPubKey result;

    int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, begin());

    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ret == 0 (assert-4)\n", __FUNCTION__);
        }
        
        cout << __FUNCTION__ << " (assert-4)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        CPubKey null_key;
        
        return null_key; // Fail (NULL)
    }

    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, (unsigned char*)result.begin(), &clen, &pubkey, fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    
    if (result.size() != clen)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : result.size() != clen (assert-5)\n", __FUNCTION__);
        }
        
        cout << __FUNCTION__ << " (assert-5)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        CPubKey null_key;
        
        return null_key; // Fail (NULL)
    }

    if(result.IsValid() == false)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : result.IsValid() == false (assert-6)\n", __FUNCTION__);
        }
        
        cout << __FUNCTION__ << " (assert-6)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        CPubKey null_key;
        
        return null_key; // Fail (NULL)
    }

    return result; // Success
}


bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const
{
    if (!fValid)
    {
        return false;
    }

    vchSig.resize(72);
    size_t nSigLen = 72;

    unsigned char extra_entropy[32] = {0};

    WriteLE32(extra_entropy, test_case);

    secp256k1_ecdsa_signature sig;
    
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, test_case ? extra_entropy : NULL);
    
    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ret == 0 (assert-7)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-7)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }

    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, (unsigned char*)&vchSig[0], &nSigLen, &sig);

    vchSig.resize(nSigLen);
    
    return true;
}


bool CKey::VerifyPubKey(const CPubKey& pubkey) const
{
    if (pubkey.IsCompressed() != fCompressed)
    {
        return false;
    }

    unsigned char rnd[8];
    
    std::string str = "Bitcoin key verification\n";
    
    GetRandBytes(rnd, sizeof(rnd));
    
    uint256 hash;
    
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    
    std::vector<unsigned char> vchSig;
    
    Sign(hash, vchSig);
    
    return pubkey.Verify(hash, vchSig);
}


bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const
{
    if (!fValid)
    {
        return false;
    }
    
    vchSig.resize(65);
    
    int rec = -1;
    
    secp256k1_ecdsa_recoverable_signature sig;
    
    int ret = secp256k1_ecdsa_sign_recoverable(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, NULL);
    
    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ret == 0 (assert-8)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-8)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }
    
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_sign, (unsigned char*)&vchSig[1], &rec, &sig);
    
    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ret == 0 (assert-9)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-9)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }

    if (rec == -1)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : rec == -1 (assert-10)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-10)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }
    
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);

    return true;
}


bool CKey::Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck=false)
{
    if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char*)begin(), &privkey[0], privkey.size()))
    {
        return false;
    }

    fCompressed = vchPubKey.IsCompressed();
    fValid = true;

    if (fSkipCheck)
    {
        return true;
    }

    return VerifyPubKey(vchPubKey);
}


bool CKey::Derive(CKey& keyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const
{
    if (IsValid() == false)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : IsValid() == false (assert-11)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-11)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }

    if (IsCompressed() == false)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : IsCompressed() == false (assert-12)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-12)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }

    unsigned char out[64];

    LockObject(out);

    if ((nChild >> 31) == 0)
    {
        CPubKey pubkey = GetPubKey();

        if (pubkey.begin() + 33 != pubkey.end())
        {
            if (fDebug)
            {
                LogPrint("key", "%s : pubkey.begin() + 33 != pubkey.end() (assert-13)\n", __FUNCTION__);
            }

            cout << __FUNCTION__ << " (assert-13)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

            return false;
        }

        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, out);
    }
    else
    {
        if (begin() + 32 != end())
        {
            if (fDebug)
            {
                LogPrint("key", "%s : begin() + 32 != end() (assert-14)\n", __FUNCTION__);
            }

            cout << __FUNCTION__ << " (assert-14)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

            return false;
        }

        BIP32Hash(cc, nChild, 0, begin(), out);
    }

    memcpy(ccChild, out+32, 32);
    memcpy((unsigned char*)keyChild.begin(), begin(), 32);

    bool ret = secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, (unsigned char*)keyChild.begin(), out);

    UnlockObject(out);

    keyChild.fCompressed = true;
    keyChild.fValid = ret;

    return ret;
}


bool CExtKey::Derive(CExtKey &out, unsigned int nChild) const
{
    out.nDepth = nDepth + 1;

    CKeyID id = key.GetPubKey().GetID();

    memcpy(&out.vchFingerprint[0], &id, 4);

    out.nChild = nChild;

    return key.Derive(out.key, out.vchChainCode, nChild, vchChainCode);
}


void CExtKey::SetMaster(const unsigned char *seed, unsigned int nSeedLen)
{
    static const char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};

    HMAC_SHA512_CTX ctx;
    HMAC_SHA512_Init(&ctx, hashkey, sizeof(hashkey));
    HMAC_SHA512_Update(&ctx, seed, nSeedLen);

    unsigned char out[64];

    LockObject(out);

    HMAC_SHA512_Final(out, &ctx);

    key.Set(&out[0], &out[32], true);

    memcpy(vchChainCode, &out[32], 32);

    UnlockObject(out);

    nDepth = 0;
    nChild = 0;

    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}


CExtPubKey CExtKey::Neuter() const
{
    CExtPubKey ret;
    ret.nDepth = nDepth;
    
    memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);

    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();

    memcpy(&ret.vchChainCode[0], &vchChainCode[0], 32);

    return ret;
}


void CExtKey::Encode(unsigned char code[74]) const
{
    code[0] = nDepth;

    memcpy(code+1, vchFingerprint, 4);

    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;

    memcpy(code+9, vchChainCode, 32);

    code[41] = 0;

    if (key.size() != 32)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : key.size() != 32 (assert-15)\n", __FUNCTION__);
        }
        
        cout << __FUNCTION__ << " (assert-15)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return;
    }

    memcpy(code+42, key.begin(), 32);
}


void CExtKey::Decode(const unsigned char code[74])
{
    nDepth = code[0];

    memcpy(vchFingerprint, code+1, 4);

    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];

    memcpy(vchChainCode, code+9, 32);

    key.Set(code+42, code+74, true);
}


bool ECC_InitSanityCheck()
{
    CKey key;

    key.MakeNewKey(true);

    CPubKey pubkey = key.GetPubKey();

    return key.VerifyPubKey(pubkey);
}


void ECC_Start()
{
    if (secp256k1_context_sign != NULL)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : secp256k1_context_sign != NULL (assert-16)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-16)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    if (ctx == NULL)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ctx == NULL (assert-17)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-17)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return;
    }

    // Global Namespace Start
    {
        // Pass in a random blinding seed to the secp256k1 context.
        unsigned char seed[32];

        LockObject(seed);
        
        GetRandBytes(seed, 32);

        bool ret = secp256k1_context_randomize(ctx, seed);

        if (ret == false)
        {
            if (fDebug)
            {
                LogPrint("key", "%s : ret == 0 (assert-18)\n", __FUNCTION__);
            }

            cout << __FUNCTION__ << " (assert-18)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

            return;
        }


        UnlockObject(seed);
    }
    // Global Namespace End

    secp256k1_context_sign = ctx;
}


void ECC_Stop()
{
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = NULL;

    if (ctx)
    {
        secp256k1_context_destroy(ctx);
    }
}
