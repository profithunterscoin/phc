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


#include "pubkey.h"
#include "util.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

/* ONLY NEEDED FOR UNIT TESTING */
#include <iostream>
using namespace std;


// Global Namespace Start
namespace
{
    /* Global secp256k1_context object used for verification. */
    secp256k1_context* secp256k1_context_verify = NULL;
}
// Global Namespace End

/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen)
{
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;

    unsigned char tmpsig[64] = {0};
    
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30)
    {
        return 0;
    }
    
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen)
    {
        return 0;
    }

    lenbyte = input[pos++];
    
    if (lenbyte & 0x80)
    {
        lenbyte -= 0x80;
        
        if (pos + lenbyte > inputlen)
        {
            return 0;
        }
    
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02)
    {
        return 0;
    }

    pos++;

    /* Integer length for R */
    if (pos == inputlen)
    {
        return 0;
    }

    lenbyte = input[pos++];
    
    if (lenbyte & 0x80)
    {
        lenbyte -= 0x80;
        
        if (pos + lenbyte > inputlen)
        {
            return 0;
        }
        
        while (lenbyte > 0 && input[pos] == 0)
        {
            pos++;

            lenbyte--;
        }

        if (lenbyte >= sizeof(size_t))
        {
            return 0;
        }
        
        rlen = 0;

        while (lenbyte > 0)
        {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    }
    else
    {
        rlen = lenbyte;
    }
    
    if (rlen > inputlen - pos)
    {
        return 0;
    }
    
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02)
    {
        return 0;
    }
    
    pos++;

    /* Integer length for S */
    if (pos == inputlen)
    {
        return 0;
    }

    lenbyte = input[pos++];
    
    if (lenbyte & 0x80)
    {
        lenbyte -= 0x80;

        if (pos + lenbyte > inputlen)
        {
            return 0;
        }
        
        while (lenbyte > 0 && input[pos] == 0)
        {
            pos++;
            lenbyte--;
        }
        
        if (lenbyte >= sizeof(size_t))
        {
            return 0;
        }
        
        slen = 0;

        while (lenbyte > 0)
        {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    }
    else
    {
        slen = lenbyte;
    }
    
    if (slen > inputlen - pos)
    {
        return 0;
    }

    spos = pos;
    pos += slen;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0)
    {
        rlen--;
        rpos++;
    }

    /* Copy R value */
    if (rlen > 32)
    {
        overflow = 1;
    }
    else
    {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0)
    {
        slen--;
        spos++;
    }

    /* Copy S value */
    if (slen > 32)
    {
        overflow = 1;
    }
    else
    {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow)
    {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    
    if (overflow)
    {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);

        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }

    return 1;
}


bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const
{
    if (!IsValid())
    {
        return false;
    }

    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size()))
    {
        return false;
    }
    
    if (vchSig.size() == 0)
    {
        return false;
    }
    
    if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, &vchSig[0], vchSig.size()))
    {
        return false;
    }
    
    /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
     * not historically been enforced in Bitcoin, so normalize them first. */
    secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig, &sig);
    
    return secp256k1_ecdsa_verify(secp256k1_context_verify, &sig, hash.begin(), &pubkey);
}


bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig)
{
    if (vchSig.size() != 65)
    {
        return false;
    }
    
    int recid = (vchSig[0] - 27) & 3;
    bool fComp = ((vchSig[0] - 27) & 4) != 0;
    
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context_verify, &sig, &vchSig[1], recid))
    {
        return false;
    }
    
    if (!secp256k1_ecdsa_recover(secp256k1_context_verify, &pubkey, &sig, hash.begin()))
    {
        return false;
    }
    
    unsigned char pub[65];
    
    size_t publen = 65;
    
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey, fComp ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    
    Set(pub, pub + publen);
    
    return true;
}


bool CPubKey::IsFullyValid() const
{
    if (!IsValid())
    {
        return false;
    }

    secp256k1_pubkey pubkey;
    
    return secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size());
}


bool CPubKey::Decompress()
{
    if (!IsValid())
    {
        return false;
    }
  
    secp256k1_pubkey pubkey;
  
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size()))
    {
        return false;
    }
  
    unsigned char pub[65];
  
    size_t publen = 65;
  
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  
    Set(pub, pub + publen);
  
    return true;
}


bool CPubKey::Derive(CPubKey& pubkeyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const
{
    if (IsValid() == false)
    {
        if (fDebug)
        {
            LogPrint("pubkey", "%s : IsValid() == false (assert-1)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-1)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }

    if ((nChild >> 31) != 0)
    {
        if (fDebug)
        {
            LogPrint("pubkey", "%s : (nChild >> 31) != 0 (assert-2)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-2)" << endl;  // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }

    if (begin() + 33 != end())
    {
        if (fDebug)
        {
            LogPrint("pubkey", "%s : begin() + 33 != end() (assert-3)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-3)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return false;
    }

    unsigned char out[64];

    BIP32Hash(cc, nChild, *begin(), begin()+1, out);

    memcpy(ccChild, out+32, 32);

    secp256k1_pubkey pubkey;
    
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size()))
    {
        return false;
    }
    
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_verify, &pubkey, out))
    {
        return false;
    }
    
    unsigned char pub[33];
    
    size_t publen = 33;
    
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey, SECP256K1_EC_COMPRESSED);
    
    pubkeyChild.Set(pub, pub + publen);
    
    return true;
}


void CExtPubKey::Encode(unsigned char code[74]) const
{
    code[0] = nDepth;

    memcpy(code+1, vchFingerprint, 4);
    
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    
    memcpy(code+9, vchChainCode, 32);
    
    if (pubkey.size() != 33)
    {
        if (fDebug)
        {
            LogPrint("pubkey", "%s : pubkey.size() != 33 (assert-4)\n", __FUNCTION__);
        }

        cout << __FUNCTION__ << " (assert-4)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

        return;
    }
    
    memcpy(code+41, pubkey.begin(), 33);
}


void CExtPubKey::Decode(const unsigned char code[74])
{
    nDepth = code[0];

    memcpy(vchFingerprint, code+1, 4);

    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];

    memcpy(vchChainCode, code+9, 32);

    pubkey.Set(code+41, code+74);
}


bool CExtPubKey::Derive(CExtPubKey &out, unsigned int nChild) const
{
    out.nDepth = nDepth + 1;

    CKeyID id = pubkey.GetID();

    memcpy(&out.vchFingerprint[0], &id, 4);

    out.nChild = nChild;

    return pubkey.Derive(out.pubkey, out.vchChainCode, nChild, vchChainCode);
}


/* static */ bool CPubKey::CheckLowS(const std::vector<unsigned char>& vchSig)
{
    secp256k1_ecdsa_signature sig;
    
    if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, &vchSig[0], vchSig.size()))
    {
        return false;
    }
    
    return (!secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, NULL, &sig));
}


/* static */ int ECCVerifyHandle::refcount = 0;


ECCVerifyHandle::ECCVerifyHandle()
{
    if (refcount == 0)
    {
        if (secp256k1_context_verify != NULL)
        {
            if (fDebug)
            {
                LogPrint("pubkey", "%s : secp256k1_context_verify != NULL (assert-5)\n", __FUNCTION__);
            }

            cout << __FUNCTION__ << " (assert-5)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

            return;
        }
    
        secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    
        if (secp256k1_context_verify == NULL)
        {
            if (fDebug)
            {
                LogPrint("pubkey", "%s : secp256k1_context_verify == NULL (assert-6)\n", __FUNCTION__);
            }

            cout << __FUNCTION__ << " (assert-6)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

            return;
        }
    }
    
    refcount++;
}


ECCVerifyHandle::~ECCVerifyHandle()
{
    refcount--;
    
    if (refcount == 0)
    {
        if (secp256k1_context_verify == NULL)
        {
            if (fDebug)
            {
                LogPrint("pubkey", "%s : secp256k1_context_verify == NULL (assert-7)\n", __FUNCTION__);
            }

            cout << __FUNCTION__ << " (assert-7)" << endl; // REMOVE AFTER UNIT TESTING COMPLETED

            return;
        }
    
        secp256k1_context_destroy(secp256k1_context_verify);
        secp256k1_context_verify = NULL;
    }
}
