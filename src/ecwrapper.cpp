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


#include "ecwrapper.h"
#include "util.h"
#include "serialize.h"
#include "uint256.h"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

/* ONLY NEEDED FOR UNIT TESTING */
#include <iostream>

using namespace std;


// Global Namespace Start
namespace
{

    // Generate a private key from just the secret parameter
    int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
    {
        int ok = 0;

        BN_CTX *ctx = NULL;
        EC_POINT *pub_key = NULL;

        if (!eckey)
        {
            return 0;
        }

        const EC_GROUP *group = EC_KEY_get0_group(eckey);

        if ((ctx = BN_CTX_new()) == NULL)
        {
            goto err;
        }

        pub_key = EC_POINT_new(group);

        if (pub_key == NULL)
        {
            goto err;
        }

        if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        {
            goto err;
        }

        EC_KEY_set_private_key(eckey,priv_key);
        EC_KEY_set_public_key(eckey,pub_key);

        ok = 1;

        err:

            if (pub_key)
            {
                EC_POINT_free(pub_key);
            }
            
            if (ctx != NULL)
            {
                BN_CTX_free(ctx);
            }

            return(ok);
    }

    // Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
    // recid selects which key is recovered
    // if check is non-zero, additional checks are performed
    int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
    {
        if (!eckey)
        {
            return 0;
        }

        int ret = 0;

        BN_CTX *ctx = NULL;

        BIGNUM *x = NULL;
        BIGNUM *e = NULL;
        BIGNUM *order = NULL;
        BIGNUM *sor = NULL;
        BIGNUM *eor = NULL;
        BIGNUM *field = NULL;
        
        EC_POINT *R = NULL;
        EC_POINT *O = NULL;
        EC_POINT *Q = NULL;
        
        BIGNUM *rr = NULL;
        BIGNUM *zero = NULL;
        
        int n = 0;
        int i = recid / 2;

        const BIGNUM *ecsig_r = NULL;
        const BIGNUM *ecsig_s = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

        ecsig_r = ecsig->r;
        ecsig_s = ecsig->s;

#else
// OPENSSL 1.1+
        ECDSA_SIG_get0(ecsig, &ecsig_r, &ecsig_s);

#endif
        const EC_GROUP *group = EC_KEY_get0_group(eckey);
        
        if ((ctx = BN_CTX_new()) == NULL)
        {
            ret = -1;

            goto err;
        }
        
        BN_CTX_start(ctx);
        
        order = BN_CTX_get(ctx);
        
        if (!EC_GROUP_get_order(group, order, ctx))
        {
            ret = -2;

            goto err;
        }
        
        x = BN_CTX_get(ctx);
        
        if (!BN_copy(x, order))
        {
            ret = -1;
            goto err;
        }
        
        if (!BN_mul_word(x, i))
        {
            ret = -1;

            goto err;
        }
        
        if (!BN_add(x, x, ecsig_r))
        {
            ret = -1;

            goto err;
        }
        
        field = BN_CTX_get(ctx);
        
        if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx))
        {
            ret = -2;

            goto err;
        }
        
        if (BN_cmp(x, field) >= 0)
        {
            ret = 0;

            goto err;
        }
        
        if ((R = EC_POINT_new(group)) == NULL)
        {
            ret = -2;

            goto err;
        }
        
        if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx))
        {
            ret = 0;

            goto err;
        }

        if (check)
        {
            if ((O = EC_POINT_new(group)) == NULL)
            {
                ret = -2;

                goto err;
            }
            
            if (!EC_POINT_mul(group, O, NULL, R, order, ctx))
            {
                ret = -2;

                goto err;
            }
            
            if (!EC_POINT_is_at_infinity(group, O))
            {
                ret = 0;

                goto err;
            }
        }
        
        if ((Q = EC_POINT_new(group)) == NULL)
        {
            ret = -2;

            goto err;
        }
        
        n = EC_GROUP_get_degree(group);
        
        e = BN_CTX_get(ctx);
        
        if (!BN_bin2bn(msg, msglen, e))
        {
            ret = -1;

            goto err;
        }
        
        if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
        
        zero = BN_CTX_get(ctx);
        
        if (!BN_zero(zero))
        {
            ret = -1;

            goto err;
        }
        
        if (!BN_mod_sub(e, zero, e, order, ctx))
        {
            ret = -1;

            goto err;
        }
        
        rr = BN_CTX_get(ctx);
        
        if (!BN_mod_inverse(rr, ecsig_r, order, ctx))
        {
            ret = -1;

            goto err;
        }
        
        sor = BN_CTX_get(ctx);
        
        if (!BN_mod_mul(sor, ecsig_s, rr, order, ctx))
        {
            ret = -1;

            goto err;
        }
        
        eor = BN_CTX_get(ctx);
        
        if (!BN_mod_mul(eor, e, rr, order, ctx))
        {
            ret = -1;

            goto err;
        }
        
        if (!EC_POINT_mul(group, Q, eor, R, sor, ctx))
        {
            ret = -2;

            goto err;
        }
        
        if (!EC_KEY_set_public_key(eckey, Q))
        {
            ret = -2;

            goto err;
        }

        ret = 1;

    err:

        if (ctx)
        {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }

        if (R != NULL)
        {
            EC_POINT_free(R);
        }

        if (O != NULL)
        {
            EC_POINT_free(O);
        }
        
        if (Q != NULL)
        {
            EC_POINT_free(Q);
        }
        
        return ret;
    }

} // Global Namespace End


CECKey::CECKey()
{
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);

    if (pkey == NULL)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - pkey = NULL \n", __FUNCTION__);
        }

        return;
    }
}


CECKey::~CECKey()
{
    EC_KEY_free(pkey);
}


void CECKey::GetSecretBytes(unsigned char vch[32]) const
{
    const BIGNUM *bn = EC_KEY_get0_private_key(pkey);

//#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    if (bn == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - bn = 0 \n", __FUNCTION__);
        }

        return;
    }

    int nBytes = BN_num_bytes(bn);

    int n = BN_bn2bin(bn, &vch[32 - nBytes]);

    if (n != nBytes)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - n != nBytes \n", __FUNCTION__);
        }

        return;
    }

/*   Does not appear to be working with 1.1+
#else
// OPENSSL 1.1+
    if (&bn == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - bn = 0 \n", __FUNCTION__);
        }

        return;
    }

    int nBytes = BN_num_bytes(&bn);

    int n = BN_bn2bin(&bn, &vch[32 - nBytes]);

    if (n != nBytes)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - n != nBytes \n", __FUNCTION__);
        }

        return;
    }

#endif
*/

    memset(vch, 0, 32 - nBytes);
}


void CECKey::SetSecretBytes(const unsigned char vch[32])
{
    bool ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    BIGNUM bn;
    BN_init(&bn);

    ret = BN_bin2bn(vch, 32, &bn) != NULL;

    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - ret = 0 \n", __FUNCTION__);
        }

        return;
    }
    
    ret = EC_KEY_regenerate_key(pkey, &bn) != 0;

    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - ret = 0 \n", __FUNCTION__);
        }

        return;
    }

    BN_clear_free(&bn);

#else 
// OPENSSL 1.1+

    BIGNUM* bn(BN_new());
    
    ret = BN_bin2bn(vch, 32, bn) != NULL;

    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - ret = 0 \n", __FUNCTION__);
        }

        return;
    }

    ret = EC_KEY_regenerate_key(pkey, bn) != 0;

    if (ret == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - ret = 0 \n", __FUNCTION__);
        }

        return;
    }

    BN_clear_free(bn);

#endif

}


int CECKey::GetPrivKeySize(bool fCompressed)
{
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);

    return i2d_ECPrivateKey(pkey, NULL);
}


int CECKey::GetPrivKey(unsigned char* privkey, bool fCompressed)
{
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);

    return i2d_ECPrivateKey(pkey, &privkey);
}


bool CECKey::SetPrivKey(const unsigned char* privkey, size_t size, bool fSkipCheck)
{
    if (d2i_ECPrivateKey(&pkey, &privkey, size))
    {
        if(fSkipCheck)
        {
            return true;
        }

        // d2i_ECPrivateKey returns true if parsing succeeds.
        // This doesn't necessarily mean the key is valid.
        if (EC_KEY_check_key(pkey))
        {
            return true;
        }
    }

    return false;
}


void CECKey::GetPubKey(std::vector<unsigned char> &pubkey, bool fCompressed)
{
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    
    int nSize = i2o_ECPublicKey(pkey, NULL);
    
    if (nSize == 0)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - nSize = 0 \n", __FUNCTION__);
        }

        return;
    }

    if (nSize > 65)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - nSize > 65 \n", __FUNCTION__);
        }

        return;
    }
    
    pubkey.clear();
    pubkey.resize(nSize);
    
    unsigned char *pbegin(begin_ptr(pubkey));
    
    int nSize2 = i2o_ECPublicKey(pkey, &pbegin);
    
    if (nSize != nSize2)
    {
        if (fDebug)
        {
            LogPrint("key", "%s : ERROR - nSize != nSize2 \n", __FUNCTION__);
        }

        return;
    }
}


bool CECKey::SetPubKey(const unsigned char* pubkey, size_t size)
{
    return o2i_ECPublicKey(&pkey, &pubkey, size) != NULL;
}


bool CECKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig)
{    
    vchSig.clear();
    
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
    
    if (sig == NULL)
    {
        return false;
    }

    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    sig_r = sig->r;
    sig_s = sig->s;

#else
// OPENSSL 1.1+

    ECDSA_SIG_get0(sig, &sig_r, &sig_s);

#endif
    
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    
    const EC_GROUP *group = EC_KEY_get0_group(pkey);
    
    BIGNUM *order = BN_CTX_get(ctx);
    BIGNUM *halforder = BN_CTX_get(ctx);
    
    EC_GROUP_get_order(group, order, ctx);

    BN_rshift1(halforder, order);
    
    if (BN_cmp(sig_s, halforder) > 0)
    {
        // enforce low S values, by negating the value (modulo the order) if above order/2.
        BIGNUM *sig_s_new = BN_dup(sig_s);
        BIGNUM *sig_r_new = BN_dup(sig_r);

        BN_sub(sig_s_new, order, sig_s);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

        BN_clear_free(sig->r);
        BN_clear_free(sig->s);

        sig->r = sig_r_new;
        sig->s = sig_s_new;

#else
// OPENSSL 1.1+

        ECDSA_SIG_set0(sig, sig_r_new, sig_s_new);

#endif

    }
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    
    unsigned int nSize = ECDSA_size(pkey);

    // Make sure it is big enough
    vchSig.resize(nSize);

    unsigned char *pos = &vchSig[0];
    
    nSize = i2d_ECDSA_SIG(sig, &pos);
    
    ECDSA_SIG_free(sig);

    // Shrink to fit actual size
    vchSig.resize(nSize);

    return true;
}


bool CECKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig)
{
    // -1 = error, 0 = bad sig, 1 = good
    if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
    {
        return false;
    }

    return true;
}


bool CECKey::SignCompact(const uint256 &hash, unsigned char *p64, int &rec)
{
    bool fOk = false;
    
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
    
    if (sig == NULL)
    {
        return false;
    }

    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    sig_r = sig->r;
    sig_s = sig->s;

#else
// OPENSSL 1.1+

    ECDSA_SIG_get0(sig, &sig_r, &sig_s);

#endif

    memset(p64, 0, 64);
    
    int nBitsR = BN_num_bits(sig_r);
    int nBitsS = BN_num_bits(sig_s);
    
    if (nBitsR <= 256 && nBitsS <= 256)
    {
        std::vector<unsigned char> pubkey;
        
        GetPubKey(pubkey, true);

        for (int i=0; i<4; i++)
        {
            CECKey keyRec;

            if (ECDSA_SIG_recover_key_GFp(keyRec.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1) == 1)
            {
                std::vector<unsigned char> pubkeyRec;

                keyRec.GetPubKey(pubkeyRec, true);

                if (pubkeyRec == pubkey)
                {
                    rec = i;
                    fOk = true;

                    break;
                }
            }
        }
        
        if (fOk == 0)
        {
            if (fDebug)
            {
                LogPrint("key", "%s : ERROR - fOk = 0 \n", __FUNCTION__);
            }

            return false;
        }
        
        BN_bn2bin(sig_r,&p64[32-(nBitsR+7)/8]);
        BN_bn2bin(sig_s,&p64[64-(nBitsS+7)/8]);
    }
    
    ECDSA_SIG_free(sig);
    
    return fOk;
}


bool CECKey::Recover(const uint256 &hash, const unsigned char *p64, int rec)
{
    if (rec<0
        || rec>=3)
    {
        return false;
    }
    
    ECDSA_SIG *sig = ECDSA_SIG_new();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OPENSSL 1.0

    BN_bin2bn(&p64[0],  32, sig->r);
    BN_bin2bn(&p64[32], 32, sig->s);

#else
// OPENSSL 1.1+

    BIGNUM *sig_r(BN_new());
    BIGNUM *sig_s(BN_new());

    ECDSA_SIG_set0(sig, sig_r, sig_s);
    
#endif

    bool ret = ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), rec, 0) == 1;

    ECDSA_SIG_free(sig);
    
    return ret;
}


bool CECKey::TweakSecret(unsigned char vchSecretOut[32], const unsigned char vchSecretIn[32], const unsigned char vchTweak[32])
{
    bool ret = true;
    
    BN_CTX *ctx = BN_CTX_new();

    BN_CTX_start(ctx);
    
    BIGNUM *bnSecret = BN_CTX_get(ctx);
    BIGNUM *bnTweak = BN_CTX_get(ctx);
    BIGNUM *bnOrder = BN_CTX_get(ctx);
    
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    // what a grossly inefficient way to get the (constant) group order...
    EC_GROUP_get_order(group, bnOrder, ctx);
    
    BN_bin2bn(vchTweak, 32, bnTweak);
    
    if (BN_cmp(bnTweak, bnOrder) >= 0)
    {
        // extremely unlikely
        ret = false;
    }
    
    BN_bin2bn(vchSecretIn, 32, bnSecret);
    BN_add(bnSecret, bnSecret, bnTweak);
    BN_nnmod(bnSecret, bnSecret, bnOrder, ctx);
    
    if (BN_is_zero(bnSecret))
    {
        // ridiculously unlikely
        ret = false;
    }
    
    int nBits = BN_num_bits(bnSecret);
    
    memset(vchSecretOut, 0, 32);
    
    BN_bn2bin(bnSecret, &vchSecretOut[32-(nBits+7)/8]);
    
    EC_GROUP_free(group);
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}


bool CECKey::TweakPublic(const unsigned char vchTweak[32])
{
    bool ret = true;
    
    BN_CTX *ctx = BN_CTX_new();
    
    BN_CTX_start(ctx);
    
    BIGNUM *bnTweak = BN_CTX_get(ctx);
    BIGNUM *bnOrder = BN_CTX_get(ctx);
    BIGNUM *bnOne = BN_CTX_get(ctx);
    
    const EC_GROUP *group = EC_KEY_get0_group(pkey);
    
    // what a grossly inefficient way to get the (constant) group order...
    EC_GROUP_get_order(group, bnOrder, ctx);
    
    BN_bin2bn(vchTweak, 32, bnTweak);
    
    if (BN_cmp(bnTweak, bnOrder) >= 0)
    {
        // extremely unlikely
        ret = false;
    }
    
    EC_POINT *point = EC_POINT_dup(EC_KEY_get0_public_key(pkey), group);
    
    BN_one(bnOne);
    EC_POINT_mul(group, point, bnTweak, point, bnOne, ctx);
    
    if (EC_POINT_is_at_infinity(group, point))
    {
        // ridiculously unlikely
        ret = false;
    }
    
    EC_KEY_set_public_key(pkey, point);
    EC_POINT_free(point);
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}


bool CECKey::SanityCheck()
{
    EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);

    if(pkey == NULL)
    {
        return false;
    }

    EC_KEY_free(pkey);

    // TODO Is there more EC functionality that could be missing?
    return true;
}
