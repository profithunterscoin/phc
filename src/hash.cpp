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


#include "hash.h"

int HMAC_SHA512_Init(HMAC_SHA512_CTX *pctx,
                        const void *pkey,
                        size_t len
                    )
{
    unsigned char key[128];

    if (len <= 128)
    {
        memcpy(key, pkey, len);

        memset(key + len, 0, 128-len);
    }
    else
    {
        SHA512_CTX ctxKey;

        SHA512_Init(&ctxKey);

        SHA512_Update(&ctxKey, pkey, len);

        SHA512_Final(key, &ctxKey);

        memset(key + 64, 0, 64);
    }

    for (int n=0; n<128; n++)
    {
        key[n] ^= 0x5c;
    }

    SHA512_Init(&pctx->ctxOuter);

    SHA512_Update(&pctx->ctxOuter, key, 128);

    for (int n=0; n<128; n++)
    {
        key[n] ^= 0x5c ^ 0x36;
    }

    SHA512_Init(&pctx->ctxInner);

    return SHA512_Update(&pctx->ctxInner, key, 128);
}


int HMAC_SHA512_Update(HMAC_SHA512_CTX *pctx,
                        const void *pdata,
                        size_t len
                        )
{
    return SHA512_Update(&pctx->ctxInner, pdata, len);
}


int HMAC_SHA512_Final(unsigned char *pmd,
                        HMAC_SHA512_CTX *pctx
                    )
{
    unsigned char buf[64];

    SHA512_Final(buf, &pctx->ctxInner);

    SHA512_Update(&pctx->ctxOuter, buf, 64);

    return SHA512_Final(pmd, &pctx->ctxOuter);
}


void BIP32Hash(const unsigned char chainCode[32],
                unsigned int nChild, unsigned char header,
                const unsigned char data[32],
                unsigned char output[64]
            )
{
    unsigned char num[4];

    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;

    HMAC_SHA512_CTX ctx;

    HMAC_SHA512_Init(&ctx, chainCode, 32);

    HMAC_SHA512_Update(&ctx, &header, 1);

    HMAC_SHA512_Update(&ctx, data, 32);

    HMAC_SHA512_Update(&ctx, num, 4);

    HMAC_SHA512_Final(output, &ctx);
    
}
