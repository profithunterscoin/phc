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


#include "uint256.h"

#include "utilstrencodings.h"

#include <stdio.h>
#include <string.h>

// base_uint2()
template <unsigned int BITS> base_uint2<BITS>::base_uint2(const std::vector<unsigned char>& vch)
{
    if (vch.size() != sizeof(data))
    {
        if (fDebug)
        {
            LogPrint("uint", "%s : ERROR - vch.size() != sizeof(data) \n", __FUNCTION__);
        }
    }
    else
    {
        memcpy(data, &vch[0], sizeof(data));
    }
}

// base_uint2::GetHex()
template <unsigned int BITS> std::string base_uint2<BITS>::GetHex() const
{
    char psz[sizeof(data) * 2 + 1];

    for (unsigned int i = 0; i < sizeof(data); i++)
    {
        sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
    }
        
    return std::string(psz, psz + sizeof(data) * 2);
}

// base_uint2::SetHex(Char)
template <unsigned int BITS> void base_uint2<BITS>::SetHex(const char* psz)
{
    memset(data, 0, sizeof(data));

    // skip leading spaces
    while (isspace(*psz))
    {
        psz++;
    }

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
    {
        psz += 2;
    }

    // hex string to uint
    const char* pbegin = psz;

    while (::HexDigit(*psz) != -1)
    {
        psz++;
    }
        
    psz--;
    
    unsigned char* p1 = (unsigned char*)data;
    unsigned char* pend = p1 + WIDTH;

    while (psz >= pbegin && p1 < pend)
    {
        *p1 = ::HexDigit(*psz--);
        if (psz >= pbegin)
        {
            *p1 |= ((unsigned char)::HexDigit(*psz--) << 4);
            p1++;
        }
    }
}

// base_uint2::SetHex(String)
template <unsigned int BITS> void base_uint2<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

// base_uint2::ToString()
template <unsigned int BITS> std::string base_uint2<BITS>::ToString() const
{
    return (GetHex());
}

// Explicit instantiations for base_uint2<160>
template base_uint2<160>::base_uint2(const std::vector<unsigned char>&);
template std::string base_uint2<160>::GetHex() const;
template std::string base_uint2<160>::ToString() const;
template void base_uint2<160>::SetHex(const char*);
template void base_uint2<160>::SetHex(const std::string&);

// Explicit instantiations for base_uint2<256>
template base_uint2<256>::base_uint2(const std::vector<unsigned char>&);
template std::string base_uint2<256>::GetHex() const;
template std::string base_uint2<256>::ToString() const;
template void base_uint2<256>::SetHex(const char*);
template void base_uint2<256>::SetHex(const std::string&);

static void inline HashMix(uint32_t& a, uint32_t& b, uint32_t& c)
{
    // Taken from lookup3, by Bob Jenkins.
    a -= c;
    a ^= ((c << 4) | (c >> 28));
    c += b;
    b -= a;
    b ^= ((a << 6) | (a >> 26));
    a += c;
    c -= b;
    c ^= ((b << 8) | (b >> 24));
    b += a;
    a -= c;
    a ^= ((c << 16) | (c >> 16));
    c += b;
    b -= a;
    b ^= ((a << 19) | (a >> 13));
    a += c;
    c -= b;
    c ^= ((b << 4) | (b >> 28));
    b += a;
}

static void inline HashFinal(uint32_t& a, uint32_t& b, uint32_t& c)
{
    // Taken from lookup3, by Bob Jenkins.
    c ^= b;
    c -= ((b << 14) | (b >> 18));
    a ^= c;
    a -= ((c << 11) | (c >> 21));
    b ^= a;
    b -= ((a << 25) | (a >> 7));
    c ^= b;
    c -= ((b << 16) | (b >> 16));
    a ^= c;
    a -= ((c << 4) | (c >> 28));
    b ^= a;
    b -= ((a << 14) | (a >> 18));
    c ^= b;
    c -= ((b << 24) | (b >> 8));
}

uint64_t uint256::GetHash(const uint256& salt) const
{
    uint32_t a, b, c;
    const uint32_t *pn = (const uint32_t*)data;
    const uint32_t *salt_pn = (const uint32_t*)salt.data;
    a = b = c = 0xdeadbeef + WIDTH;

    a += pn[0] ^ salt_pn[0];
    b += pn[1] ^ salt_pn[1];
    c += pn[2] ^ salt_pn[2];

    HashMix(a, b, c);

    a += pn[3] ^ salt_pn[3];
    b += pn[4] ^ salt_pn[4];
    c += pn[5] ^ salt_pn[5];

    HashMix(a, b, c);

    a += pn[6] ^ salt_pn[6];
    b += pn[7] ^ salt_pn[7];

    HashFinal(a, b, c);

    return ((((uint64_t)b) << 32) | c);
}

//~~~~~~~~~~~~~~~~~~~~~ FROM BITCOIN CORE 10 START ~~~~~~~~~~~~~~~~~~~~~

// This implementation directly uses shifts instead of going
// through an intermediate MPI representation.
uint256& uint256::SetCompact(uint32_t nCompact, bool* pfNegative, bool* pfOverflow)
{
    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;

    if (nSize <= 3)
    {
        nWord >>= 8 * (3 - nSize);

        *this = nWord;
    }
    else
    {
        *this = nWord;
        *this <<= 8 * (nSize - 3);
    }

    if (pfNegative)
    {
        *pfNegative = nWord != 0 && (nCompact & 0x00800000) != 0;
    }

    if (pfOverflow)
    {
        *pfOverflow = nWord != 0 && ((nSize > 34) ||
                                     (nWord > 0xff && nSize > 33) ||
                                     (nWord > 0xffff && nSize > 32));
    }

    return *this;
}

uint32_t uint256::GetCompact(bool fNegative) const
{
    int nSize = (bits() + 7) / 8;
    uint32_t nCompact = 0;

    if (nSize <= 3)
    {
        nCompact = GetLow64() << 8 * (3 - nSize);
    }
    else
    {
        uint256 bn = *this >> 8 * (nSize - 3);
        nCompact = bn.GetLow64();
    }

    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if (nCompact & 0x00800000)
    {
        nCompact >>= 8;
        nSize++;
    }

    if ((nCompact & ~0x007fffff) != 0)
    {
        if (fDebug)
        {
            LogPrint("uint", "%s : ERROR - (nCompact & ~0x007fffff) != 0 \n", __FUNCTION__);
        }

        return 0;
    }

    if (nSize >= 256)
    {
        if (fDebug)
        {
            LogPrint("uint", "%s : ERROR - nSize >= 256 \n", __FUNCTION__);
        }

        return 0;        
    }

    nCompact |= nSize << 24;
    nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0);

    return nCompact;
}

//~~~~~~~~~~~~~~~~~~~~~ FROM BITCOIN CORE 10 END ~~~~~~~~~~~~~~~~~~~~~