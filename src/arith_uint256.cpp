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


#include "arith_uint256.h"

#include "uint256.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

#include <stdio.h>
#include <string.h>

/* ONLY NEEDED FOR UNIT TESTING */
#include <iostream>
using namespace std;


// base_uint2(string)
template <unsigned int BITS> base_uint2<BITS>::base_uint2(const std::string& str)
{
    SetHex(str);
}

// base_uint2::operator<<=
template <unsigned int BITS> base_uint2<BITS>& base_uint2<BITS>::operator<<=(unsigned int shift)
{
    base_uint2<BITS> a(*this);

    for (int i = 0; i < WIDTH; i++)
    {   
        pn[i] = 0;
    }
        
    int k = shift / 32;
    shift = shift % 32;

    for (int i = 0; i < WIDTH; i++)
    {
        if (i + k + 1 < WIDTH && shift != 0)
        {
            pn[i + k + 1] |= (a.pn[i] >> (32 - shift));
        }
            
        if (i + k < WIDTH)
        {
            pn[i + k] |= (a.pn[i] << shift);
        }
            
    }

    return *this;
}

// base_uint2::operator>>=
template <unsigned int BITS> base_uint2<BITS>& base_uint2<BITS>::operator>>=(unsigned int shift)
{
    base_uint2<BITS> a(*this);

    for (int i = 0; i < WIDTH; i++)
    {
        pn[i] = 0;
    }
        
    int k = shift / 32;
    shift = shift % 32;

    for (int i = 0; i < WIDTH; i++)
    {
        if (i - k - 1 >= 0 && shift != 0)
        {
            pn[i - k - 1] |= (a.pn[i] << (32 - shift));
        }
            
        if (i - k >= 0)
        {
            pn[i - k] |= (a.pn[i] >> shift);
        }
            
    }

    return *this;
}

// base_uint2::operator*=
template <unsigned int BITS> base_uint2<BITS>& base_uint2<BITS>::operator*=(uint32_t b32)
{
    uint64_t carry = 0;

    for (int i = 0; i < WIDTH; i++)
    {
        uint64_t n = carry + (uint64_t)b32 * pn[i];
        pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }

    return *this;
}

// base_uint2::operator*=
template <unsigned int BITS> base_uint2<BITS>& base_uint2<BITS>::operator*=(const base_uint2& b)
{
    base_uint2<BITS> a = *this;
    *this = 0;

    for (int j = 0; j < WIDTH; j++)
    {
        uint64_t carry = 0;

        for (int i = 0; i + j < WIDTH; i++)
        {
            uint64_t n = carry + pn[i + j] + (uint64_t)a.pn[j] * b.pn[i];
            pn[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }

    return *this;
}

// base_uint2::operator/=
template <unsigned int BITS> base_uint2<BITS>& base_uint2<BITS>::operator/=(const base_uint2& b)
{
    base_uint2<BITS> div = b;     // make a copy, so we can shift.
    base_uint2<BITS> num = *this; // make a copy, so we can subtract.
    *this = 0;                   // the quotient.

    int num_bits = num.bits();
    int div_bits = div.bits();

    if (div_bits == 0)
    {
        throw uint_error("Division by zero");
    }
        
    if (div_bits > num_bits)
    {
        // the result is certainly 0.
        return *this;
    } 

    int shift = num_bits - div_bits;
    div <<= shift; // shift so that div and num align.

    while (shift >= 0)
    {
        if (num >= div)
        {
            num -= div;
            pn[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }

        div >>= 1; // shift back.
        shift--;
    }

    // num now contains the remainder of the division.
    return *this;
}

// base_uint2::CompareTo()
template <unsigned int BITS> int base_uint2<BITS>::CompareTo(const base_uint2<BITS>& b) const
{
    for (int i = WIDTH - 1; i >= 0; i--)
    {
        if (pn[i] < b.pn[i])
        {
            return -1;
        }
            
        if (pn[i] > b.pn[i])
        {
            return 1;
        }
    }

    return 0;
}

// base_uint2::EqualTo()
template <unsigned int BITS> bool base_uint2<BITS>::EqualTo(uint64_t b) const
{
    for (int i = WIDTH - 1; i >= 2; i--)
    {
        if (pn[i])
        {
            return false;
        }
    }

    if (pn[1] != (b >> 32))
    {
        return false;
    }
        

    if (pn[0] != (b & 0xfffffffful))
    {
        return false;
    }

    return true;
}

// base_uint2::getdouble()
template <unsigned int BITS> double base_uint2<BITS>::getdouble() const
{
    double ret = 0.0;
    double fact = 1.0;

    for (int i = 0; i < WIDTH; i++)
    {
        ret += fact * pn[i];
        fact *= 4294967296.0;
    }

    return ret;
}

// base_uint2::GetHex()
template <unsigned int BITS> std::string base_uint2<BITS>::GetHex() const
{
    return ArithToUint256(*this).GetHex();
}

// base_uint2::SetHex()
template <unsigned int BITS> void base_uint2<BITS>::SetHex(const char* psz)
{
    *this = UintToArith256(uint256S(psz));
}

// base_uint2::SetHex()
template <unsigned int BITS> void base_uint2<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

// base_uint2::ToString()
template <unsigned int BITS> std::string base_uint2<BITS>::ToString() const
{
    return (GetHex());
}

// base_uint2::bits()
template <unsigned int BITS> unsigned int base_uint2<BITS>::bits() const
{
    for (int pos = WIDTH - 1; pos >= 0; pos--)
    {
        if (pn[pos])
        {
            for (int bits = 31; bits > 0; bits--)
            {
                if (pn[pos] & 1 << bits)
                {
                    return 32 * pos + bits + 1;
                }
            }

            return 32 * pos + 1;
        }
    }

    return 0;
}

// Explicit instantiations for base_uint2<256>
template base_uint2<256>::base_uint2(const std::string&);
template base_uint2<256>& base_uint2<256>::operator<<=(unsigned int);
template base_uint2<256>& base_uint2<256>::operator>>=(unsigned int);
template base_uint2<256>& base_uint2<256>::operator*=(uint32_t b32);
template base_uint2<256>& base_uint2<256>::operator*=(const base_uint2<256>& b);
template base_uint2<256>& base_uint2<256>::operator/=(const base_uint2<256>& b);

template int base_uint2<256>::CompareTo(const base_uint2<256>&) const;
template bool base_uint2<256>::EqualTo(uint64_t) const;
template double base_uint2<256>::getdouble() const;
template std::string base_uint2<256>::GetHex() const;
template std::string base_uint2<256>::ToString() const;
template void base_uint2<256>::SetHex(const char*);
template void base_uint2<256>::SetHex(const std::string&);
template unsigned int base_uint2<256>::bits() const;

// This implementation directly uses shifts instead of going
// through an intermediate MPI representation.
// arith_uint256::SetCompact()
arith_uint256& arith_uint256::SetCompact(uint32_t nCompact, bool* pfNegative, bool* pfOverflow)
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
        *pfOverflow = nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32));
    }

    return *this;
}

// arith_uint256::GetCompact()
uint32_t arith_uint256::GetCompact(bool fNegative) const
{
    int nSize = (bits() + 7) / 8;
    uint32_t nCompact = 0;

    if (nSize <= 3)
    {
        nCompact = GetLow64() << 8 * (3 - nSize);
    }
    else
    {
        arith_uint256 bn = *this >> 8 * (nSize - 3);
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
        /*
        if (fDebug)
        {
            LogPrint("uint", "%s : ERROR - (nCompact & ~0x007fffff) != 0 \n", __FUNCTION__);
        }
        */

        return 0;
    }
    
    if (nSize >= 256)
    {
        /*
        if (fDebug)
        {
            LogPrint("uint", "%s : ERROR - nSize >= 256 \n", __FUNCTION__);
        }
        */

        return 0;
    }
    
    nCompact |= nSize << 24;
    nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    
    return nCompact;
}

// ArithToUint256()
uint256 ArithToUint256(const arith_uint256 &a)
{
    uint256 b;

    for(int x=0; x<a.WIDTH; ++x)
    {
        WriteLE32(b.begin() + x*4, a.pn[x]);
    }
        
    return b;
}

// UintToArith256()
arith_uint256 UintToArith256(const uint256 &a)
{
    arith_uint256 b;

    for(int x=0; x<b.WIDTH; ++x)
    {
        b.pn[x] = ReadLE32(a.begin() + x*4);
    }
        
    return b;
}
