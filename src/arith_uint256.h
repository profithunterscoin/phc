// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (C) 2017-2018 Crypostle Core developers
// Copyright (c) 2018-2019 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#ifndef BITCOIN_ARITH_UINT256_H
#define BITCOIN_ARITH_UINT256_H

#include <cstring>
#include <stdexcept>
#include <stdint.h>

class uint256;


class uint_error : public std::runtime_error
{
    public:

        explicit uint_error(const std::string& str) : std::runtime_error(str) {}
};


/** Template base class for unsigned big integers. */
// base_uint2
template<unsigned int BITS> class base_uint2
{
    protected:

        enum
        {
            WIDTH=BITS/32
        };

        uint32_t pn[WIDTH];

    public:

        base_uint2()
        {
            for (int i = 0; i < WIDTH; i++)
            {
                pn[i] = 0;
            }
        }

        base_uint2(const base_uint2& b)
        {
            for (int i = 0; i < WIDTH; i++)
            {
                pn[i] = b.pn[i];
            }
        }

        base_uint2& operator=(const base_uint2& b)
        {
            for (int i = 0; i < WIDTH; i++)
            {
                pn[i] = b.pn[i];
            }
                
            return *this;
        }

        base_uint2(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);

            for (int i = 2; i < WIDTH; i++)
            {
                pn[i] = 0;
            }
        }

        explicit base_uint2(const std::string& str);

        bool operator!() const
        {
            for (int i = 0; i < WIDTH; i++)
            {
                if (pn[i] != 0)
                {
                    return false;
                }
            }

            return true;
        }

        const base_uint2 operator~() const
        {
            base_uint2 ret;

            for (int i = 0; i < WIDTH; i++)
            {
                ret.pn[i] = ~pn[i];
            }
            
            return ret;
        }

        const base_uint2 operator-() const
        {
            base_uint2 ret;

            for (int i = 0; i < WIDTH; i++)
            {
                ret.pn[i] = ~pn[i];
            }
            
            ret++;

            return ret;
        }

        double getdouble() const;

        base_uint2& operator=(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);

            for (int i = 2; i < WIDTH; i++)
            {
                pn[i] = 0;
            }
            
            return *this;
        }

        base_uint2& operator^=(const base_uint2& b)
        {
            for (int i = 0; i < WIDTH; i++)
            {
                pn[i] ^= b.pn[i];
            }
                
            return *this;
        }

        base_uint2& operator&=(const base_uint2& b)
        {
            for (int i = 0; i < WIDTH; i++)
            {
                pn[i] &= b.pn[i];
            }
                
            return *this;
        }

        base_uint2& operator|=(const base_uint2& b)
        {
            for (int i = 0; i < WIDTH; i++)
            {
                pn[i] |= b.pn[i];
            }
                
            return *this;
        }

        base_uint2& operator^=(uint64_t b)
        {
            pn[0] ^= (unsigned int)b;
            pn[1] ^= (unsigned int)(b >> 32);

            return *this;
        }

        base_uint2& operator|=(uint64_t b)
        {
            pn[0] |= (unsigned int)b;
            pn[1] |= (unsigned int)(b >> 32);

            return *this;
        }

        base_uint2& operator<<=(unsigned int shift);
        base_uint2& operator>>=(unsigned int shift);

        base_uint2& operator+=(const base_uint2& b)
        {
            uint64_t carry = 0;

            for (int i = 0; i < WIDTH; i++)
            {
                uint64_t n = carry + pn[i] + b.pn[i];

                pn[i] = n & 0xffffffff;
                carry = n >> 32;
            }

            return *this;
        }

        base_uint2& operator-=(const base_uint2& b)
        {
            *this += -b;

            return *this;
        }

        base_uint2& operator+=(uint64_t b64)
        {
            base_uint2 b;
            b = b64;
            *this += b;

            return *this;
        }

        base_uint2& operator-=(uint64_t b64)
        {
            base_uint2 b;
            b = b64;
            *this += -b;

            return *this;
        }

        base_uint2& operator*=(uint32_t b32);
        base_uint2& operator*=(const base_uint2& b);
        base_uint2& operator/=(const base_uint2& b);

        base_uint2& operator++()
        {
            // prefix operator
            int i = 0;

            while (++pn[i] == 0 && i < WIDTH-1)
            {
                i++;
            }
                
            return *this;
        }

        const base_uint2 operator++(int)
        {
            // postfix operator
            const base_uint2 ret = *this;
            ++(*this);

            return ret;
        }

        base_uint2& operator--()
        {
            // prefix operator
            int i = 0;

            while (--pn[i] == (uint32_t)-1 && i < WIDTH-1)
            {
                i++;
            }

            return *this;
        }

        const base_uint2 operator--(int)
        {
            // postfix operator
            const base_uint2 ret = *this;
            --(*this);

            return ret;
        }

        int CompareTo(const base_uint2& b) const;
        bool EqualTo(uint64_t b) const;

        friend inline const base_uint2 operator+(const base_uint2& a, const base_uint2& b) { return base_uint2(a) += b; }
        friend inline const base_uint2 operator-(const base_uint2& a, const base_uint2& b) { return base_uint2(a) -= b; }
        friend inline const base_uint2 operator*(const base_uint2& a, const base_uint2& b) { return base_uint2(a) *= b; }
        friend inline const base_uint2 operator/(const base_uint2& a, const base_uint2& b) { return base_uint2(a) /= b; }
        friend inline const base_uint2 operator|(const base_uint2& a, const base_uint2& b) { return base_uint2(a) |= b; }
        friend inline const base_uint2 operator&(const base_uint2& a, const base_uint2& b) { return base_uint2(a) &= b; }
        friend inline const base_uint2 operator^(const base_uint2& a, const base_uint2& b) { return base_uint2(a) ^= b; }
        friend inline const base_uint2 operator>>(const base_uint2& a, int shift) { return base_uint2(a) >>= shift; }
        friend inline const base_uint2 operator<<(const base_uint2& a, int shift) { return base_uint2(a) <<= shift; }
        friend inline const base_uint2 operator*(const base_uint2& a, uint32_t b) { return base_uint2(a) *= b; }
        
        friend inline bool operator==(const base_uint2& a, const base_uint2& b) { return memcmp(a.pn, b.pn, sizeof(a.pn)) == 0; }
        friend inline bool operator!=(const base_uint2& a, const base_uint2& b) { return memcmp(a.pn, b.pn, sizeof(a.pn)) != 0; }
        friend inline bool operator>(const base_uint2& a, const base_uint2& b) { return a.CompareTo(b) > 0; }
        friend inline bool operator<(const base_uint2& a, const base_uint2& b) { return a.CompareTo(b) < 0; }
        friend inline bool operator>=(const base_uint2& a, const base_uint2& b) { return a.CompareTo(b) >= 0; }
        friend inline bool operator<=(const base_uint2& a, const base_uint2& b) { return a.CompareTo(b) <= 0; }
        friend inline bool operator==(const base_uint2& a, uint64_t b) { return a.EqualTo(b); }
        friend inline bool operator!=(const base_uint2& a, uint64_t b) { return !a.EqualTo(b); }

        std::string GetHex() const;

        void SetHex(const char* psz);
        void SetHex(const std::string& str);

        std::string ToString() const;

        unsigned int size() const
        {
            return sizeof(pn);
        }

        /**
        * Returns the position of the highest bit set plus one, or zero if the
        * value is zero.
        */
        unsigned int bits() const;

        uint64_t GetLow64() const
        {
            if (WIDTH < 2)
            {
                return pn[0];
            }

            return pn[0] | (uint64_t)pn[1] << 32;
        }
};


/** 256-bit unsigned big integer. */
// base_uint2
class arith_uint256 : public base_uint2<256>
{
    public:
    
        arith_uint256() {}
        arith_uint256(const base_uint2<256>& b) : base_uint2<256>(b) {}
        arith_uint256(uint64_t b) : base_uint2<256>(b) {}
        
        explicit arith_uint256(const std::string& str) : base_uint2<256>(str) {}

        /**
        * The "compact" format is a representation of a whole
        * number N using an unsigned 32bit number similar to a
        * floating point format.
        * The most significant 8 bits are the unsigned exponent of base 256.
        * This exponent can be thought of as "number of bytes of N".
        * The lower 23 bits are the mantissa.
        * Bit number 24 (0x800000) represents the sign of N.
        * N = (-1^sign) * mantissa * 256^(exponent-3)
        *
        * Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
        * MPI uses the most significant bit of the first byte as sign.
        * Thus 0x1234560000 is compact (0x05123456)
        * and  0xc0de000000 is compact (0x0600c0de)
        *
        * Bitcoin only uses this "compact" format for encoding difficulty
        * targets, which are unsigned 256bit quantities.  Thus, all the
        * complexities of the sign bit and using base 256 are probably an
        * implementation accident.
        */
        arith_uint256& SetCompact(uint32_t nCompact, bool *pfNegative = NULL, bool *pfOverflow = NULL);
        
        uint32_t GetCompact(bool fNegative = false) const;

        friend uint256 ArithToUint256(const arith_uint256 &);
        friend arith_uint256 UintToArith256(const uint256 &);
};

uint256 ArithToUint256(const arith_uint256 &);
arith_uint256 UintToArith256(const uint256 &);

#endif // BITCOIN_ARITH_UINT256_H
