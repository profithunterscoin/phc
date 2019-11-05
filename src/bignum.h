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


#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <openssl/bn.h>

#include <stdexcept>
#include <vector>

#include <stdint.h>

/** Errors thrown by the bignum class */
class bignum_error : public std::runtime_error
{
    public:

        explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};


/** RAII encapsulated BN_CTX (OpenSSL bignum context) */
class CAutoBN_CTX
{
    protected:

        BN_CTX* pctx;
        BN_CTX* operator=(BN_CTX* pnew)
        {
            return pctx = pnew;
        }

    public:

        CAutoBN_CTX()
        {
            pctx = BN_CTX_new();

            if (pctx == NULL)
            {
                throw bignum_error("CAutoBN_CTX : BN_CTX_new() returned NULL");
            }
        }

        ~CAutoBN_CTX()
        {
            if (pctx != NULL)
            {
                BN_CTX_free(pctx);
            }
        }

        operator BN_CTX*()
        {
            return pctx;
        }
        
        BN_CTX& operator*()
        {
            return *pctx;
        }
        
        BN_CTX** operator&()
        {
            return &pctx;
        }
        
        bool operator!()
        {
            return (pctx == NULL);
        }
};


/** C++ wrapper for BIGNUM (OpenSSL bignum) */

#if OPENSSL_VERSION_NUMBER < 0x10100000L  // OPENSSL 1.0
class CBigNum : public BIGNUM
{
    public:

        CBigNum()
        {
            BN_init(this);
        }

        CBigNum(const CBigNum& b)
        {
            BN_init(this);

            if (!BN_copy(this, &b))
            {
                BN_clear_free(this);
#else // OPENSSL 1.1+
class CBigNum
{
    BIGNUM* bn;

    public:

        CBigNum() : bn(BN_new())
        {}

        CBigNum(const CBigNum& b) : CBigNum()
        {
            if (!BN_copy(bn, b.bn))
            {
                BN_clear_free(bn);
#endif           
                throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_copy failed");
            }
        }

        CBigNum& operator=(const CBigNum& b)
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_copy(this, &b))
#else // OPENSSL 1.1+
            if (!BN_copy(bn, b.bn))
#endif
            {
                throw bignum_error("CBigNum::operator= : BN_copy failed");
            }
            
            return (*this);
        }

        ~CBigNum()
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_clear_free(this);	
        }

        //CBigNum(char n) is not portable.  Use 'signed char' or 'unsigned char'.
        CBigNum(signed char n)
        {
            BN_init(this);

            if (n >= 0)
            {
                setulong(n);
            }
            else
            {
                setint64(n);
            }
        }
        
        CBigNum(short n)
        {
            BN_init(this);

            if (n >= 0)
            {
                setulong(n);
            }
            else 
            {
                setint64(n);
            }
        }
        
        CBigNum(int n)
        {
            BN_init(this);

            if (n >= 0)
            {
            setulong(n);
            }
            else
            {
            setint64(n);
            }
        }
        
        CBigNum(long n)
        {
            BN_init(this);

            if (n >= 0)
            {
                setulong(n);
            }
            else
            {
                setint64(n);
            }
        }

        CBigNum(long long n)
        {
            BN_init(this);

            setint64(n);
        }
        
        CBigNum(unsigned char n)
        {
            BN_init(this);
        
            setulong(n);
        }
        
        CBigNum(unsigned short n)
        {
            BN_init(this);
            
            setulong(n);
        }
        
        CBigNum(unsigned int n)
        {
            BN_init(this);
            
            setulong(n);
        }
        
        CBigNum(unsigned long n)
        {
            BN_init(this);
            
            setulong(n);
        }
        
        CBigNum(unsigned long long n)
        {
            BN_init(this);
            
            setuint64(n);
        }
        
        explicit CBigNum(uint256 n)
        {
            BN_init(this);
            
            setuint256(n);
        }

        explicit CBigNum(const std::vector<unsigned char>& vch)
        {
            BN_init(this);

#else // OPENSSL 1.1+
            BN_clear_free(bn);
        }

        //CBigNum(char n) is not portable.  Use 'signed char' or 'unsigned char'.
        CBigNum(signed char n) : CBigNum()
        {
            if (n >= 0)
            {
                setulong(n);
            }
            else
            {
                setint64(n);
            }
        }
        
        CBigNum(short n) : CBigNum()
        {
            if (n >= 0)
            {
                setulong(n);
            }
            else 
            {
                setint64(n);
            }
        }
        
        CBigNum(int n) : CBigNum()
        {
            if (n >= 0)
            {
            setulong(n);
            }
            else
            {
            setint64(n);
            }
        }
        
        CBigNum(long n) : CBigNum()
        {
            if (n >= 0)
            {
                setulong(n);
            }
            else
            {
                setint64(n);
            }
        }

        CBigNum(long long n) : CBigNum() 
        {
            setint64(n);
        }
        
        CBigNum(unsigned char n) : CBigNum() 
        {       
            setulong(n);
        }
        
        CBigNum(unsigned short n) : CBigNum() 
        {            
            setulong(n);
        }
        
        CBigNum(unsigned int n) : CBigNum() 
        {           
            setulong(n);
        }
        
        CBigNum(unsigned long n) : CBigNum() 
        {            
            setulong(n);
        }
        
        CBigNum(unsigned long long n) : CBigNum() 
        {            
            setuint64(n);
        }
        
        explicit CBigNum(uint256 n) : CBigNum() 
        {            
            setuint256(n);
        }

        explicit CBigNum(const std::vector<unsigned char>& vch) : CBigNum()
        {
#endif  
            setvch(vch);
        }

        /** Generates a cryptographically secure random number between zero and range exclusive
        * i.e. 0 < returned number < range
        * @param range The upper bound on the number.
        * @return
        */
        static CBigNum  randBignum(const CBigNum& range)
        {
            CBigNum ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if(!BN_rand_range(&ret, &range))
#else  // OPENSSL 1.1+
            if(!BN_rand_range(ret.bn, range.bn))
#endif
            {
                throw bignum_error("CBigNum:rand element : BN_rand_range failed");
            }
        
            return ret;
        }

        /** Generates a cryptographically secure random k-bit number
        * @param k The bit length of the number.
        * @return
        */
        static CBigNum RandKBitBigum(const uint32_t k)
        {
            CBigNum ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if(!BN_rand(&ret, k, -1, 0))
#else  // OPENSSL 1.1+
            if(!BN_rand(ret.bn, k, -1, 0))
#endif
            {
                throw bignum_error("CBigNum:rand element : BN_rand failed");
            }
        
            return ret;
        }

        /**Returns the size in bits of the underlying bignum.
        *
        * @return the size
        */
        int bitSize() const
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            return  BN_num_bits(this);
#else // OPENSSL 1.1+
            return  BN_num_bits(bn);
#endif
        }

        void setulong(unsigned long n)
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_set_word(this, n))
#else // OPENSSL 1.1+
            if (!BN_set_word(bn, n))
#endif
            {
                throw bignum_error("CBigNum conversion from unsigned long : BN_set_word failed");
            }
        }

        unsigned long getulong() const
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            return BN_get_word(this);
#else // OPENSSL 1.1+
            return BN_get_word(bn);
#endif
        }

        unsigned int getuint() const
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            return BN_get_word(this);
#else // OPENSSL 1.1+
            return BN_get_word(bn);
#endif
        }

        int getint() const
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            unsigned long n = BN_get_word(this);

            if (!BN_is_negative(this))
#else // OPENSSL 1.1+
            unsigned long n = BN_get_word(bn);

            if (!BN_is_negative(bn))
#endif
            {
                return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : n);
            }
            else
            {
                return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::min() : -(int)n);
            }
        }

        void setint64(int64_t sn)
        {
            unsigned char pch[sizeof(sn) + 6];
            unsigned char* p = pch + 4;
            
            bool fNegative;
            
            uint64_t n;

            if (sn < (int64_t)0)
            {
                // Since the minimum signed integer cannot be represented as positive so long as its type is signed, and it's not well-defined what happens if you make it unsigned before negating it, we instead increment the negative integer by 1, convert it, then increment the (now positive) unsigned integer by 1 to compensate
                n = -(sn + 1);
                ++n;
                
                fNegative = true;
            }
            else
            {
                n = sn;

                fNegative = false;
            }

            bool fLeadingZeroes = true;
            
            for (int i = 0; i < 8; i++)
            {
                unsigned char c = (n >> 56) & 0xff;
                
                n <<= 8;
                
                if (fLeadingZeroes)
                {
                    if (c == 0)
                    {
                        continue;
                    }
                    if (c & 0x80)
                    {
                        *p++ = (fNegative ? 0x80 : 0);
                    }
                    else if (fNegative)
                    {
                        c |= 0x80;
                    }

                    fLeadingZeroes = false;
                }
                
                *p++ = c;
            }
            
            unsigned int nSize = p - (pch + 4);
            
            pch[0] = (nSize >> 24) & 0xff;
            pch[1] = (nSize >> 16) & 0xff;
            pch[2] = (nSize >> 8) & 0xff;
            pch[3] = (nSize) & 0xff;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_mpi2bn(pch, p - pch, this);
#else // OPENSSL 1.1+
            BN_mpi2bn(pch, p - pch, bn);
#endif
        }

        uint64_t getuint64()
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            unsigned int nSize = BN_bn2mpi(this, NULL);
#else // OPENSSL 1.1+
            unsigned int nSize = BN_bn2mpi(bn, NULL);
#endif
            
            if (nSize < 4)
            {
                return 0;
            }

            std::vector<unsigned char> vch(nSize);

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_bn2mpi(this, &vch[0]);
#else // OPENSSL 1.1+
            BN_bn2mpi(bn, &vch[0]);
#endif       
            if (vch.size() > 4)
            {
                vch[4] &= 0x7f;
            }
            
            uint64_t n = 0;
            
            for (unsigned int i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            {
                ((unsigned char*)&n)[i] = vch[j];
            }
            
            return n;
        }

        void setuint64(uint64_t n)
        {
            unsigned char pch[sizeof(n) + 6];
            unsigned char* p = pch + 4;
            
            bool fLeadingZeroes = true;
            
            for (int i = 0; i < 8; i++)
            {
                unsigned char c = (n >> 56) & 0xff;
                
                n <<= 8;

                if (fLeadingZeroes)
                {
                    if (c == 0)
                    {
                        continue;
                    }

                    if (c & 0x80)
                    {
                        *p++ = 0;
                    }

                    fLeadingZeroes = false;
                }

                *p++ = c;
            }
            
            unsigned int nSize = p - (pch + 4);
            
            pch[0] = (nSize >> 24) & 0xff;
            pch[1] = (nSize >> 16) & 0xff;
            pch[2] = (nSize >> 8) & 0xff;
            pch[3] = (nSize) & 0xff;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_mpi2bn(pch, p - pch, this); 
#else // OPENSSL 1.1+
            BN_mpi2bn(pch, p - pch, bn);
#endif
        }

        void setuint256(uint256 n)
        {
            unsigned char pch[sizeof(n) + 6];
            unsigned char* p = pch + 4;
            
            bool fLeadingZeroes = true;
            
            unsigned char* pbegin = (unsigned char*)&n;
            unsigned char* psrc = pbegin + sizeof(n);
            
            while (psrc != pbegin)
            {
                unsigned char c = *(--psrc);

                if (fLeadingZeroes)
                {
                    if (c == 0)
                    {
                        continue;
                    }

                    if (c & 0x80)
                    {
                        *p++ = 0;
                    }

                    fLeadingZeroes = false;
                }
                
                *p++ = c;
            }
            
            unsigned int nSize = p - (pch + 4);
            
            pch[0] = (nSize >> 24) & 0xff;
            pch[1] = (nSize >> 16) & 0xff;
            pch[2] = (nSize >> 8) & 0xff;
            pch[3] = (nSize >> 0) & 0xff;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_mpi2bn(pch, p - pch, this);
#else // OPENSSL 1.1+
            BN_mpi2bn(pch, p - pch, bn);
#endif
        }

        uint256 getuint256() const
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            unsigned int nSize = BN_bn2mpi(this, NULL);
#else // OPENSSL 1.1+
            unsigned int nSize = BN_bn2mpi(bn, NULL);
#endif

            if (nSize < 4)
            {
                return 0;
            }
            
            std::vector<unsigned char> vch(nSize);

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_bn2mpi(this, &vch[0]);
#else // OPENSSL 1.1+
            BN_bn2mpi(bn, &vch[0]);
#endif

            if (vch.size() > 4)
            {
                vch[4] &= 0x7f;
            }
            
            uint256 n = 0;
            
            for (unsigned int i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            {
                ((unsigned char*)&n)[i] = vch[j];
            }
            
            return n;
        }


        void setvch(const std::vector<unsigned char>& vch)
        {
            std::vector<unsigned char> vch2(vch.size() + 4);
            
            unsigned int nSize = vch.size();
            
            // BIGNUM's byte stream format expects 4 bytes of
            // big endian size data info at the front
            vch2[0] = (nSize >> 24) & 0xff;
            vch2[1] = (nSize >> 16) & 0xff;
            vch2[2] = (nSize >> 8) & 0xff;
            vch2[3] = (nSize >> 0) & 0xff;
            
            // swap data to big endian
            reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_mpi2bn(&vch2[0], vch2.size(), this);
#else // OPENSSL 1.1+
            BN_mpi2bn(&vch2[0], vch2.size(), bn);
#endif
        }

        std::vector<unsigned char> getvch() const
        {

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            unsigned int nSize = BN_bn2mpi(this, NULL);
#else // OPENSSL 1.1+
            unsigned int nSize = BN_bn2mpi(bn, NULL);
#endif       
            if (nSize <= 4)
            {
                return std::vector<unsigned char>();
            }
            
            std::vector<unsigned char> vch(nSize);

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_bn2mpi(this, &vch[0]);
#else // OPENSSL 1.1+
            BN_bn2mpi(bn, &vch[0]);
#endif            
            vch.erase(vch.begin(), vch.begin() + 4);
            
            reverse(vch.begin(), vch.end());
            
            return vch;
        }

        CBigNum& SetCompact(unsigned int nCompact)
        {
            unsigned int nSize = nCompact >> 24;
            
            std::vector<unsigned char> vch(4 + nSize);
            
            vch[3] = nSize;
            
            if (nSize >= 1)
            {
                vch[4] = (nCompact >> 16) & 0xff;
            }
            
            if (nSize >= 2)
            {
                vch[5] = (nCompact >> 8) & 0xff;
            }
            
            if (nSize >= 3)
            {
                vch[6] = (nCompact >> 0) & 0xff;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_mpi2bn(&vch[0], vch.size(), this);
#else // OPENSSL 1.1+
            BN_mpi2bn(&vch[0], vch.size(), bn);
#endif
            return *this;
        }

        unsigned int GetCompact() const
        {

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            unsigned int nSize = BN_bn2mpi(this, NULL);
#else // OPENSSL 1.1+
            unsigned int nSize = BN_bn2mpi(bn, NULL);
#endif
            std::vector<unsigned char> vch(nSize);
            
            nSize -= 4;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_bn2mpi(this, &vch[0]);
#else // OPENSSL 1.1+
            BN_bn2mpi(bn, &vch[0]);
#endif
            unsigned int nCompact = nSize << 24;
            
            if (nSize >= 1)
            {
                nCompact |= (vch[4] << 16);
            }
            
            if (nSize >= 2)
            {
                nCompact |= (vch[5] << 8);
            }
            
            if (nSize >= 3)
            {
                nCompact |= (vch[6] << 0);
            }
            
            return nCompact;
        }

        void SetHex(const std::string& str)
        {
            // skip 0x
            const char* psz = str.c_str();
            
            while (isspace(*psz))
            {
                psz++;
            }

            bool fNegative = false;
            
            if (*psz == '-')
            {
                fNegative = true;

                psz++;
            }
            
            if (psz[0] == '0' && tolower(psz[1]) == 'x')
            {
                psz += 2;
            }
            
            while (isspace(*psz))
            {
                psz++;
            }

            // hex string to bignum
            *this = 0;
            int n;
            
            while ((n = HexDigit(*psz)) != -1)
            {
                *this <<= 4;
                *this += n;

                ++psz;
            }
            
            if (fNegative)
            {
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
                *this = 0 - *this;
#else // OPENSSL 1.1+
                BN_set_negative(bn, 1);
#endif
            }
        }

        std::string ToString(int nBase=10) const
        {
            CAutoBN_CTX pctx;
            CBigNum bnBase = nBase;
            CBigNum bn0 = 0;
            std::string str;
            CBigNum bn = *this;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            BN_set_negative(&bn, false);
#else // OPENSSL 1.1+
            BN_set_negative(bn.bn, false);
#endif

            CBigNum dv;
            CBigNum rem;

#if OPENSSL_VERSION_NUMBER < 0x10100000L       // OPENSSL 1.0
            if (BN_cmp(&bn, &bn0) == 0)
#else // OPENSSL 1.1+
            if (BN_cmp(bn.bn, bn0.bn) == 0)
#endif
            {
                return "0";
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L      // OPENSSL 1.0
            while (BN_cmp(&bn, &bn0) > 0)
            {
                if (!BN_div(&dv, &rem, &bn, &bnBase, pctx))
#else // OPENSSL 1.1+
            while (BN_cmp(bn.bn, bn0.bn) > 0)
            {
                if (!BN_div(dv.bn, rem.bn, bn.bn, bnBase.bn, pctx))
#endif
                {
                    throw bignum_error("CBigNum::ToString() : BN_div failed");
                }
                
                bn = dv;

                unsigned int c = rem.getulong();
                
                str += "0123456789abcdef"[c];
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (BN_is_negative(this))
#else // OPENSSL 1.1+
            if (BN_is_negative(this->bn))
#endif
            {
                str += "-";
            }
            
            reverse(str.begin(), str.end());
            
            return str;
        }

        std::string GetHex() const
        {
            return ToString(16);
        }

        unsigned int GetSerializeSize(int nType=0, int nVersion=PROTOCOL_VERSION) const
        {
            return ::GetSerializeSize(getvch(), nType, nVersion);
        }

        template<typename Stream> void Serialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION) const
        {
            ::Serialize(s, getvch(), nType, nVersion);
        }

        template<typename Stream> void Unserialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION)
        {
            std::vector<unsigned char> vch;
            ::Unserialize(s, vch, nType, nVersion);
            setvch(vch);
        }

        /**
        * exponentiation with an int. this^e
        * @param e the exponent as an int
        * @return
        */
        CBigNum pow(const int e) const
        {
            return this->pow(CBigNum(e));
        }

        /**
        * exponentiation this^e
        * @param e the exponent
        * @return
        */
        CBigNum pow(const CBigNum& e) const
        {
            CAutoBN_CTX pctx;
        
            CBigNum ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_exp(&ret, this, &e, pctx))
#else // OPENSSL 1.1+
            if (!BN_exp(ret.bn, bn, e.bn, pctx))
#endif
            {
                throw bignum_error("CBigNum::pow : BN_exp failed");
            }
        
            return ret;
        }

        /**
        * modular multiplication: (this * b) mod m
        * @param b operand
        * @param m modulus
        */
        CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const
        {
            CAutoBN_CTX pctx;
        
            CBigNum ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_mod_mul(&ret, this, &b, &m, pctx))
#else // OPENSSL 1.1+
            if (!BN_mod_mul(ret.bn, bn, b.bn, m.bn, pctx))
#endif
            {
                throw bignum_error("CBigNum::mul_mod : BN_mod_mul failed");
            }
            
            return ret;
        }

        /**
        * modular exponentiation: this^e mod n
        * @param e exponent
        * @param m modulus
        */
        CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const
        {
            CAutoBN_CTX pctx;
            
            CBigNum ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if( e < 0)
#else // OPENSSL 1.1+
            if(BN_is_negative(e.bn))
#endif
            {
                // g^-x = (g^-1)^x

                CBigNum inv = this->inverse(m);

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
                CBigNum posE = e * -1;
                if (!BN_mod_exp(&ret, &inv, &posE, &m, pctx))
#else // OPENSSL 1.1+
                CBigNum posE(e);
                BN_set_negative(posE.bn, !BN_is_negative(e.bn));
                if (!BN_mod_exp(ret.bn, inv.bn, posE.bn, m.bn, pctx))
#endif

                {
                    throw bignum_error("CBigNum::pow_mod: BN_mod_exp failed on negative exponent");
                }
            }
            else
            {

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
                if (!BN_mod_exp(&ret, this, &e, &m, pctx))
#else // OPENSSL 1.1+
                if (!BN_mod_exp(ret.bn, bn, e.bn, m.bn, pctx))
#endif
                {
                    throw bignum_error("CBigNum::pow_mod : BN_mod_exp failed");
                }
            }

            return ret;
        }

        /**
        * Calculates the inverse of this element mod m.
        * i.e. i such this*i = 1 mod m
        * @param m the modu
        * @return the inverse
        */
        CBigNum inverse(const CBigNum& m) const
        {
            CAutoBN_CTX pctx;
            
            CBigNum ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_mod_inverse(&ret, this, &m, pctx))
#else // OPENSSL 1.1+
            if (!BN_mod_inverse(ret.bn, bn, m.bn, pctx))
#endif
            {
                throw bignum_error("CBigNum::inverse*= :BN_mod_inverse");
            }
            
            return ret;
        }

        /**
        * Generates a random (safe) prime of numBits bits
        * @param numBits the number of bits
        * @param safe true for a safe prime
        * @return the prime
        */
        static CBigNum generatePrime(const unsigned int numBits, bool safe = false)
        {
            CBigNum ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if(!BN_generate_prime_ex(&ret, numBits, (safe == true), NULL, NULL, NULL))
#else // OPENSSL 1.1+
            if(!BN_generate_prime_ex(ret.bn, numBits, (safe == true), NULL, NULL, NULL))
#endif
            {
                throw bignum_error("CBigNum::generatePrime*= :BN_generate_prime_ex");
            }

            return ret;
        }

        /**
        * Calculates the greatest common divisor (GCD) of two numbers.
        * @param m the second element
        * @return the GCD
        */
        CBigNum gcd( const CBigNum& b) const
        {
            CAutoBN_CTX pctx;
            
            CBigNum ret;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_gcd(&ret, this, &b, pctx))
#else // OPENSSL 1.1+
            if (!BN_gcd(ret.bn, bn, b.bn, pctx))
#endif
            {
                throw bignum_error("CBigNum::gcd*= :BN_gcd");
            }
            
            return ret;
        }

        /**
        * Miller-Rabin primality test on this element
        * @param checks: optional, the number of Miller-Rabin tests to run
        * default causes error rate of 2^-80.
        * @return true if prime
        */
        bool isPrime(const int checks=BN_prime_checks) const
        {
            CAutoBN_CTX pctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
    int ret = BN_is_prime(this, checks, NULL, pctx, NULL);
#else // OPENSSL 1.1+
    int ret = BN_is_prime_ex(bn, checks, pctx, NULL);
#endif
            if(ret < 0)
            {
                throw bignum_error("CBigNum::isPrime :BN_is_prime");
            }
            
            return ret;
        }

        bool isOne() const
        {

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            return BN_is_one(this);
#else // OPENSSL 1.1+
            return BN_is_one(bn);
#endif
        }

        bool operator!() const
        {

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            return BN_is_zero(this);
#else // OPENSSL 1.1+
            return BN_is_zero(bn);
#endif
        }

        CBigNum& operator+=(const CBigNum& b)
        {

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_add(this, this, &b))
#else // OPENSSL 1.1+
            if (!BN_add(bn, bn, b.bn))
#endif
            {
                throw bignum_error("CBigNum::operator+= : BN_add failed");
            }
            
            return *this;
        }

        CBigNum& operator-=(const CBigNum& b)
        {

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            *this = *this - b;
#else // OPENSSL 1.1+
            if (!BN_sub(bn, bn, b.bn))
            {
                throw bignum_error("CBigNum::operator-= : BN_sub failed");
            }
#endif

            return *this;
        }

        CBigNum& operator*=(const CBigNum& b)
        {
            CAutoBN_CTX pctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_mul(this, this, &b, pctx))
#else // OPENSSL 1.1+
            if (!BN_mul(bn, bn, b.bn, pctx))
#endif
            {
                throw bignum_error("CBigNum::operator*= : BN_mul failed");
            }
            
            return *this;
        }

        CBigNum& operator/=(const CBigNum& b)
        {
            CAutoBN_CTX pctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            *this = *this / b;
#else // OPENSSL 1.1+
            if (!BN_div(bn, NULL, bn, b.bn, pctx))
            {
                throw bignum_error("CBigNum::operator/= : BN_div failed");
            }
#endif
            return *this;
        }

        CBigNum& operator%=(const CBigNum& b)
        {
            CAutoBN_CTX pctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            *this = *this % b;
#else // OPENSSL 1.1+
            if (!BN_div(NULL, bn, bn, b.bn, pctx))
            {
                throw bignum_error("CBigNum::operator%= : BN_div failed");
            }
#endif
            
            return *this;
        }

        CBigNum& operator<<=(unsigned int shift)
        {

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_lshift(this, this, shift))
#else // OPENSSL 1.1+
            if (!BN_lshift(bn, bn, shift))
#endif
            {
                throw bignum_error("CBigNum:operator<<= : BN_lshift failed");
            }
            
            return *this;
        }

        CBigNum& operator>>=(unsigned int shift)
        {
            // Note: BN_rshift segfaults on 64-bit if 2^shift is greater than the number
            //   if built on ubuntu 9.04 or 9.10, probably depends on version of OpenSSL
            CBigNum a = 1;
            
            a <<= shift;
            
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (BN_cmp(&a, this) > 0)
#else // OPENSSL 1.1+
            if (BN_cmp(a.bn, bn) > 0)
#endif
            {
                *this = 0;
                
                return *this;
            }

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_rshift(this, this, shift))
#else // OPENSSL 1.1+
            if (!BN_rshift(bn, bn, shift))
#endif
            {
                throw bignum_error("CBigNum:operator>>= : BN_rshift failed");
            }
            
            return *this;
        }

        CBigNum& operator++()
        {
            // prefix operator

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_add(this, this, BN_value_one()))
#else // OPENSSL 1.1+
            if (!BN_add(bn, bn, BN_value_one()))
#endif
            {
                throw bignum_error("CBigNum::operator++ : BN_add failed");
            }
            
            return *this;
        }

        const CBigNum operator++(int)
        {
            // postfix operator
            const CBigNum ret = *this;
            
            ++(*this);
            
            return ret;
        }

        CBigNum& operator--()
        {
            // prefix operator
            CBigNum r;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
            if (!BN_sub(&r, this, BN_value_one()))
#else // OPENSSL 1.1+
            if (!BN_sub(r.bn, bn, BN_value_one()))
#endif
            {
                throw bignum_error("CBigNum::operator-- : BN_sub failed");
            }
            
            *this = r;
            
            return *this;
        }

        const CBigNum operator--(int)
        {
            // postfix operator
            const CBigNum ret = *this;
            
            --(*this);
            
            return ret;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
    friend inline const CBigNum operator-(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator/(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator%(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator*(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<(const CBigNum& a, const CBigNum& b);
#else // OPENSSL 1.1+
    const BIGNUM* to_bignum() const
    {
        return bn;
    }

    BIGNUM* to_bignum()
    {
        return bn;
    }
#endif

};


inline const CBigNum operator+(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (!BN_add(&r, &a, &b))
#else // OPENSSL 1.1+
    if (!BN_add(r.to_bignum(), a.to_bignum(), b.to_bignum()))
#endif
    {
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    }
    
    return r;
}


inline const CBigNum operator-(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
    if (!BN_sub(&r, &a, &b))
#else // OPENSSL 1.1+
    if (!BN_sub(r.to_bignum(), a.to_bignum(), b.to_bignum()))
#endif
    {
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    }
    
    return r;
}


inline const CBigNum operator-(const CBigNum& a)
{
    CBigNum r(a);

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
    BN_set_negative(&r, !BN_is_negative(&r));
#else // OPENSSL 1.1+
    BN_set_negative(r.to_bignum(), !BN_is_negative(r.to_bignum()));
#endif
    
    return r;
}


inline const CBigNum operator*(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    
    CBigNum r;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
    if (!BN_mul(&r, &a, &b, pctx))
#else // OPENSSL 1.1+
    if (!BN_mul(r.to_bignum(), a.to_bignum(), b.to_bignum(), pctx))
#endif
    {
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    }
    
    return r;
}


inline const CBigNum operator/(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    
    CBigNum r;

#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
    if (!BN_div(&r, NULL, &a, &b, pctx))
#else // OPENSSL 1.1+
    if (!BN_div(r.to_bignum(), NULL, a.to_bignum(), b.to_bignum(), pctx))
#endif
    {
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    }
    
    return r;
}


inline const CBigNum operator%(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    
    CBigNum r;
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
    if (!BN_nnmod(&r, &a, &b, pctx))
#else // OPENSSL 1.1+
    if (!BN_nnmod(r.to_bignum(), a.to_bignum(), b.to_bignum(), pctx))
#endif
    {
        throw bignum_error("CBigNum::operator% : BN_div failed");
    }
    
    return r;
}


inline const CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r;
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L   // OPENSSL 1.0
    if (!BN_lshift(&r, &a, shift))
#else // OPENSSL 1.1+
    if (!BN_lshift(r.to_bignum(), a.to_bignum(), shift))
#endif
    {
        throw bignum_error("CBigNum:operator<< : BN_lshift failed");
    }
    
    return r;
}


inline const CBigNum operator>>(const CBigNum& a, unsigned int shift)
{
    CBigNum r = a;
    
    r >>= shift;
    
    return r;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L  // OPENSSL 1.0

inline bool operator==(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(&a, &b) == 0);
}

inline bool operator!=(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(&a, &b) != 0);
}

inline bool operator<=(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(&a, &b) <= 0);
}

inline bool operator>=(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(&a, &b) >= 0);
}

inline bool operator<(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(&a, &b) < 0);
}

inline bool operator>(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(&a, &b) > 0);
}

#else // OPENSSL 1.1+

inline bool operator==(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(a.to_bignum(), b.to_bignum()) == 0);
}

inline bool operator!=(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(a.to_bignum(), b.to_bignum()) != 0);
}

inline bool operator<=(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(a.to_bignum(), b.to_bignum()) <= 0);
}

inline bool operator>=(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(a.to_bignum(), b.to_bignum()) >= 0);
}

inline bool operator<(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(a.to_bignum(), b.to_bignum()) < 0);
}

inline bool operator>(const CBigNum& a, const CBigNum& b)
{
    return (BN_cmp(a.to_bignum(), b.to_bignum()) > 0);
}

#endif

inline std::ostream& operator<<(std::ostream &strm, const CBigNum &b)
{
    return strm << b.ToString(10);
}

typedef  CBigNum Bignum;

#endif // END
