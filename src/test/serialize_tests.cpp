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


#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "serialize.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(serialize_tests)

BOOST_AUTO_TEST_CASE(varints)
{
    // encode

    CDataStream ss(SER_DISK, 0);
    CDataStream::size_type size = 0;

    for (int i = 0; i < 100000; i++)
    {
        ss << VARINT(i);
        size += ::GetSerializeSize(VARINT(i), 0, 0);

        BOOST_CHECK(size == ss.size());
    }

    for (uint64 i = 0;  i < 100000000000ULL; i += 999999937)
    {
        ss << VARINT(i);
        size += ::GetSerializeSize(VARINT(i), 0, 0);

        BOOST_CHECK(size == ss.size());
    }

    // decode
    for (int i = 0; i < 100000; i++)
    {
        int j;

        ss >> VARINT(j);

        BOOST_CHECK_MESSAGE(i == j, "decoded:" << j << " expected:" << i);
    }

    for (uint64 i = 0;  i < 100000000000ULL; i += 999999937)
    {
        uint64 j;
        ss >> VARINT(j);
        
        BOOST_CHECK_MESSAGE(i == j, "decoded:" << j << " expected:" << i);
    }

}

BOOST_AUTO_TEST_SUITE_END()
