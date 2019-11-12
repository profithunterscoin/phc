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

#include "uint256.h"

BOOST_AUTO_TEST_SUITE(uint160_tests)

BOOST_AUTO_TEST_CASE(uint160_equality)
{
    uint160 num1 = 10;
    uint160 num2 = 11;

    BOOST_CHECK(num1+1 == num2);

    uint64 num3 = 10;
    
    BOOST_CHECK(num1 == num3);
    BOOST_CHECK(num1+num2 == num3+num2);
}

BOOST_AUTO_TEST_SUITE_END()
