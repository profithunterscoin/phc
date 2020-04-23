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


#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

/* Not used yet
struct SeedSpec6
{
    uint8_t addr[16];
    uint16_t port;
};
*/

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, const unsigned int *data, unsigned int count, int port)
{
     // It'll only connect to one or two seed nodes because once it connects,
     // it'll get a pile of addresses with newer timestamps.
     // Seed nodes are given a random 'last seen time' of between one and two
     // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    
    for (unsigned int k = 0; k < count; ++k)
    {
        struct in_addr ip;
        unsigned int i = data[k], t;
        
        // -- convert to big endian
        t =   (i & 0x000000ff) << 24u
            | (i & 0x0000ff00) << 8u
            | (i & 0x00ff0000) >> 8u
            | (i & 0xff000000) >> 24u;
        
        memcpy(&ip, &t, sizeof(ip));
        
        CAddress addr(CService(ip, port));

        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;

        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams
{
    public:

        CMainParams()
        {
            // The message start string is designed to be unlikely to occur in normal data.
            // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
            // a large 4-byte int at any alignment.
            pchMessageStart[0] = 0x1a;
            pchMessageStart[1] = 0x33;
            pchMessageStart[2] = 0x25;
            pchMessageStart[3] = 0x88;
            
            vAlertPubKey = ParseHex("045ae8e09a456a2ae88f9a2fdb99122612cd26f9da329731b1b8335f650978c9d21df0a0543ba1179d05a081c3c1ec389ce2bb55e36565b50ab40dde6b19d136e1");
            nDefaultPort = 20060;
            nRPCPort = 20061;
            bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
            strDataDir = ""; // Default

            // Build the genesis block. Note that the output of the genesis coinbase cannot
            // be spent as it did not originally exist in the database.
            //

            /*
            mainnet.genesis : 
            CBlock(hash=0000b587d86da35102be091d9d303851d53130a70375a2ae6b8827ca18feb00d, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4, nTime=1514844000, nBits=1f00ffff, nNonce=1006718, vtx=1, vchBlockSig=)
            Coinbase(hash=10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4, nTime=1514844000, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24426974636f696e202e2e2e20616e6f746865722062696720626f6f7374202d20434e4243)
            CTxOut(nValue=0.00, scriptPubKey=045ae8e09a456a2ae88f9a2fdb9912)

            vMerkleTree:  10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4

            mainnet.genesis.GetHash(): 0000b587d86da35102be091d9d303851d53130a70375a2ae6b8827ca18feb00d
            mainnet.genesis.hashMerkleRoot: 10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4
            mainnet.genesis.nTime: 1514844000
            mainnet.genesis.nNonce: 1006718
            */

            const char* pszTimestamp = "Bitcoin ... another big boost - CNBC";
            
            CTransaction txNew;
            txNew.nTime = 1514844000; // GMT: Monday, January 1, 2018 10:00:00 PM
            txNew.vin.resize(1);
            txNew.vout.resize(1);
            txNew.vin[0].scriptSig = CScript() << 0 << 42 << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
            txNew.vout[0].scriptPubKey = CScript() << ParseHex("045ae8e09a456a2ae88f9a2fdb9912");
            txNew.vout[0].nValue = 0;
            genesis.vtx.push_back(txNew);
            genesis.hashPrevBlock = 0;
            genesis.hashMerkleRoot = genesis.BuildMerkleTree();
            genesis.nVersion = 1;
            genesis.nTime    = 1514844000; // GMT: Monday, January 1, 2018 10:00:00 PM
            genesis.nBits    = 520159231;
            genesis.nNonce   = 1006718;

            /*
            hashGenesisBlock = uint256("0x01");
            if (true && (genesis.GetHash() != hashGenesisBlock))
            {
                uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                while (genesis.GetHash() > hashTarget)
                {
                    ++genesis.nNonce;
                    if (genesis.nNonce == 0)
                    {
                        ++genesis.nTime;
                    }
                }

            }

            hashGenesisBlock = genesis.GetHash();

            cout << "mainnet.genesis : \n" << genesis.ToString() << endl;
            cout << "mainnet.genesis.GetHash(): " << genesis.GetHash().ToString() << endl;
            cout << "mainnet.genesis.hashMerkleRoot: " << genesis.hashMerkleRoot.ToString() << endl;
            cout << "mainnet.genesis.nTime: " << genesis.nTime << endl;
            cout << "mainnet.genesis.nNonce: " << genesis.nNonce << endl;
            */
        
            hashGenesisBlock = genesis.GetHash();

            assert(hashGenesisBlock == uint256("0000b587d86da35102be091d9d303851d53130a70375a2ae6b8827ca18feb00d"));
            assert(genesis.hashMerkleRoot == uint256("10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4"));

            base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,55);
            base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,40);
            base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,152);
            base58Prefixes[STEALTH_ADDRESS] = std::vector<unsigned char>(1,40);
            base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();;
            base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();;

            //vFixedSeeds.clear();
            //vSeeds.clear();

            vSeeds.push_back(CDNSSeedData("0",  "54.37.233.45"));
            vSeeds.push_back(CDNSSeedData("1",  "142.44.246.195"));
            vSeeds.push_back(CDNSSeedData("2",  "104.238.191.138"));
            vSeeds.push_back(CDNSSeedData("3",  "207.148.26.5"));
            vSeeds.push_back(CDNSSeedData("4",  "209.250.241.11"));
            vSeeds.push_back(CDNSSeedData("5",  "45.32.42.28"));
            vSeeds.push_back(CDNSSeedData("6",  "45.76.20.101"));
            vSeeds.push_back(CDNSSeedData("7",  "188.72.214.10"));
            vSeeds.push_back(CDNSSeedData("8",  "107.172.185.30"));
            vSeeds.push_back(CDNSSeedData("9",  "45.77.244.158"));
            vSeeds.push_back(CDNSSeedData("10",  "104.236.68.74"));
            vSeeds.push_back(CDNSSeedData("11",  "93.175.196.159"));
            vSeeds.push_back(CDNSSeedData("12",  "199.247.4.85"));
            vSeeds.push_back(CDNSSeedData("13",  "91.121.76.138"));
            vSeeds.push_back(CDNSSeedData("14",  "117.89.40.15"));
            vSeeds.push_back(CDNSSeedData("15",  "45.32.201.18"));
            vSeeds.push_back(CDNSSeedData("16",  "91.240.86.254"));
            vSeeds.push_back(CDNSSeedData("17",  "209.250.255.100"));
            vSeeds.push_back(CDNSSeedData("18",  "193.111.199.65"));
            vSeeds.push_back(CDNSSeedData("19",  "45.32.146.229"));
            vSeeds.push_back(CDNSSeedData("20",  "45.76.63.129"));
            vSeeds.push_back(CDNSSeedData("21",  "31.187.71.38"));
            vSeeds.push_back(CDNSSeedData("22",  "162.212.156.73"));
            vSeeds.push_back(CDNSSeedData("23",  "45.76.79.219"));
            vSeeds.push_back(CDNSSeedData("24",  "82.245.113.89"));
            vSeeds.push_back(CDNSSeedData("25",  "45.77.101.196"));
            vSeeds.push_back(CDNSSeedData("26",  "108.61.117.160"));
            vSeeds.push_back(CDNSSeedData("27",  "45.77.59.116"));
            vSeeds.push_back(CDNSSeedData("28",  "89.47.160.153"));
            vSeeds.push_back(CDNSSeedData("29",  "136.144.185.202"));
            vSeeds.push_back(CDNSSeedData("30",  "116.62.132.125"));
            vSeeds.push_back(CDNSSeedData("31",  "45.76.30.132"));
            vSeeds.push_back(CDNSSeedData("32",  "207.148.25.232"));
            vSeeds.push_back(CDNSSeedData("33",  "194.67.198.169"));
            vSeeds.push_back(CDNSSeedData("34",  "165.227.4.45"));
            vSeeds.push_back(CDNSSeedData("35",  "104.236.109.73"));
            vSeeds.push_back(CDNSSeedData("36",  "209.250.230.163"));
            vSeeds.push_back(CDNSSeedData("37",  "45.77.56.180"));
            vSeeds.push_back(CDNSSeedData("38",  "195.133.144.153"));
            vSeeds.push_back(CDNSSeedData("39",  "162.212.156.234"));
            vSeeds.push_back(CDNSSeedData("40",  "185.243.131.118"));
            vSeeds.push_back(CDNSSeedData("41",  "90.156.157.28"));
            vSeeds.push_back(CDNSSeedData("42",  "185.206.147.226"));
            vSeeds.push_back(CDNSSeedData("43",  "209.250.244.148"));
            vSeeds.push_back(CDNSSeedData("44",  "45.32.169.174"));
            vSeeds.push_back(CDNSSeedData("45",  "185.203.116.240"));
            vSeeds.push_back(CDNSSeedData("46",  "45.32.31.102"));
            vSeeds.push_back(CDNSSeedData("47",  "109.248.46.56"));
            vSeeds.push_back(CDNSSeedData("48",  "103.207.39.149"));
            vSeeds.push_back(CDNSSeedData("49",  "45.77.101.196"));
            vSeeds.push_back(CDNSSeedData("50",  "207.246.108.146"));
            vSeeds.push_back(CDNSSeedData("51",  "108.61.117.160"));
            vSeeds.push_back(CDNSSeedData("52",  "209.250.246.24"));
            vSeeds.push_back(CDNSSeedData("53",  "194.67.198.169"));
            vSeeds.push_back(CDNSSeedData("54",  "104.238.191.63"));
            vSeeds.push_back(CDNSSeedData("55",  "162.212.154.236"));
            vSeeds.push_back(CDNSSeedData("56",  "94.242.11.54"));
            vSeeds.push_back(CDNSSeedData("57",  "89.25.172.208"));
            vSeeds.push_back(CDNSSeedData("58",  "194.87.232.92"));
            vSeeds.push_back(CDNSSeedData("59",  "104.156.255.214"));
            vSeeds.push_back(CDNSSeedData("60",  "78.28.250.103"));
            vSeeds.push_back(CDNSSeedData("61",  "104.207.138.37"));
            vSeeds.push_back(CDNSSeedData("62",  "207.148.84.21"));
            vSeeds.push_back(CDNSSeedData("63",  "45.77.138.228"));
            vSeeds.push_back(CDNSSeedData("64",  "193.124.190.161"));
            vSeeds.push_back(CDNSSeedData("65",  "199.247.25.153"));
            vSeeds.push_back(CDNSSeedData("66",  "81.169.135.146"));
            vSeeds.push_back(CDNSSeedData("67",  "195.154.102.114"));
            vSeeds.push_back(CDNSSeedData("68",  "162.212.158.40"));
            vSeeds.push_back(CDNSSeedData("69",  "175.137.180.244"));
            vSeeds.push_back(CDNSSeedData("70",  "89.47.160.153"));
            vSeeds.push_back(CDNSSeedData("71",  "162.212.158.195"));
            vSeeds.push_back(CDNSSeedData("72",  "194.67.199.175"));
            vSeeds.push_back(CDNSSeedData("73",  "66.154.105.142"));
            vSeeds.push_back(CDNSSeedData("74",  "198.13.50.26"));
            vSeeds.push_back(CDNSSeedData("75",  "65.13.152.100"));
            vSeeds.push_back(CDNSSeedData("76",  "78.28.227.89"));
            vSeeds.push_back(CDNSSeedData("77",  "93.175.196.159"));
            vSeeds.push_back(CDNSSeedData("78",  "45.77.54.45"));
            vSeeds.push_back(CDNSSeedData("79",  "107.152.32.193"));
            vSeeds.push_back(CDNSSeedData("80",  "107.191.48.109"));
            vSeeds.push_back(CDNSSeedData("81",  "115.75.5.106"));
            vSeeds.push_back(CDNSSeedData("82",  "118.100.106"));
            vSeeds.push_back(CDNSSeedData("83",  "144.202.10.156"));
            vSeeds.push_back(CDNSSeedData("84",  "144.202.102.197"));
            vSeeds.push_back(CDNSSeedData("85",  "144.202.59.93"));
            vSeeds.push_back(CDNSSeedData("86",  "144.202.64.12"));
            vSeeds.push_back(CDNSSeedData("87",  "144.202.66.162"));
            vSeeds.push_back(CDNSSeedData("88",  "149.154.68.13"));
            vSeeds.push_back(CDNSSeedData("89",  "159.89.181.214"));
            vSeeds.push_back(CDNSSeedData("90",  "165.227.182.225"));
            vSeeds.push_back(CDNSSeedData("91",  "165.227.66.150"));
            vSeeds.push_back(CDNSSeedData("92",  "178.33.80.223"));
            vSeeds.push_back(CDNSSeedData("93",  "185.92.220.91"));
            vSeeds.push_back(CDNSSeedData("94",  "194.182.66.218"));
            vSeeds.push_back(CDNSSeedData("95",  "194.19.235.72"));
            vSeeds.push_back(CDNSSeedData("96",  "194.19.235.73"));
            vSeeds.push_back(CDNSSeedData("97",  "194.19.235.74"));
            vSeeds.push_back(CDNSSeedData("98",  "195.191.174.168"));
            vSeeds.push_back(CDNSSeedData("99",  "198.13.43.142"));
            vSeeds.push_back(CDNSSeedData("100",  "207.148.28.40"));
            vSeeds.push_back(CDNSSeedData("101",  "207.148.28.9"));
            vSeeds.push_back(CDNSSeedData("102",  "207.148.29.214"));
            vSeeds.push_back(CDNSSeedData("103",  "207.148.86.87"));
            vSeeds.push_back(CDNSSeedData("104",  "209.250.249.250"));
            vSeeds.push_back(CDNSSeedData("105",  "209.250.252.119"));
            vSeeds.push_back(CDNSSeedData("106",  "213.231.2.188"));
            vSeeds.push_back(CDNSSeedData("107",  "217.61.104.227"));
            vSeeds.push_back(CDNSSeedData("108",  "39.104.114.2"));
            vSeeds.push_back(CDNSSeedData("109",  "43.254.133.136"));
            vSeeds.push_back(CDNSSeedData("110",  "45.32.195.196"));
            vSeeds.push_back(CDNSSeedData("111",  "45.77.108.112"));
            vSeeds.push_back(CDNSSeedData("112",  "45.77.156.202"));
            vSeeds.push_back(CDNSSeedData("113",  "45.77.181.39"));
            vSeeds.push_back(CDNSSeedData("114",  "54.36.163.179"));
            vSeeds.push_back(CDNSSeedData("115",  "62.173.139.126"));
            vSeeds.push_back(CDNSSeedData("116",  "77.37.255.230"));
            vSeeds.push_back(CDNSSeedData("117",  "77.91.88.211"));
            vSeeds.push_back(CDNSSeedData("118",  "80.208.224.74"));
            vSeeds.push_back(CDNSSeedData("119",  "80.211.194.210"));
            vSeeds.push_back(CDNSSeedData("120",  "81.2.248.42"));
            vSeeds.push_back(CDNSSeedData("121",  "87.189.241.120"));
            vSeeds.push_back(CDNSSeedData("122",  "94.156.189.232"));
            vSeeds.push_back(CDNSSeedData("123",  "96.127.206.72"));       
    
            convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);

            nPoolMaxTransactions = 3;

            //strSporkKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";
            //strMasternodePaymentsPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";
            strDarksendPoolDummyAddress = "PXeU4EGgDEnFJHuNptvqsWHs4qsdYg3Ypu";

            strDevRewardAddress = "PTxSxCoYi7nVs5hhDMKE5B8JuBVFdgWFaz"; // Not used yet
            
            nLastPOWBlock = 0x7fffffff;
            nPOSStartBlock = 10000;
            //nStakeMaxAge = 9999; // 9999 days


            ///////////////////////
            // 1.0.0.6 - Hard Forks

            // PIP1 - Strict Range controls after fork height (Mitigates mining-centralization without 100% reward loss)
            nPIP1 = 120000; // Block #120000 Activation


            ///////////////////////
            // 1.0.0.7 - Hard Forks

            // PIP3 - Do not allow blank payments (deactivation)
            nPIP3 = 999999999; // Block # Activation (UNDECIDED)


            ///////////////////////
            // 1.0.0.8 - Hard Forks (Proposed)

            // PIP2 - TargetTimespan correction after development testing
            nPIP2 = 999999999; // Block # Activation (UNDECIDED)

            // PIP4 - Developers fee
            nPIP4 = 999999999; // Block # Activation (UNDECIDED)

            // PIP5 - Blockshield
            nPIP5 = 999999999; // Block # Activation (UNDECIDED)

            // PIP6 - ASIC Choker
            nPIP6 = 999999999; // Block # Activation (UNDECIDED)

            // PIP7 - IncrementExtraNonce
            nPIP7 = 999999999; // Block # Activation (UNDECIDED)
        }

        virtual const CBlock& GenesisBlock() const
        {
            return genesis;
        }
        
        virtual Network NetworkID() const
        {
            return CChainParams::MAIN;
        }

        virtual const vector<CAddress>& FixedSeeds() const
        {
            return vFixedSeeds;
        }

    protected:

        CBlock genesis;
        vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams
{

    public:
        
        CTestNetParams()
        {
            // The message start string is designed to be unlikely to occur in normal data.
            // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
            // a large 4-byte int at any alignment.
            pchMessageStart[0] = 0x6b;
            pchMessageStart[1] = 0x33;
            pchMessageStart[2] = 0x25;
            pchMessageStart[3] = 0x75;
            
            bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
            vAlertPubKey = ParseHex("04344278bdac5f6e1e1711a3672a5002e54369b984c97df9d36e5aa2123dec228e85da0b88f3a38ba62746a1ca20726dd73a806767620c830ffb99ab1e6c45a778");
            nDefaultPort = 20062;
            nRPCPort = 20063;
            strDataDir = "testnet/";

            // Build the genesis block. Note that the output of the genesis coinbase cannot
            // be spent as it did not originally exist in the database.
            //

            /*
            testnet.genesis : 
            CBlock(hash=0000ce8f49c8c59ed8a4c50cdacddc1f84b1be04e52232989887c99aad3e8e4e, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4, nTime=1548626154, nBits=1f00ffff, nNonce=319349, vtx=1, vchBlockSig=)
            Coinbase(hash=10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4, nTime=1514844000, ver=1, vin.size=1, vout.size=1, nLockTime=0)
            CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24426974636f696e202e2e2e20616e6f746865722062696720626f6f7374202d20434e4243)
            CTxOut(nValue=0.00, scriptPubKey=045ae8e09a456a2ae88f9a2fdb9912)

            vMerkleTree:  10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4

            testnet.genesis.GetHash(): 0000ce8f49c8c59ed8a4c50cdacddc1f84b1be04e52232989887c99aad3e8e4e
            testnet.genesis.hashMerkleRoot: 10a0a2b5415e856e2920e10add027cf52aa801a046fc466285555c3c7603dff4
            testnet.genesis.nTime: 1548626154
            testnet.genesis.nNonce: 319349
            */

            // Modify the testnet genesis block so the timestamp is valid for a later start.
            genesis.nTime = 1548626154; // GMT: Sunday, January 27, 2019 9:55:54 PM
            genesis.nBits  = 520159231;
            genesis.nNonce = 319349;

            hashGenesisBlock = uint256("0x01");
            
            if (true && (genesis.GetHash() != hashGenesisBlock))
            {
                uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                while (genesis.GetHash() > hashTarget)
                {
                    ++genesis.nNonce;
                    if (genesis.nNonce == 0)
                    {
                        ++genesis.nTime;
                    }
                }

            }

            /*
            hashGenesisBlock = genesis.GetHash();

            cout << "testnet.genesis : \n" << genesis.ToString() << endl;
            cout << "testnet.genesis.GetHash(): " << genesis.GetHash().ToString() << endl;
            cout << "testnet.genesis.hashMerkleRoot: " << genesis.hashMerkleRoot.ToString() << endl;
            cout << "testnet.genesis.nTime: " << genesis.nTime << endl;
            cout << "testnet.genesis.nNonce: " << genesis.nNonce << endl;
            */

            hashGenesisBlock = genesis.GetHash();

            assert(hashGenesisBlock == uint256("0000ce8f49c8c59ed8a4c50cdacddc1f84b1be04e52232989887c99aad3e8e4e"));

            //vFixedSeeds.clear();
            //vSeeds.clear();

            vSeeds.push_back(CDNSSeedData("1",  "54.37.233.45"));
            //vSeeds.push_back(CDNSSeedData("2",  "173.199.114.227"));
            vSeeds.push_back(CDNSSeedData("3",  "178.33.146.163"));
            vSeeds.push_back(CDNSSeedData("4",  "194.182.66.218"));
            vSeeds.push_back(CDNSSeedData("5",  "80.211.194.210"));
            vSeeds.push_back(CDNSSeedData("6",  "81.2.248.42"));

            base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127);
            base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
            base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,239);
            base58Prefixes[STEALTH_ADDRESS] = std::vector<unsigned char>(1,40);
            base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();;
            base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();;

            convertSeeds(vFixedSeeds, pnTestnetSeed, ARRAYLEN(pnTestnetSeed), nDefaultPort);

            strDarksendPoolDummyAddress = "PXeU4EGgDEnFJHuNptvqsWHs4qsdYg3Ypu";

            strDevRewardAddress = "tDFQKd4v6GoqjmoimRAmgH33fn5NnGLuYm";

            nLastPOWBlock = 0x7fffffff;
            nPOSStartBlock = 10000;
            //nStakeMaxAge = 9999; // 9999 days (not implemented yet)


            ///////////////////////
            // 1.0.0.6 - Protocol Improvement Proposals (Hard Forks)

            // PIP1 - Strict Range controls after fork height (Mitigates mining-centralization without 100% reward loss)
            nPIP1 = 1200; // Block #1200 Activation


            ///////////////////////
            // 1.0.0.7 - Protocol Improvement Proposals (Hard Forks)

            // PIP3 - Do not allow blank payments (deactivation)
            nPIP3 = 1; // Block #1 Activation

            // PIP2 - TargetTimespan correction after development testing
            nPIP2 = 1; // Block #1 Activation

            // PIP5 - Blockshield
            nPIP5 = 1; // Block #1 Activation

            // PIP6 - ASIC Choker
            nPIP6 = 1; // Block #1 Activation

            // PIP7 - IncrementExtraNonce
            nPIP7 = 1; // Block #1 Activation


            ///////////////////////
            // 1.0.0.8 - Protocol Improvement Proposals (Proposed Hard Forks)

            // PIP4 - Developers fee
            nPIP4 = 999999999; // Block # Activation (UNDECIDED)

        }

        virtual Network NetworkID() const
        {
            return CChainParams::TESTNET;
        }
};
static CTestNetParams testNetParams;


static CChainParams *pCurrentParams = &mainParams;


const CChainParams &Params()
{
    return *pCurrentParams;
}


void SelectParams(CChainParams::Network network)
{
    switch (network)
    {
        case CChainParams::MAIN:
        {
            pCurrentParams = &mainParams;
            
            break;
        }

        case CChainParams::TESTNET:
        {
            pCurrentParams = &testNetParams;

            break;
        }

        default:
        {
            assert(false && "Unimplemented network");

            return;
        }
    }
}


bool SelectParamsFromCommandLine()
{  
    bool fTestNet = GetBoolArg("-testnet", false);
    
    if (fTestNet)
    {
        SelectParams(CChainParams::TESTNET);
    }
    else
    {
        SelectParams(CChainParams::MAIN);
    }
    
    return true;
}
