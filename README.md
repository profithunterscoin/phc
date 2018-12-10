# Profit Hunters Coin 1.0.0.7

PHC is a Pow/PoS/Masternode-based cryptocurrency to be used for affiliate
opportunities and online marketing. Assisting new crypto-currency users get
started with peer to peer profits from trading coins on our decentralized exchange.

Adjustments based on network hashrate, previous block difficulty simulating real bullion mining: If the difficulty rate is low; using excessive work to produce low value blocks does not yield large return rates. When the ratio of difficulty adjusts and the network hashrate remains constant or declines: The reward per block will reach the maximum level, thus mining becomes very profitable.

Dynamic Block Rewards & Firewall implementation is intended to discourage >51% attacks, or malicous miners.
It will also serve as an automatic inflation adjustment based on network conditions.

- Dynamic Block Reward 3.0 (C) 2017 Crypostle
- Block #1 Up to 50000 [Max PoW: 100 PHC] [PoS: 1000% APR] 
- Block #50001 Up to 120000 [Max PoW: 50 PHC] [PoS: 500% APR]
- Block #120001 Up to 150000 [Max PoW: 25 PHC] [PoS: 250% APR]
- Block #150000 Up to 200000 [Max PoW: 12.5 PHC] [PoS: 125% APR]
- Block #200001 Up to 250000 [Max PoW: 6.25 PHC] [PoS: 62% APR]
- Block #250001+ [Max PoW: 3.125 PHC] [PoS: 31% APR]
- Block Spacing: 60 Seconds (1 minutes)
- Diff Retarget: 2 Blocks
- Maturity: 101 Blocks
- Stake Minimum Age: 1 Hour
- Masternode Collateral: 10000 PHC
- 30 MegaByte Maximum Block Size (30X Bitcoin Core)

## Misc Features:

PHC includes an Address Index feature, based on the address index API (searchrawtransactions RPC command) implemented in Bitcoin Core but modified implementation to work with the PHC codebase (PoS coins maintain a txindex by default for instance).

Initialize the Address Index By Running with -reindexaddr Command Line Argument. It may take 10-15 minutes to build the initial index.

## Main Network Information:

- Port: 20060
- RPC Port: 20061
- Magic Bytes: 0x1a 0x33 0x25 0x88

## Test Network Information:

- Port: 20062
- RPC Port: 20063
- Magic Bytes: 0x6b 0x33 0x25 0x75

## Social Network:

- Github: https://github.com/BiznatchEnterprises/phc
- Forum: http://profithuntersclub.com/index.php?t=msg&th=85&start=0&
- Slack: http://slack.profithunterscoin.com
- Telegram: https://t.me/profithunterscoin
- Discord: https://discord.gg/Abwhbw2


---------------------------------------------------------------

Profit Hunters Coin (PHC) is a free open source decentralized project derived from Bitcoin.
It's an experimental project with the goal of providing a long-term energy-efficient scrypt-based crypto-currency.
You're using this software with no guarantees or warranty of any kind. Use it at your own risk!
Built on the foundations of Bitcoin, Litecoin, PeerCoin, NovaCoin, CraveProject, Dash Masternodes
XUVCoin, BATA, and Crypostle to help further advance the field of crypto-currency.

## Contributions:

- Copyright © 2018 Crypostle developers
- Copyright © 2017 The XUV developers
- Copyright © 2014-2015 The ShadowCoin developers
- Copyright © 2014-2015 The Dash developers
- Copyright © 2014 The Crave developers
- Copyright © 2009-2012 The Darkcoin developers
- Copyright © 2012-2014 The NovaCoin developers
- Copyright © 2011-2015 The Peercoin developers
- Copyright © 2009-2014 The Bitcoin developers

This product includes software developed by the OpenSSL Project for use in
the OpenSSL Toolkit (http://www.openssl.org/).

This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).