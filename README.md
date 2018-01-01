
Profit Hunters Coin development tree

PHC is a PoS-based cryptocurrency. PHC includes an Address Index feature, based on the address index API (searchrawtransactions RPC command) implemented in Bitcoin Core but modified implementation to work with the PHC codebase (PoS coins maintain a txindex by default for instance).

Initialize the Address Index By Running with -reindexaddr Command Line Argument.  It may take 10-15 minutes to build the initial index.

- POW Reward: Dynamic (1-100 PHC per Block)
- POS Reward: 3 - 100% Coinage Subsidy
- Block Spacing: 120 Seconds (2 minutes)
- Diff Retarget: 2 Blocks
- Maturity: 100 Blocks
- Stake Minimum Age: 1 Hour
- 40 MegaByte Maximum Block Size (40X Bitcoin Core)

Main Network Information:

- Port: 20060
- RPC Port: 20061
- Magic Bytes: 0x1a 0x33 0x25 0x88

Test Network Information:

- Port: 20062
- RPC Port: 20063
- Magic Bytes: 0x6b 0x33 0x25 0x75