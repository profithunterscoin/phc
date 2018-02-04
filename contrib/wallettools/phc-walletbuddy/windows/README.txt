-------------------------------------------------------------------
PHC - PHC Wallet Buddy 1.0 - Windows - (C) 2018 Profit Hunters Coin
-------------------------------------------------------------------
BACKUP wallet.dat file to an external drive before you continue!
Notice: USE THIS TOOL AT YOUR OWN RISK!


Here are some things you can do with PHC Wallet Buddy:

- Clean your AppData\PHC folder (renaming: database, txleveldb, blk0001.dat, db.log, debug.log)
- Restore your AppData\PHC folder after cleaning (with this tool only)
- Download/install the most recent version of phc-qt.exe
- Download/install the most recent version of the blockchain bootstrap
- Run wallet in "normal" or "repair wallet" mode

Installing PHC Wallet Buddy 1.0:
Step 1 - Unzip the archive or download from http://github.com/biznatchenterprises/phc/contrib/wallettools/phc-walletbuddy/windows/
Step 2 - Copy curl.exe, this file, and phc-walletbuddy.bat in the same directory (folder) as phc-qt.exe


Wallet chain-forked (stuck on blocks?)

Step 0 - Backup your wallet! File -> Backup Wallet (selecting an external usb drive is recommended)
Step 1 - Make sure curl.exe and stuck_wallet_fix.bat is located in the same directory (folder) as phc-qt.exe
Step 2 - Double click (run) stuck_wallet_fix.bat
Step 3 - You will be asked to install curl.exe to system32 type: n {ENTER}
step 4 - You will be asked if you backed up your wallet, if you did type: y {ENTER}
Step 5 - You will be asked to Clean PHC AppData tpe: y {ENTER}
Step 6 - You will be asked to Download phc-qt update, if you have not already type: y {ENTER}
Step 7 - You will be asked to Download recent bootstrap file. Type: y {ENTER}
Step 8 - You will be asked to Load Wallet. Type: y {ENTER}
Step 9 - Wait for your wallet to finish "importing blocks" and to connect to peers and fully sync.


Curl not working?

Step 1 - Right click on stuck_wallet_fix and click "Run as administrator"
Step 2 - It will ask you to install curl.exe to system32. Type: y {ENTER}
Step 3 - Run PHC Wallet Buddy again.