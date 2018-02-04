@echo off
CLS
echo -------------------------------------------------------------------
echo PHC - Wallet Buddy 1.0 - Windows - (C) 2018 Profit Hunters Coin
echo -------------------------------------------------------------------
echo USE THIS TOOL AT YOUR OWN RISK!
echo BACKUP wallet.dat file to an external drive before you continue!

rem ------------------------------------------
:startfix

SET /P prompt= Install Curl to system32 (optional)? Y/N 

IF "%prompt%"=="Y" GOTO :installcurl
IF "%prompt%"=="y" GOTO :installcurl
IF "%prompt%"=="N" GOTO :askforwalletbackup
IF "%prompt%"=="n" GOTO :askforwalletbackup


rem ------------------------------------------
:installcurl

echo Installing: curl to System32...
copy %~dp0\curl.exe %SystemRoot%\System32\curl.exe

GOTO :endoffix


rem ------------------------------------------
:askforwalletbackup
SET /P prompt= Did you backup your wallet.dat file? Y/N 

IF "%prompt%"=="Y" GOTO :askforappdataclean
IF "%prompt%"=="y" GOTO :askforappdataclean
IF "%prompt%"=="N" GOTO :endoffix
IF "%prompt%"=="n" GOTO :endoffix

GOTO :endoffix


rem ------------------------------------------
:askforappdataclean

SET /P prompt= Clean PHC AppData? Y/N 

IF "%prompt%"=="Y" GOTO :cleanwalletdir
IF "%prompt%"=="y" GOTO :cleanwalletdir
IF "%prompt%"=="N" GOTO :askforupdate
IF "%prompt%"=="n" GOTO :askforupdate


rem ------------------------------------------
:cleanwalletdir

echo Cleaning Wallet Datadir
cd %userprofile%\AppData\Roaming\PHC\
rename database database-bkp
rename txleveldb txleveldb-bkp
rename blk0001.dat blk0001.dat-bkp
rename db.log db.log-bkp
rename debug.log debug.log-bkp

cd %~dp0\

GOTO :askforupdate


rem ------------------------------------------
:askforupdate

SET /P prompt= Download phc-qt.exe update (if available)? Y/N 

IF "%prompt%"=="Y" GOTO :getupdate
IF "%prompt%"=="y" GOTO :getupdate
IF "%prompt%"=="N" GOTO :askforbootstrap
IF "%prompt%"=="n" GOTO :askforbootstrap

rem ------------------------------------------
:getupdate

cd %~dp0\

echo Downloading recent version of phc-qt.exe...

curl.exe -O http://profithunterscoin.com/win/phc-qt.exe

GOTO :askforbootstrap


rem ------------------------------------------
:askforbootstrap

SET /P prompt= Download bootstrap file update (if available)? Y/N 

IF "%prompt%"=="Y" GOTO :downloadbootstrap
IF "%prompt%"=="y" GOTO :downloadbootstrap
IF "%prompt%"=="N" GOTO :askforwalletrun
IF "%prompt%"=="n" GOTO :askforwalletrun


rem ------------------------------------------
:downloadbootstrap

cd %userprofile%\AppData\Roaming\PHC\

echo Downloading recent blockchain bootstrap...

curl.exe -O http://profithunterscoin.com/bootstraps/bootstrap.dat

cd %~dp0\

GOTO :askforwalletrun


rem ------------------------------------------
:askforwalletrun

SET /P prompt= Load wallet? Y/N 

IF "%prompt%"=="Y" GOTO :walletrun
IF "%prompt%"=="y" GOTO :walletrun
IF "%prompt%"=="N" GOTO :askforwalletrepair
IF "%prompt%"=="n" GOTO :askforwalletrepair


rem ------------------------------------------
:walletrun

cd %~dp0\

echo Loading phc-qt.exe...

phc-qt.exe -loadblock=bootstrap.dat

GOTO :endoffix


rem ------------------------------------------
:askforwalletrepair

SET /P prompt= Load wallet in repair mode? Y/N 

IF "%prompt%"=="Y" GOTO :walletrepair
IF "%prompt%"=="y" GOTO :walletrepair
IF "%prompt%"=="N" GOTO :askforrestore
IF "%prompt%"=="n" GOTO :askforrestore


rem ------------------------------------------
:walletrepair

cd %~dp0\

echo Loading phc-qt.exe -repairwallet...

phc-qt.exe -repairwallet

GOTO :endoffix


rem ------------------------------------------
:askforrestore

SET /P prompt= Restore Datadir from backup? Y/N 

IF "%prompt%"=="Y" GOTO :restoreappdir
IF "%prompt%"=="y" GOTO :restoreappdir
IF "%prompt%"=="N" GOTO :endoffix
IF "%prompt%"=="n" GOTO :endoffix


rem ------------------------------------------
:restoreappdir

cd %userprofile%\AppData\Roaming\PHC\
rename database-bkp database
rename txleveldb-bkp txleveldb
rename blk0001.dat-bkp blk0001.dat
rename db.log-bkp db.log
rename debug.log-bkp debug.log

cd %~dp0\


GOTO :endoffix


rem ------------------------------------------
:endoffix

echo "Exiting PHC Wallet Buddy..."
exit;
rem ------------------------------------------