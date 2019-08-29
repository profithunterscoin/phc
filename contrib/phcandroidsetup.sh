#!/bin/bash
echo "PHCD Android Setup Script 1.0 - Aug 28, 2019"

echo "Installing dependencies..."
pkg install root-repo
pkg install unstable-repo
pkg install x11-repo
pkg update
pkg upgrade
apt install make
apt install boost
apt install git
apt install g++
apt install openssl
apt install libdb
apt install automake
apt install build-essential
apt inatall libllvm
apt install libcurl
apt install attr
apt install libcrypt
apt install libcln
apt install miniupnpc
apt install libprotobuf
apt install leveldb
apt install leveldb-dev
apt install libandroid-shmem
apt install libc*
apt install proot
apt install stdatomic
pkg install libgmp

echo "Downloading PHC source code..."
git clone http://github.com/profithunterscoin/phc
cd phc/src && git checkout 1.0.0.7-dev
cd

echo "Downloading & Installing DB 18..."
wget https://fossies.org/linux/misc/db-18.1.32.tar.gz
tar -xzvf db-18.1.32.tar.gz
cd db-18.1.32
cd build_android
../dist/configure --enable-cxx --with-static
make
termux-chroot make install
cd

echo "Downloading & Installing LevelDB..."
wget https://github.com/profithunterscoin/android_depends_phc/raw/master/android-leveldb.tgz
tar -xvzf android-leveldb.tgz
rm -rf leveldb
cp -r leveldb phc/src/leveldb
cd

echo "Downloading & Installing Ifaddrs patch..."
git clone https://github.com/profithunterscoin/android-ifaddrs
mv /data/data/com.termux/files/usr/include/ifaddrs.h ifaddrs-old.h
cd android-ifaddrs 
cp * /data/data/com.termux/files/usr/include/
cd

echo "Downloading & Installing GMP..."
git clone https://github.com/profithunterscoin/GMP
cd GMP
./configure
make
termux-chroot make install
termux-chroot cp gmp.h ../../usr/include
termux-chroot cp libgmp.la ../../usr/lib
cd

echo "Downloading & Installing Openssl..."
git clone https://github.com/profithunterscoin/openssl
cd openssl
./config
make
termux-chroot make install
termux-chroot cp libssl.a ../../usr/libssl
termux-chroot cp libcrypto.a ../../usr/lib
cd

echo "Downloading & Installing Miniupnp..."
git clone https://github.com/profithunterscoin/miniupnp
cd miniupnp/miniupnpc
make
termux-chroot make install
cd

echo "Downloading & Installing Boost 1.7..."
wget https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.bz2
tar xvjf boost_1_70_0.tar.bz2
mv /data/data/com.termux/files/usr/include/python3.7m /data/data/com.termux/files/usr/include/python3.7
mv /data/data/com.termux.files/usr/lib/libpython3.7m.so /data/data/com.termux/files/usr/lib/libpython37.so
cd boost_1_70_0
termux-chroot ./bootstrap.sh --prefix=/data/data/com.termux/files/usr && ./b2 stage threading=multi link=shared
termux-chroot ./bootstrap.sh --prefix=/data/data/com.termux/files/usr && ./b2 stage threading=multi link=static
cd

echo "Compiling PHC source code (STATIC)..."
cd phc
cd src/
make -f makefile.android STATIC=1

echo "Installing PHCd..."
termux-chroot cp phcd /usr/bin

echo "Creating PHC configuration..."
read -p "Enter an RPC username" USER
read -p "Enter an RPC password" PASS
echo "rpcuser=$USER" > phc.conf
echo "rpcpassword=$PASS" > phc.conf
echo "server=1" > phc.conf
echo "listen=1" > phc.conf
echo "daemon=1" > phc.conf
echo "lowbandwidth=1" > phc.conf

echo "Loading PHCd..."
phcd
