#!/bin/bash
echo "PHCD Android Setup Script 1.2 - Sept 10, 2019"

echo "Installing dependencies..."
pkg install root-repo
pkg install x11-repo
pkg update
pkg upgrade
apt install make
pkg install clang
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
apt install libprotobuf
apt install leveldb
apt install libleveldb
apt install libandroid-shmem
apt install libc*
apt install proot
apt install stdatomic
pkg install libgmp

echo "Downloading PHC source code..."
cd
if [! -d "phc" ]; then
git clone http://github.com/profithunterscoin/phc
fi
cd phc/src && git checkout 1.0.0.7-dev
cd

echo "Downloading & Installing DB 18..."
if [! -f "db-18.1.32.tar.gz" ]; then
wget https://fossies.org/linux/misc/db-18.1.32.tar.gz
fi
if [! -d "db-18.1.32" ]; then
tar -xzvf db-18.1.32.tar.gz
fi
cd db-18.1.32
cd build_android
../dist/configure --enable-cxx --with-static
make
termux-chroot make install
cd

echo "Downloading & Installing Ifaddrs patch..."
if [! -d "android-ifaddrs" ]; then
git clone https://github.com/profithunterscoin/android-ifaddrs
fi
mv /data/data/com.termux/files/usr/include/ifaddrs.h ifaddrs-old.h
cd android-ifaddrs 
cp * /data/data/com.termux/files/usr/include/
cd

echo "Downloading & Installing GMP..."
if [! -d "GMP" ]; then
git clone https://github.com/profithunterscoin/GMP
fi
cd GMP
./configure CFLAGS="-g -Wall -Wconversion -Wno-sign-compare"
make
termux-chroot make install
termux-chroot cp gmp.h ../../usr/include
cd
if [! -d "../../usr/lib/.libs" ]; then
mkdir ../../usr/lib/.libs/
fi
if [-f "../../usr/local/lib/libgmp.a" ]; then
termux-chroot cp ../usr/local/lib/libgmp* ../usr/lib/.libs
termux-chroot cp ../usr/local/lib/libgmp* GMP/
fi

echo "Downloading & Installing Openssl..."
if [! -d "openssl" ]; then
git clone https://github.com/profithunterscoin/openssl
fi
cd openssl
./config
make
termux-chroot make install
termux-chroot cp libssl.a ../../usr/libssl
termux-chroot cp libcrypto.a ../../usr/lib
cd

echo "Downloading & Installing Miniupnp..."
if [! -d "miniupnp" ]; then
git clone https://github.com/profithunterscoin/miniupnp
fi
cd miniupnp/miniupnpc
make
termux-chroot make install
cd

echo "Downloading & Installing Boost 1.7..."
if [! -f "boost_1_70_0.tar.bz2" ]; then
wget https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.bz2
fi
if [! -d "boost_1_70_0" ]; then
tar xvjf boost_1_70_0.tar.bz2
fi
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
