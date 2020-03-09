#### 1. Download and install Oracle VirtualBox for Windows:

http://download.virtualbox.org/virtualbox/4.3.14/VirtualBox-4.3.14-95030-Win.exe

#### 2. Follow this picture tutorial exactly step for step to setup a Debian VM:

https://github.com/mastercoin-MSC/mastercore/blob/mscore-0.0.8/doc/gitian-building.md#create-a-new-virtualbox-vm

In particular:
- Create a new VirtualBox VM
- Installing Debian

**Note:** the link to Debian 7.4.0 is no longer available, so use a newer version:

http://cdimage.debian.org/debian-cd/7.6.0/amd64/iso-cd/debian-7.6.0-amd64-netinst.iso

Don't close the VM once Debian is installed.

#### 3. Download PuTTY for Windows:

http://the.earth.li/~sgtatham/putty/latest/x86/putty.exe

#### 4. Connect to the VM:

Start `putty.exe` and connect:

- Host Name: `localhost`
- Port: `22222`

![Imgur](http://i.imgur.com/LPPm7wV.png)

Click `Open`, accept the server's certificate and login as user `root`.

#### 5. Install dependencies:

Enter the following line:

```bash
apt-get install git ruby sudo apt-cacher-ng qemu-utils debootstrap lxc python-cheetah parted kpartx bridge-utils -y
```

![Imgur](http://i.imgur.com/54wPRpi.png)

When you get a colorful screen with a question about the `LXC directory`, just go with the default (`/var/lib/lxc`).

#### 6. Go on with:

```bash
adduser debian sudo
```

![Imgur](http://i.imgur.com/nppZQgf.png)

#### 7. Copy and enter each line:

```bash
echo "%sudo ALL=NOPASSWD: /usr/bin/lxc-start" > /etc/sudoers.d/gitian-lxc
echo "cgroup  /sys/fs/cgroup  cgroup  defaults  0   0" >> /etc/fstab
echo '#!/bin/sh -e' > /etc/rc.local
echo 'brctl addbr br0' >> /etc/rc.local
echo 'ifconfig br0 10.0.3.2/24 up' >> /etc/rc.local
echo 'exit 0' >> /etc/rc.local
echo 'export USE_LXC=1' >> /home/debian/.profile
echo 'export GITIAN_HOST_IP=10.0.3.2' >> /home/debian/.profile
echo 'export LXC_GUEST_IP=10.0.3.5' >> /home/debian/.profile
reboot
```
![Imgur](http://i.imgur.com/IPBp2dM.png)

The connection will terminate due to the reboot.

#### 8. Reconnect:

Start `putty.exe` and use:

- Host Name: `localhost`
- Port: `22222`

This time login with user `debian`.

#### 9. Install gitian, enter:

```bash
wget http://archive.ubuntu.com/ubuntu/pool/universe/v/vm-builder/vm-builder_0.12.4+bzr489.orig.tar.gz
tar -zxvf vm-builder_0.12.4+bzr489.orig.tar.gz
cd vm-builder-0.12.4+bzr489
sudo python setup.py install
cd ..
```
You will be asked for the password for the user `debian`.

#### 10. Clone the repos:

```bash
git clone https://github.com/devrandom/gitian-builder.git
git clone https://github.com/mastercoin-MSC/mastercore.git bitcoin
```

![Imgur](http://i.imgur.com/WAOAJOL.png)

**Note:** If you use the `mastercore` repo, save files in `bitcoin` via `git clone https://github.com/.../mastercore.git bitcoin`.

#### 11. Setup gitian images, enter:

```bash
cd gitian-builder
bin/make-base-vm --lxc --arch i386 --suite precise
bin/make-base-vm --lxc --arch amd64 --suite precise
```

This will take some time.

#### 12. Prepare inputs:

```bash
mkdir -p inputs
cd inputs/
wget 'http://miniupnp.free.fr/files/download.php?file=miniupnpc-1.9.tar.gz' -O miniupnpc-1.9.tar.gz
wget 'https://www.openssl.org/source/openssl-1.0.1h.tar.gz' --no-check-certificate
wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
wget 'https://www.zlib.net/fossils/zlib-1.2.8.tar.gz'
wget 'ftp://ftp.simplesystems.org/pub/png/src/history/libpng16/libpng-1.6.8.tar.gz'
wget 'https://fukuchi.org/works/qrencode/qrencode-3.4.3.tar.bz2'
wget 'https://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.bz2'
wget 'https://svn.boost.org/trac/boost/raw-attachment/ticket/7262/boost-mingw.patch' -O boost-mingw-gas-cross-compile-2013-03-03.patch
wget 'http://mirror.csclub.uwaterloo.ca/qtproject/archive/qt/5.2/5.2.0/single/qt-everywhere-opensource-src-5.2.0.tar.gz'
wget 'https://download.qt-project.org/archive/qt/4.6/qt-everywhere-opensource-src-4.6.4.tar.gz'
wget 'https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/protobuf/protobuf-2.5.0.tar.gz'
wget 'https://github.com/mingwandroid/toolchain4/archive/10cc648683617cca8bcbeae507888099b41b530c.tar.gz'
wget 'http://www.opensource.apple.com/tarballs/cctools/cctools-809.tar.gz'
wget 'http://www.opensource.apple.com/tarballs/dyld/dyld-195.5.tar.gz'
wget 'http://www.opensource.apple.com/tarballs/ld64/ld64-127.2.tar.gz'
wget 'http://pkgs.fedoraproject.org/repo/pkgs/cdrkit/cdrkit-1.1.11.tar.gz/efe08e2f3ca478486037b053acd512e9/cdrkit-1.1.11.tar.gz'
wget 'https://github.com/theuni/libdmg-hfsplus/archive/libdmg-hfsplus-v0.1.tar.gz'
wget 'http://llvm.org/releases/3.2/clang+llvm-3.2-x86-linux-ubuntu-12.04.tar.gz' -O clang-llvm-3.2-x86-linux-ubuntu-12.04.tar.gz
wget 'https://raw.githubusercontent.com/theuni/osx-cross-depends/master/patches/cdrtools/genisoimage.diff' -O cdrkit-deterministic.patch
```
The following lines can't be pasted together for some reason..

```bash
cd ..
./bin/gbuild ../bitcoin/contrib/gitian-descriptors/boost-win.yml
mv build/out/boost-*.zip inputs/
./bin/gbuild ../bitcoin/contrib/gitian-descriptors/deps-win.yml
mv build/out/bitcoin-deps-*.zip inputs/
./bin/gbuild ../bitcoin/contrib/gitian-descriptors/qt-win.yml
mv build/out/qt-*.zip inputs/
./bin/gbuild ../bitcoin/contrib/gitian-descriptors/protobuf-win.yml
mv build/out/protobuf-*.zip inputs/
```

#### 13. Start building, enter:

```bash
URL=https://github.com/mastercoin-MSC/mastercore.git
COMMIT=mscore-0.0.8
./bin/gbuild --commit bitcoin=${COMMIT} --url bitcoin=${URL} ../bitcoin/contrib/gitian-descriptors/gitian-win.yml
```

You can replace the values used for `URL` and `COMMIT` to use another repo, branch or commit. It's also possible to use a local path, e.g.:

```bash
URL=/home/debian/bitcoin
COMMIT=3a03c3fdfd0c3e4177bc3f87bd0e2a4bcbb2f04c
./bin/gbuild --commit bitcoin=${COMMIT} --url bitcoin=${URL} ../bitcoin/contrib/gitian-descriptors/gitian-win.yml
```

#### 14. Move files from VM:

Get an SFTP client such as FileZilla:

https://filezilla-project.org/download.php?type=client

Connect to:

- Host: `localhost`
- Port: `22222`
- Protocol: `SFTP - SSH File Transfer Protocol`
- User: `debian`
- Password: `somepw`

![Imgur](http://i.imgur.com/XMMDYat.png)

The build results are stored in `/home/debian/gitian-builder/build/out`, move them to your local machine.

Use `-txindex` and `-testnet` as startup parameter.
