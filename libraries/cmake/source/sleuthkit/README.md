# Linux

## x86_64

```bash
cat /etc/issue
CentOS release 6.10 (Final)
Kernel \r on an \m
```

```bash
ldd --version
ldd (GNU libc) 2.12.2
```

```bash
yum info glibc

...

Version     : 2.12
Release     : 1.212.el6

...

```

## AArch64

```bash
cat /etc/issue
Ubuntu 16.04.7 LTS \n \l
```

```bash
ldd --version
ldd (Ubuntu GLIBC 2.23-0ubuntu11.2) 2.23
```

```bash
apt show libc-bin
Package: libc-bin
Version: 2.23-0ubuntu11.3
...

```


## Common

Prepare the environment

```bash
export PATH="/opt/osquery-toolchain/usr/bin:${PATH}"
export CFLAGS="--sysroot /opt/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} -lm"
export CC=clang
export CXX="clang++"
```

Fix the `FATAL: kernel too old` issue in the toolchain:

```bash
ln \
  -sf \
  /opt/osquery-toolchain/usr/bin/llvm-ar \
  /opt/osquery-toolchain/usr/bin/ar

ln \
  -sf \
  /opt/osquery-toolchain/usr/bin/llvm-ranlib \
  /opt/osquery-toolchain/usr/bin/ranlib

ln \
  -sf \
  /opt/osquery-toolchain/usr/bin/llvm-nm \
  /opt/osquery-toolchain/usr/bin/nm
```

Make sure you are working on a clean source folder

```
git reset --hard ; git clean -ffdx
```

Disable the stdc++ library check

```
sed -i '/stdc++/d' configure.ac
```

Disable tools, documentation, etc

```
sed -i '/SUBDIRS = tsk/c\SUBDIRS = tsk' Makefile.am
```

Configure the project

```
./bootstrap

./configure \
  --enable-static \
  --disable-java \
  --without-libewf \
  --without-libvhdi \
  --without-libvmdk \
  --without-afflib
```

Expected output:

```text
Building:
   afflib support:                        no
   libewf support:                        no
   zlib support:                          yes

   libvhdi support:                       no
   libvmdk support:                       no
Features:
   Java/JNI support:                      no
   Multithreading:                        yes
```

Start the build

```
make -j $(nproc)
```

Copy the generated files: `tsk/tsk_config.h`, `tsk/tsk_incs.h`

# macOS

Make sure you are working on a clean repository

```
git reset --hard ; git clean -ffdx
```

Once the `libtool` brew package has been installed:

```
mkdir bin
ln -s $(which glibtool) bin/libtool
ln -s $(which glibtoolize) bin/libtoolize

export PATH="$(pwd)/bin:${PATH}"
```

Update the `Makefile.am` file:

```patch
-SUBDIRS = tsk tools tests samples man $(UNIT_TESTS) $(JAVA_BINDINGS) $(JAVA_CASEUCO)
+SUBDIRS = tsk
```

Prepare the environment

Note: If building for M1, add `-target arm64-apple-macos10.15` at the end of the `CFLAGS` environment variable.

```bash
export CFLAGS="-isysroot /Applications/Xcode_12.4.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.1.sdk"
export CXXFLAGS="${CFLAGS}"
```

Configure the project

Note: If building for M1, add `--host=arm64-apple-macos10.15` at the end of the configure invocation (otherwise the configure will fail, trying to launch an M1 binary locally).

```
./bootstrap

./configure \
  --enable-static \
  --disable-java \
  --without-libewf \
  --without-libvhdi \
  --without-libvmdk \
  --without-afflib
```

Expected output:

```text
Building:
   afflib support:                        no
   libewf support:                        no
   zlib support:                          yes

   libvhdi support:                       no
   libvmdk support:                       no
Features:
   Java/JNI support:                      no
   Multithreading:                        yes
```

Build the project

```
make -j $(sysctl -n hw.logicalcpu)
```

Copy the generated files: `tsk/tsk_config.h`, `tsk/tsk_incs.h`
