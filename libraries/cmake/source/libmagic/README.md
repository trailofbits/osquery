# macOS

Install the required build-time dependencies

```bash
brew install \
  autoconf \
  automake \
  libtool
```

Prepare the environment

Note: If building for M1, add `-target arm64-apple-macos10.15` at the end of the `CFLAGS` environment variable.

```bash
export CC=clang
export CFLAGS="-mmacosx-version-min=10.12 -isysroot /Applications/Xcode_12.4.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.1.sdk"
```

Configure and build the project

Note: If building for M1, add `--host=arm64-apple-macos10.15` at the end of the configure invocation (otherwise the configure will fail, trying to launch an M1 binary locally).

```bash
autoreconf \
  -f \
  -i
```

```bash
./configure \
  --enable-static \
  --with-pic \
  --disable-libseccomp \
  --disable-bzlib

make -j $(nproc)
```

# Linux

## AArch64

```
cat /etc/issue
Ubuntu 16.04.7 LTS \n \l
```

```
ldd --version
ldd (Ubuntu GLIBC 2.23-0ubuntu11.2) 2.23
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
Written by Roland McGrath and Ulrich Drepper.
```

```
apt show libc-bin
Package: libc-bin
Version: 2.23-0ubuntu11.3

...

```

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

## Common

Prepare the environment

```bash
export PATH="/opt/osquery-toolchain/usr/bin:${PATH}"
export CFLAGS="--sysroot /opt/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang
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
```

Configure and build the project

```bash
autoreconf \
  -f \
  -i

./configure \
  --enable-static \
  --with-pic \
  --disable-libseccomp \
  --disable-bzlib

make -j $(nproc)
```

Copy the generated config files: `config.h`, `src/magic.h`
