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

Make sure that libsasl2 is not enabled

```
sed 's/set(WITH_SASL_CYRUS ON)/set(WITH_SASL_CYRUS OFF)/g' -i CMakeLists.txt
sed -i '/list(APPEND BUILT_WITH "SASL_CYRUS")/d' -i CMakeLists.txt
```

Integrate the osquery-toolchain in the main CMakeLists.txt file (see the following file in osquery: `cmake/toolchain.cmake`). Then configure the project.

```
cmake \
  -S . \
  -B build \
  -DOSQUERY_TOOLCHAIN_SYSROOT=/opt/osquery-toolchain \
  -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_DEVEL=OFF \
  -DENABLE_LZ4_EXT=OFF \
  -DENABLE_REFCNT_DEBUG=OFF \
  -DRDKAFKA_BUILD_EXAMPLES=OFF \
  -DRDKAFKA_BUILD_STATIC=ON \
  -DRDKAFKA_BUILD_TESTS=OFF \
  -DWITHOUT_OPTIMIZATION=OFF \
  -DWITH_PLUGINS=ON \
  -DWITH_SASL=ON \
  -DWITH_SSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_ZSTD=ON \
  -DWITH_SASL_SCRAM:BOOL=ON \
  -DWITH_SASL_OAUTHBEARER:BOOL=ON
```

Build the project

```
cmake \
  --build build
```

Copy the generated config file: `build/generated/config.h`

# macOS

Make sure you are working on a clean source folder

```
git reset --hard ; git clean -ffdx
```

Make sure that libsasl2 is not enabled

```
gsed 's/set(WITH_SASL_CYRUS ON)/set(WITH_SASL_CYRUS OFF)/g' -i CMakeLists.txt
gsed -i '/list(APPEND BUILT_WITH "SASL_CYRUS")/d' -i CMakeLists.txt
```

## x86_64

```sh
cmake \
  -S . \
  -B build \
  -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_DEVEL=OFF \
  -DENABLE_LZ4_EXT=OFF \
  -DENABLE_REFCNT_DEBUG=OFF \
  -DRDKAFKA_BUILD_EXAMPLES=OFF \
  -DRDKAFKA_BUILD_STATIC=ON \
  -DRDKAFKA_BUILD_TESTS=OFF \
  -DWITHOUT_OPTIMIZATION=OFF \
  -DWITH_PLUGINS=ON \
  -DWITH_SASL=ON \
  -DWITH_SSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_ZSTD=ON \
  -DWITH_SASL_SCRAM:BOOL=ON \
  -DWITH_SASL_OAUTHBEARER:BOOL=ON \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.12 \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl@1.1/1.1.1k
```

## Apple Silicon

```sh
cmake \
  -S . \
  -B build \
  -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_DEVEL=OFF \
  -DENABLE_LZ4_EXT=OFF \
  -DENABLE_REFCNT_DEBUG=OFF \
  -DRDKAFKA_BUILD_EXAMPLES=OFF \
  -DRDKAFKA_BUILD_STATIC=ON \
  -DRDKAFKA_BUILD_TESTS=OFF \
  -DWITHOUT_OPTIMIZATION=OFF \
  -DWITH_PLUGINS=ON \
  -DWITH_SASL=ON \
  -DWITH_SSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_ZSTD=ON \
  -DWITH_SASL_SCRAM:BOOL=ON \
  -DWITH_SASL_OAUTHBEARER:BOOL=ON \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl@1.1/1.1.1k
```

# Windows

```
cmake ^
  -S . ^
  -B build ^
  -DBUILD_SHARED_LIBS=OFF ^
  -DENABLE_DEVEL=OFF ^
  -DENABLE_LZ4_EXT=OFF ^
  -DENABLE_REFCNT_DEBUG=OFF ^
  -DRDKAFKA_BUILD_EXAMPLES=OFF ^
  -DRDKAFKA_BUILD_STATIC=ON ^
  -DRDKAFKA_BUILD_TESTS=OFF ^
  -DWITHOUT_OPTIMIZATION=OFF ^
  -DWITH_PLUGINS=ON ^
  -DWITH_SASL=ON ^
  -DWITH_SSL=ON ^
  -DWITH_ZLIB=ON ^
  -DWITH_ZSTD=ON ^
  -DWITH_SASL_SCRAM:BOOL=ON ^
  -DWITH_SASL_OAUTHBEARER:BOOL=ON
```
