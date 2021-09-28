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

Integrate the osquery-toolchain in the main CMakeLists.txt file (see the following file in osquery: `cmake/toolchain.cmake`). Then configure the project.

Force the following `check_include_files()` checks: `stdint.h`, `math.h`, `ctype.h`, `unistd.h`.

```
cmake \
  -S . \
  -B build \
  -DOSQUERY_TOOLCHAIN_SYSROOT=/opt/osquery-toolchain \
  -DBUILD_SHARED_LIBS=OFF \
  -DLIBXML2_WITH_C14N=ON \
  -DLIBXML2_WITH_CATALOG=OFF \
  -DLIBXML2_WITH_DEBUG=OFF \
  -DLIBXML2_WITH_DOCB=OFF \
  -DLIBXML2_WITH_FTP=OFF \
  -DLIBXML2_WITH_HTML=OFF \
  -DLIBXML2_WITH_HTTP=OFF \
  -DLIBXML2_WITH_ICONV=OFF \
  -DLIBXML2_WITH_ICU=OFF \
  -DLIBXML2_WITH_ISO8859X=OFF \
  -DLIBXML2_WITH_LEGACY=OFF \
  -DLIBXML2_WITH_LZMA=OFF \
  -DLIBXML2_WITH_MEM_DEBUG=OFF \
  -DLIBXML2_WITH_MODULES=OFF \
  -DLIBXML2_WITH_OUTPUT=ON \
  -DLIBXML2_WITH_PATTERN=ON \
  -DLIBXML2_WITH_PROGRAMS=OFF \
  -DLIBXML2_WITH_PUSH=ON \
  -DLIBXML2_WITH_PYTHON=OFF \
  -DLIBXML2_WITH_READER=ON \
  -DLIBXML2_WITH_REGEXPS=ON \
  -DLIBXML2_WITH_RUN_DEBUG=OFF \
  -DLIBXML2_WITH_SAX1=OFF \
  -DLIBXML2_WITH_SCHEMAS=OFF \
  -DLIBXML2_WITH_SCHEMATRON=OFF \
  -DLIBXML2_WITH_TESTS=OFF \
  -DLIBXML2_WITH_THREADS=ON \
  -DLIBXML2_WITH_THREAD_ALLOC=OFF \
  -DLIBXML2_WITH_TREE=ON \
  -DLIBXML2_WITH_VALID=OFF \
  -DLIBXML2_WITH_WRITER=ON \
  -DLIBXML2_WITH_XINCLUDE=OFF \
  -DLIBXML2_WITH_XPATH=ON \
  -DLIBXML2_WITH_XPTR=ON \
  -DLIBXML2_WITH_ZLIB=ON \
  -DHAVE_STDINT_H:BOOL=true \
  -DHAVE_MATH_H:BOOL=true \
  -DHAVE_CTYPE_H:BOOL=true \
  -DHAVE_UNISTD_H:BOOL=true \
  -DHAVE_VA_COPY:BOOL=true
```

Build the project

```
cmake \
  --build build \
  -j $(nproc)
```

Copy the generated config files: `build/config.h`, `./build/libxml/xmlversion.h`

# macOS

## Common

Make sure you are working on a clean source folder

```
git reset --hard ; git clean -ffdx
```

When building for m1, also pass the following parameter: `-DCMAKE_OSX_ARCHITECTURES=arm64`

```
cmake \
  -S . \
  -B build \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.12 \
  -DBUILD_SHARED_LIBS=OFF \
  -DLIBXML2_WITH_C14N=ON \
  -DLIBXML2_WITH_CATALOG=OFF \
  -DLIBXML2_WITH_DEBUG=OFF \
  -DLIBXML2_WITH_DOCB=OFF \
  -DLIBXML2_WITH_FTP=OFF \
  -DLIBXML2_WITH_HTML=OFF \
  -DLIBXML2_WITH_HTTP=OFF \
  -DLIBXML2_WITH_ICONV=OFF \
  -DLIBXML2_WITH_ICU=OFF \
  -DLIBXML2_WITH_ISO8859X=OFF \
  -DLIBXML2_WITH_LEGACY=OFF \
  -DLIBXML2_WITH_LZMA=OFF \
  -DLIBXML2_WITH_MEM_DEBUG=OFF \
  -DLIBXML2_WITH_MODULES=OFF \
  -DLIBXML2_WITH_OUTPUT=ON \
  -DLIBXML2_WITH_PATTERN=ON \
  -DLIBXML2_WITH_PROGRAMS=OFF \
  -DLIBXML2_WITH_PUSH=ON \
  -DLIBXML2_WITH_PYTHON=OFF \
  -DLIBXML2_WITH_READER=ON \
  -DLIBXML2_WITH_REGEXPS=ON \
  -DLIBXML2_WITH_RUN_DEBUG=OFF \
  -DLIBXML2_WITH_SAX1=OFF \
  -DLIBXML2_WITH_SCHEMAS=OFF \
  -DLIBXML2_WITH_SCHEMATRON=OFF \
  -DLIBXML2_WITH_TESTS=OFF \
  -DLIBXML2_WITH_THREADS=ON \
  -DLIBXML2_WITH_THREAD_ALLOC=OFF \
  -DLIBXML2_WITH_TREE=ON \
  -DLIBXML2_WITH_VALID=OFF \
  -DLIBXML2_WITH_WRITER=ON \
  -DLIBXML2_WITH_XINCLUDE=OFF \
  -DLIBXML2_WITH_XPATH=ON \
  -DLIBXML2_WITH_XPTR=ON \
  -DLIBXML2_WITH_ZLIB=ON
```

Build the project

```
cmake \
  --build build \
  -j $(nproc)
```

Copy the generated config files: `build/config.h`, `./build/libxml/xmlversion.h`

# Windows

Make sure you are working on a clean source folder

```
git reset --hard ; git clean -ffdx
```

```
cmake ^
  -S . ^
  -B build ^
  -DBUILD_SHARED_LIBS=OFF ^
  -DLIBXML2_WITH_C14N=ON ^
  -DLIBXML2_WITH_CATALOG=OFF ^
  -DLIBXML2_WITH_DEBUG=OFF ^
  -DLIBXML2_WITH_DOCB=OFF ^
  -DLIBXML2_WITH_FTP=OFF ^
  -DLIBXML2_WITH_HTML=OFF ^
  -DLIBXML2_WITH_HTTP=OFF ^
  -DLIBXML2_WITH_ICONV=OFF ^
  -DLIBXML2_WITH_ICU=OFF ^
  -DLIBXML2_WITH_ISO8859X=OFF ^
  -DLIBXML2_WITH_LEGACY=OFF ^
  -DLIBXML2_WITH_LZMA=OFF ^
  -DLIBXML2_WITH_MEM_DEBUG=OFF ^
  -DLIBXML2_WITH_MODULES=OFF ^
  -DLIBXML2_WITH_OUTPUT=ON ^
  -DLIBXML2_WITH_PATTERN=ON ^
  -DLIBXML2_WITH_PROGRAMS=OFF ^
  -DLIBXML2_WITH_PUSH=ON ^
  -DLIBXML2_WITH_PYTHON=OFF ^
  -DLIBXML2_WITH_READER=ON ^
  -DLIBXML2_WITH_REGEXPS=ON ^
  -DLIBXML2_WITH_RUN_DEBUG=OFF ^
  -DLIBXML2_WITH_SAX1=OFF ^
  -DLIBXML2_WITH_SCHEMAS=OFF ^
  -DLIBXML2_WITH_SCHEMATRON=OFF ^
  -DLIBXML2_WITH_TESTS=OFF ^
  -DLIBXML2_WITH_THREADS=ON ^
  -DLIBXML2_WITH_THREAD_ALLOC=OFF ^
  -DLIBXML2_WITH_TREE=ON ^
  -DLIBXML2_WITH_VALID=OFF ^
  -DLIBXML2_WITH_WRITER=ON ^
  -DLIBXML2_WITH_XINCLUDE=OFF ^
  -DLIBXML2_WITH_XPATH=ON ^
  -DLIBXML2_WITH_XPTR=ON ^
  -DLIBXML2_WITH_ZLIB=ON
```

Build the project

```
cmake ^
  --build build ^
  --config Release
```

Copy the generated config files: `build/config.h`, `./build/libxml/xmlversion.h`
