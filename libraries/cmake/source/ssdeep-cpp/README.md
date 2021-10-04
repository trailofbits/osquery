# ssdeep-cpp

## Linux

### x86

Using CentOS 6.10 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12
```

Generated with the following commands:

```sh
export TOOLCHAIN=/usr/local/osquery-toolchain
export PATH=${TOOLCHAIN}/usr/bin:$PATH
export COMMON_FLAGS="--sysroot ${TOOLCHAIN}"
export CFLAGS="${COMMON_FLAGS}"
export CXXFLAGS="${COMMON_FLAGS}"
export LDFLAGS="${COMMON_FLAGS}"
export CC=clang
export CXX=clang++

./bootstrap
./configure --disable-shared --enable-static
```

NOTE: If the bootstrap step fails with `configure.ac:12: error: required file './ltmain.sh' not found`, run `libtoolize` and then `./bootstrap` again.

### AArch64

Using Ubuntu 16.04 (glibc 2.23)

```sh
ldd --version
ldd (GNU libc) 2.23
```

Generated with the following commands:

```sh
export TOOLCHAIN=/usr/local/osquery-toolchain
export PATH=${TOOLCHAIN}/usr/bin:$PATH
export COMMON_FLAGS="--sysroot ${TOOLCHAIN}"
export CFLAGS="${COMMON_FLAGS}"
export CXXFLAGS="${COMMON_FLAGS}"
export LDFLAGS="${COMMON_FLAGS}"
export CC=clang
export CXX=clang++

./bootstrap
./configure --disable-shared --enable-static
```

## macOS

Using macOS 11.6 with XCode 13.0 and SDK 11.3 on x86_64

Generated with the following commands:

### M1

```sh
./bootstrap
CFLAGS="-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target arm64-apple-macos10.15" ./configure --disable-shared --enable-static --host=aarch64-apple-darwin
```

### x86_64

```sh
./bootstrap
CFLAGS="-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target x86_64-apple-macos10.12" ./configure --disable-shared --enable-static
```

## Common

Then for all platforms copy

```sh
cp ./config.h ../config/${ARCH}/linux/config.h
```
