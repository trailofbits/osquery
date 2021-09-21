# zlib

Check that the generated `zconf.h` and the compilation enables the defines that we are hardcoding in the CMake.

## Linux

### x86

Using CentOS 6.10 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12
```

Fix the toolchain with some symlinks:

```bash
export TOOLCHAIN=/usr/local/osquery-toolchain
sudo ln -s nm ${TOOLCHAIN}/usr/bin/
sudo ln -s objdump ${TOOLCHAIN}/usr/bin/
sudo ln -s ranlib ${TOOLCHAIN}/usr/bin/
sudo ln -s strip ${TOOLCHAIN}/usr/bin/
sudo ln -s ar ${TOOLCHAIN}/usr/bin/
```

Generated with the following commands:
```bash
export PATH="${TOOLCHAIN}/usr/bin:${PATH}"
export CFLAGS="--sysroot ${TOOLCHAIN}"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export CC=clang

./configure --static --64
make
```

### AArch64

Using Ubuntu 16.04 LTS (glibc 2.23)

```sh
ldd --version
ldd (GNU libc) 2.23
```

Generated with the following commands:

```bash
export PATH="/usr/local/osquery-toolchain/usr/bin:${PATH}"
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export CC=clang

./configure --static --64
make
```

## macOS

Using macOS 10.16 with XCode 13 and SDK 11.3 on x86_64

Generated with the following commands:

### M1

```sh
CFLAGS="-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target arm64-apple-macos10.15" ./configure --static --64
make
```

### x86

```sh
CFLAGS="-target arm64-apple-macos10.12"
./configure --static --64
make
```
