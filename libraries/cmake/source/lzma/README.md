# lzma

## Linux

### x86

Using CentOS 6.10 (glibc 2.12). Download the tarball version.

```sh
ldd --version
ldd (GNU libc) 2.12
```

Generated with the following commands:

```bash
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang

./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb,delta --enable-decoders=lzma1,lzma2,x86,arm,armthumb,delta --disable-nls
```

### AArch64

Using Ubuntu 16.04 (glibc 2.23).

```sh
ldd --version
ldd (GNU libc) 2.23
```

Install:
```
sudo apt install autoconf automake libtool
```

Generated with the following commands:

```bash
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang

./autogen.sh
./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb,delta --enable-decoders=lzma1,lzma2,x86,arm,armthumb,delta --disable-nls
```

### Common

Then copy

```sh
cp ./config.h ../config/ARCH/linux/config.h
```

From the build we also add the defines:
```
HAVE_CONFIG_H
TUKLIB_SYMBOL_PREFIX=lzma_
```

## macOS

Using macOS 10.15 with XCode 12 and SDK 11.1 on x86_64

Generated with the following commands:

### M1

```sh
./autogen.sh
CFLAGS="-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.1.sdk -target arm64-apple-macos10.15" ./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb,delta --enable-decoders=lzma1,lzma2,x86,arm,armthumb,delta --disable-nls --host=aarch64-apple-darwin
```

### x86_64
```sh
./autogen.sh
./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb,delta --enable-decoders=lzma1,lzma2,x86,arm,armthumb,delta --disable-nls
```

Then for both architectures copy

```sh
cp ./config.h ../config/ARCH/macos/config.h
```

From the build we also add the defines:
```
HAVE_CONFIG_H
TUKLIB_SYMBOL_PREFIX=lzma_
```

## Windows

Copy `windows\vs2019\config.h` from the lzma source to `config\x86_64\windows`.

Then comment these defines inside the `config.h` file:
```
#define HAVE_DECODER_IA64 1
#define HAVE_DECODER_POWERPC 1
#define HAVE_DECODER_SPARC 1

#define HAVE_ENCODER_IA64 1
#define HAVE_ENCODER_POWERPC 1
#define HAVE_ENCODER_SPARC 1
```
