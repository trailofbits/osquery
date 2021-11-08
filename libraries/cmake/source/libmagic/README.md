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
