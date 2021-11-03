# Linux

## x86

Using CentOS 6.10 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12
```

Generated with the following commands:

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DWITH_TLS=OFF -DWITH_GFLAGS=OFF -DWITH_THREADS=ON -DHAVE_LIB_GFLAGS=ON -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON -DCMAKE_SYSROOT=/usr/local/osquery-toolchain -DCMAKE_CXX_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang++ -DCMAKE_C_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang -DCMAKE_C_FLAGS="-pthread" -DCMAKE_CXX_FLAGS="-pthread"
```

## AArch64

Using Ubuntu 16.04 (glibc 2.23)

```sh
ldd --version
ldd (Ubuntu GLIBC 2.23-0ubuntu11.3) 2.23
```

Generated with the following commands:

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DWITH_TLS=OFF -DWITH_GFLAGS=OFF -DWITH_THREADS=ON -DHAVE_LIB_GFLAGS=ON -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON -DCMAKE_SYSROOT=/usr/local/osquery-toolchain -DCMAKE_CXX_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang++ -DCMAKE_C_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang -DCMAKE_C_FLAGS="-pthread" -DCMAKE_CXX_FLAGS="-pthread"
```

# Windows

Configure with

```sh
cmake -G "Visual Studio 16 2019" -A x64 ../ -DWITH_TLS=OFF -DWITH_GFLAGS=OFF -DWITH_THREADS=ON -DHAVE_LIB_GFLAGS=ON -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON
```


# macOS

Using macOS 11.x with XCode 13 and SDK 11.3 on x86_64

## x86

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DWITH_TLS=OFF -DWITH_GFLAGS=OFF -DWITH_THREADS=ON -DHAVE_LIB_GFLAGS=ON -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON -DCMAKE_OSX_DEPLOYMENT_TARGET=10.12
```
## M1

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DWITH_TLS=OFF -DWITH_GFLAGS=OFF -DWITH_THREADS=ON -DHAVE_LIB_GFLAGS=ON -DCMAKE_OSX_ARCHITECTURES=arm64 -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15
```

# All platforms

Copy the generated files from the build folder, to the respective folders in the osquery source under `libraries/cmake/source/glog/generated`

```
glog -> libraries/cmake/source/glog/generated/<os>/<architecture>/public/glog
config.h -> libraries/cmake/source/glog/generated/<os>/<architecture>private/config.h
```

Edit `TEST_SRC_DIR` in `generated/<os>/<architecture>/private/config.h` and set it to `""`, since it's not necessary
