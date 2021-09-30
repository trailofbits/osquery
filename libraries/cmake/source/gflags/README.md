# gflags

Notes to reproduce the library configuration and generated files

## Linux

### x86

Using CentOS 6.10 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12
```

Install CMake

```sh
wget https://cmake.org/files/v3.21/cmake-3.21.3-linux-x86_64.tar.gz
sudo tar xvf cmake-3.21.3-Linux-x86_64.tar.gz -C /usr/local --strip 1
```

Install the osquery toolchain

```sh
wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-x86_64.tar.xz
sudo tar xvf osquery-toolchain-1.1.0-x86_64.tar.xz -C /usr/local
```

Configure with
```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_SYSROOT=/usr/local/osquery-toolchain -DCMAKE_CXX_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang++
```

### AArch64

Using Ubuntu 16.04 LTS (glibc 2.23)

```sh
ldd --version
ldd (GNU libc) 2.23
```

Install CMake

```sh
wget https://cmake.org/files/v3.21/cmake-3.21.3-linux-aarch64.tar.gz
sudo tar xvf cmake-3.21.3-Linux-x86_64.tar.gz -C /usr/local --strip 1
```

Install the osquery toolchain

```sh
wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-aarch64.tar.xz
sudo tar xvf osquery-toolchain-1.1.0-aarch64.tar.xz -C /usr/local
```

Configure with
```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_SYSROOT=/usr/local/osquery-toolchain -DCMAKE_CXX_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang++
```

## Windows

Configure with

```sh
cmake -G "Visual Studio 16 2019" -A x64 ../ -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags
```


## macOS

Using macOS 10.15 with XCode 12 and SDK 11.1 on x86_64

Generated with the following commands:

### M1

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 -DCMAKE_OSX_ARCHITECTURES=arm64
```


### x86

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_OSX_DEPLOYMENT_TARGET=10.12
```


## All platforms

Copy the generated files under `include` from the build folder, to the respective folders in the osquery source under `libraries/cmake/source/gflags/generated`

Copy only once (it's the same for all platforms)

```
include/gflags/gflags_completions.h -> generated/gflags/gflags_completions.h
```

Then copy for each os

```
include/gflags/defines.h -> generated/<arch>/<os>/private/defines.h
include/gflags/gflags_declare.h -> generated/<arch>/<os>/public/gflags/gflags_declare.h
include/gflags/gflags.h -> generated/<arch>/<os>/public/gflags/gflags.h
```
