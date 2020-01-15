# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(grpcMain)
  set(gRPC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(gRPC_BACKWARDS_COMPATIBILITY_MODE OFF CACHE BOOL "" FORCE)
  
  # Disable thirdparty zlib, gflags, cares module
  set(gRPC_ZLIB_PROVIDER "" CACHE STRING "" FORCE)
  set(gRPC_GFLAGS_PROVIDER "" CACHE STRING "" FORCE)
  set(gRPC_CARES_PROVIDER "" CACHE STRING "" FORCE)
  set(gRPC_PROTOBUF_PROVIDER "" CACHE STRING "" FORCE)
    
  # build boringssl as module
  set(gRPC_SSL_PROVIDER module CACHE STRING "" FORCE)

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  add_subdirectory("${library_root}" "${CMAKE_CURRENT_BINARY_DIR}/submodule" EXCLUDE_FROM_ALL)

  set(cares_include_directory
    "${library_root}/third_party/cares/"
    "${library_root}/third_party/cares/cares/"
  )

  target_include_directories(grpc PRIVATE
	${cares_include_directory}
  )

  add_library(thirdparty_grpc INTERFACE)

  target_link_libraries(thirdparty_grpc INTERFACE
    grpc
    thirdparty_zlib
    thirdparty_openssl
    thirdparty_googletest
  )

  target_include_directories(thirdparty_grpc INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/submodule/include"
  )
endfunction()

grpcMain()
