# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

cmake_minimum_required(VERSION 3.14.6)
include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

importSourceSubmodule(
  NAME "grpc"

  NO_RECURSIVE

  SUBMODULES
    "src"
    "src/third_party/abseil-cpp"
    "src/third_party/benchmark"
    "src/third_party/bloaty"
    "src/third_party/cares/cares"
    "src/third_party/protobuf"
    "src/third_party/udpa"

  PATCH
    "src"
)
