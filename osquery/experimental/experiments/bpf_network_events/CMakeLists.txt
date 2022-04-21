# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

add_subdirectory("libraries")

add_osquery_library(osquery_experiments_bpfnetworkevents EXCLUDE_FROM_ALL
  include/osquery/experiments/bpf_network_events.h
  src/bpf_network_events.cpp

  src/bpfnetworkeventstable.h
  src/bpfnetworkeventstable.cpp

  src/networkeventsservice.h
  src/networkeventsservice.cpp
)

target_include_directories(osquery_experiments_bpfnetworkevents PRIVATE
  include
)

target_include_directories(osquery_experiments_bpfnetworkevents SYSTEM INTERFACE
  include
)

target_link_libraries(osquery_experiments_bpfnetworkevents PUBLIC
  osquery_cxx_settings
  osquery_core
  thirdparty_networkevents
)
