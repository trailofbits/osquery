# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

if(OSQUERY_BUILD_BPF)
  # TODO: Fix this in the networkevents library
  message(FATAL_ERROR "BPF support can't be enabled when OSQUERY_BUILD_EXPERIMENTS is ON")
endif()

# TODO: This is going to import the system zlib
add_subdirectory("src" EXCLUDE_FROM_ALL)

target_link_libraries(networkevents PRIVATE
  thirdparty_cxx_settings
)

add_library(thirdparty_networkevents ALIAS networkevents)
