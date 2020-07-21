# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(expatMain)
  set(expat_option_list
    EXPAT_BUILD_TOOLS
    EXPAT_BUILD_EXAMPLES
    EXPAT_BUILD_TESTS
    EXPAT_SHARED_LIBS
    EXPAT_BUILD_DOCS
    EXPAT_BUILD_FUZZERS
    EXPAT_OSSFUZZ_BUILD
    EXPAT_WITH_LIBBSD
    EXPAT_ENABLE_INSTALL
    EXPAT_DTD
    EXPAT_NS
    EXPAT_WARNINGS_AS_ERRORS
    EXPAT_DEV_URANDOM
    EXPAT_ATTR_INFO
    EXPAT_LARGE_SIZE
    EXPAT_MIN_SIZE
  )

  foreach(expat_option ${expat_option_list})
    set("${expat_option}" false CACHE BOOL "" FORCE)
  endforeach()

  add_subdirectory(src/expat)
  if(NOT TARGET expat)
    message(FATAL_ERROR "Failed to import the expat library")
  endif()

  target_link_libraries(expat PRIVATE
    c_settings
  )

  add_library(thirdparty_expat INTERFACE)
  target_link_libraries(thirdparty_expat INTERFACE
    cxx_settings
    expat
  )

  target_include_directories(thirdparty_expat INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/expat/lib"
  )
endfunction()

expatMain()
