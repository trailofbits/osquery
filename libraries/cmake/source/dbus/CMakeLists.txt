# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(dbusMain)
  set(library_root "${OSQUERY_dbus_ROOT_DIR}")

  # The first folder is to bypass the inclusion of CPack by shadowing
  # the inclusion of CPackInstallConfig
  list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/modules"
    "${library_root}/cmake/modules"
    "${library_root}/cmake"
  )

  set(dbus_option_list
    DBUS_BUILD_TESTS
    DBUS_RELOCATABLE
    DBUS_ENABLE_PKGCONFIG
    DBUS_DISABLE_ASSERT
    DBUS_ENABLE_STATS
    DBUS_ENABLE_CONTAINERS
    ENABLE_SYSTEMD
    ENABLE_USER_SESSION
    DBUS_WITH_SYSTEMD_SYSTEMUNITDIR
    DBUS_WITH_SYSTEMD_USERUNITDIR
    GLIB2_FOUND
    DBUS_WITH_GLIB
    DBUS_USE_OUTPUT_DEBUG_STRING
    DBUS_ENABLE_ANSI
    DBUS_ENABLE_VERBOSE_MODE
    DBUS_DISABLE_CHECKS
    DBUS_GCOV_ENABLED
    DBUS_BUS_ENABLE_INOTIFY
    HAVE_CONSOLE_OWNER_FILE
    X11_FOUND
    DBUS_BUILD_X11
    DBUS_INSTALL_SYSTEM_LIBS
    SYSTEMD_FOUND
    _SYSTEMD_FOUND
    DBUS_BUS_ENABLE_SYSTEMD
    DBUS_SYSTEMD_SYSTEMUNITDIR
    DBUS_SYSTEMD_USERUNITDIR
  )

  foreach(dbus_option ${dbus_option_list})
    set("${dbus_option}" false CACHE BOOL "" FORCE)
  endforeach()

  set(EXPAT_FOUND true CACHE BOOL "" FORCE)
  set(EXPAT_INCLUDE_DIR "")
  
  add_library(systemd INTERFACE)

  add_subdirectory("${library_root}" "${CMAKE_CURRENT_BINARY_DIR}/submodule" EXCLUDE_FROM_ALL)
  add_library(thirdparty_dbus INTERFACE)
  target_link_libraries(thirdparty_dbus INTERFACE
    c_settings
  )

  # This does not work, the CMake they have written has too many hardcoded
  # paths and/or use the wrong variables (i.e.: CMAKE_SOURCE_DIR instead of CMAKE_CURRENT_SOURCE_DIR)
  #add_library(thirdparty_dbus INTERFACE)
set(dbus_library_list
  dbus-internal
  dbus-1
  dbus-daemon
  dbus-daemon-launch-helper
  dbus-daemon-internal
  dbus-uuidgen
  dbus-run-session
  dbus-send
  dbus-update-activation-environment
  dbus-cleanup-sockets
  dbus-test-tool
  dbus-launch
  dbus-monitor
)
foreach(dbus_library ${dbus_library_list})
  target_link_libraries("${dbus_library}" c_settings thirdparty_expat)
  set_target_properties("${dbus_library}" PROPERTIES POSITION_INDEPENDENT_CODE true)

endforeach()
target_link_libraries(thirdparty_dbus INTERFACE
  dbus-1
)

target_include_directories(thirdparty_dbus INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_BINARY_DIR}/submodule"
)
endfunction()

dbusMain()
