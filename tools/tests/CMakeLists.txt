# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryToolsTestsMain)
  if(OSQUERY_BUILD_TESTS)
    set(configs_base_path "${CMAKE_CURRENT_SOURCE_DIR}/configs")
    generateCopyFileTarget("osquery_tools_tests_conffiles" "${configs_base_path}" "REGEX" "*.conf" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_configfiles" "${configs_base_path}" "REGEX" "*.config" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_plistfiles" "${configs_base_path}" "REGEX" "*.plist" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_testfiles" "${configs_base_path}" "REGEX" "*" "${TEST_CONFIGS_DIR}")
    generateCopyFileTarget("osquery_tools_tests_awsfiles" "${configs_base_path}" "REGEX" "aws/*" "${TEST_CONFIGS_DIR}")
    generatePythonTests()
  endif()
endfunction()

function(addPython2Test)
  set(oneValueArgs NAME SCRIPT)
  set(multiValueArgs EXTRA_ARGS)
  cmake_parse_arguments(PARSE_ARGV 0 osquery_test "" "${oneValueArgs}" "${multiValueArgs}")

  get_filename_component(script_name "${osquery_test_SCRIPT}" NAME)

  configure_file("${osquery_test_SCRIPT}" ${script_name} COPYONLY)

  set(python_test_command
    "${CMAKE_COMMAND}" -E env "PYTHONPATH=${OSQUERY_PYTHON_PATH}"
    "${Python2_EXECUTABLE}" -u ${script_name} --verbose --build "${CMAKE_BINARY_DIR}" --test-configs-dir "${TEST_CONFIGS_DIR}" "${osquery_test_EXTRA_ARGS}")

  add_test(NAME ${osquery_test_NAME}
    COMMAND ${python_test_command}
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

  set_tests_properties(${osquery_test_NAME} PROPERTIES TIMEOUT 30)
endfunction()

function(preparePythonTestsEnvironment)
  # Common files and scripts needed by the tests
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test_base.py" test_base.py COPYONLY)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/utils.py" utils.py COPYONLY)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test_http_server.py" test_http_server.py COPYONLY)
  configure_file("${CMAKE_SOURCE_DIR}/tools/deployment/osquery.example.conf" "${TEST_CONFIGS_DIR}/osquery.example.conf" COPYONLY)

  add_custom_target(osquery_tools_tests_pythontests ALL)

  # Create the directory where python modules should go
  set(python_modules_root_dir "${OSQUERY_PYTHON_PATH}")

  # Get the osquery to thrift python interface path in the binary dir to link it into the python modules path
  get_target_property(thrift_osquery_python_interface_dir osquery_extensions_thrift_osquerypy INTERFACE_DIR)

  add_custom_command(
    OUTPUT "${python_modules_root_dir}/osquery"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${python_modules_root_dir}/osquery"
    COMMAND "${CMAKE_COMMAND}" -E touch "${python_modules_root_dir}/osquery/__init__.py"
  )

  set(python_modules_deps_dirs_links
    "${thrift_osquery_python_interface_dir}/osquery/extensions|${python_modules_root_dir}/osquery/extensions"
  )

  set(create_python_modules_tree_deps
    "${python_modules_root_dir}"
    "${python_modules_root_dir}/osquery"
    "${python_modules_root_dir}/osquery/extensions"
  )

  set(create_python_modules_tree_target_deps
    osquery_extensions_thrift_osquerypy
  )

  # The test test_example_queries requires to use codegen scripts, let's copy them in the binary dir
  generateCopyFileTarget("osquery_tools_codegen_scripts" "${CMAKE_SOURCE_DIR}/tools/codegen" "REGEX" "gen*.py" "${CMAKE_CURRENT_BINARY_DIR}")

  # Also prepare a proper module path for utils.py
  add_custom_target(osquery_prepare_utils_for_gentable DEPENDS "${python_modules_root_dir}/osquery/tools/tests/utils.py")
  add_custom_command(
    OUTPUT "${python_modules_root_dir}/osquery/tools/tests/utils.py"
    COMMAND "${CMAKE_COMMAND}" -E make_directory  "${python_modules_root_dir}/osquery/tools/tests"
    COMMAND "${CMAKE_COMMAND}" -E touch "${python_modules_root_dir}/osquery/__init__.py"
    COMMAND "${CMAKE_COMMAND}" -E touch "${python_modules_root_dir}/osquery/tools/__init__.py"
    COMMAND "${CMAKE_COMMAND}" -E touch "${python_modules_root_dir}/osquery/tools/tests/__init__.py"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink "${CMAKE_CURRENT_BINARY_DIR}/utils.py" "${python_modules_root_dir}/osquery/tools/tests/utils.py"
  )

  if(PLATFORM_WINDOWS)
    configure_file("${CMAKE_SOURCE_DIR}/tools/tests/winexpect.py" winexpect.py COPYONLY)
  else()

    # Posix platforms use the extension shipped with the pre-built packages or built from source, lets link it inside the python path
    get_target_property(thrift_python_install_dir thirdparty_thrift_python EXTENSION_INSTALL_DIR)

    list(APPEND python_modules_deps_dirs_links
      "${thrift_python_install_dir}/thrift|${python_modules_root_dir}/thrift"
    )

    list(APPEND create_python_modules_tree_deps
      "${python_modules_root_dir}/thrift"
    )

    list(APPEND create_python_modules_tree_target_deps
      thirdparty_thrift_python
    )
  endif()

  add_custom_target(create_python_modules_tree DEPENDS "${create_python_modules_tree_deps}")

  foreach(link_info ${python_modules_deps_dirs_links})
    string(REPLACE "|" ";" link_info_list "${link_info}")
    list(GET link_info_list 0 source_folder)
    list(GET link_info_list 1 destination_folder)
    add_custom_command(OUTPUT "${destination_folder}" COMMAND "${CMAKE_COMMAND}" -E create_symlink "${source_folder}" "${destination_folder}")
  endforeach()

  foreach(target_dep ${create_python_modules_tree_target_deps})
    add_dependencies(create_python_modules_tree ${target_dep})
  endforeach()

  add_dependencies(osquery_prepare_utils_for_gentable create_python_modules_tree)
  add_dependencies(osquery_tools_tests_pythontests osqueryd)
  add_dependencies(osquery_tools_tests_pythontests osquery_tools_tests_testfiles)
  add_dependencies(osquery_tools_tests_pythontests osquery_prepare_utils_for_gentable)
  add_dependencies(osquery_tools_tests_pythontests osquery_tools_codegen_scripts)
  add_dependencies(osquery_tools_tests_pythontests specs_table_files)
  add_dependencies(osquery_tools_tests_pythontests create_python_modules_tree)
endfunction()

function(generatePythonTests)

  preparePythonTestsEnvironment()

  # Tests
  addPython2Test(NAME tools_tests_testosqueryd SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_osqueryd.py")

  addPython2Test(NAME tools_tests_testosqueryi SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_osqueryi.py")

  addPython2Test(NAME tools_tests_testrelease SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_release.py")

  if(DEFINED PLATFORM_WINDOWS)
    addPython2Test(NAME tools_tests_testwindowsservice SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_windows_service.py")
  else()
    addPython2Test(NAME tools_tests_testadditional SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_additional.py")

    addPython2Test(NAME tools_tests_testexamplequeries SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_example_queries.py")

    # The following tests need to be restored when extensions work again
    addPython2Test(NAME tools_tests_testextensions SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/test_extensions.py" "")
    set_tests_properties(tools_tests_testextensions PROPERTIES DISABLED TRUE)
  endif()
endfunction()

osqueryToolsTestsMain()
