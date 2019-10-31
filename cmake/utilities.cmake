# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

# Generates an include namespace; this is sadly required by the Buck-based project and can't be removed
function(generateIncludeNamespace target_name namespace_path mode)
  # Make sure we actually have parameters
  if(${ARGC} EQUAL 0)
    message(SEND_ERROR "No library specified")
    return()
  endif()

  # Validate the mode
  if(NOT "${mode}" STREQUAL "FILE_ONLY" AND NOT "${mode}" STREQUAL "FULL_PATH")
    message(SEND_ERROR "Invalid namespace generation mode")
    return()
  endif()

  # Generate a root target that we'll attach to the user target
  set(index 1)

  while(true)
    set(root_target_name "${target_name}_ns_gen_${index}")
    if(NOT TARGET "${root_target_name}")
      break()
    endif()

    MATH(EXPR index "${index}+1")
  endwhile()

  add_custom_target("${root_target_name}"
    COMMENT "Generating namespace '${namespace_path}' for target '${target_name}'"
  )

  add_dependencies("${target_name}" "${root_target_name}")

  get_target_property(target_type "${target_name}" TYPE)
  if("${target_type}" STREQUAL "INTERFACE_LIBRARY")
    set(target_mode "INTERFACE")
  else()
    set(target_mode "PUBLIC")
  endif()

  foreach(relative_source_file_path ${ARGN})
    get_filename_component(source_name "${relative_source_file_path}" NAME)

    set(target_namespace_root_directory "${CMAKE_BINARY_DIR}/ns_${target_name}")

    if("${mode}" STREQUAL "FILE_ONLY")
      set(output_source_file_path "${target_namespace_root_directory}/${namespace_path}/${source_name}")
    else()
      set(output_source_file_path "${target_namespace_root_directory}/${namespace_path}/${relative_source_file_path}")
    endif()

    get_filename_component(parent_folder_path "${output_source_file_path}" DIRECTORY)
    set(source_base_path "${CMAKE_CURRENT_SOURCE_DIR}")
    set(absolute_source_file_path "${source_base_path}/${relative_source_file_path}")

    add_custom_command(
      OUTPUT "${output_source_file_path}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${parent_folder_path}"
      COMMAND "${CMAKE_COMMAND}" -E create_symlink "${absolute_source_file_path}" "${output_source_file_path}"
      VERBATIM
    )

    string(REPLACE "/" "_" file_generator_name "${target_name}_ns_${relative_source_file_path}")
    add_custom_target("${file_generator_name}" DEPENDS "${output_source_file_path}")
    add_dependencies("${root_target_name}" "${file_generator_name}")

    if(ADD_HEADERS_AS_SOURCES)
      target_sources("${target_name}" ${target_mode} "${absolute_source_file_path}")
    endif()
  endforeach()

  # So that the IDE finds all the necessary headers
  add_dependencies("prepare_for_ide" "${root_target_name}")

  target_include_directories("${target_name}" ${target_mode} "${target_namespace_root_directory}")
endfunction()

# Marks the specified target to enable link whole archive
function(enableLinkWholeArchive target_name)
  if(DEFINED PLATFORM_LINUX)
    set(new_project_target_link_options
      "SHELL:-Wl,--whole-archive $<TARGET_FILE:${target_name}> -Wl,--no-whole-archive"
    )
  elseif(DEFINED PLATFORM_MACOS)
    set(new_project_target_link_options
      "SHELL:-Wl,-force_load $<TARGET_FILE:${target_name}>"
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    set(new_project_target_link_options
      "/WHOLEARCHIVE:$<TARGET_FILE:${target_name}>"
    )
  endif()

  target_link_options(${target_name} INTERFACE ${new_project_target_link_options})
endfunction()

function(findPythonExecutablePath)
  find_package(Python2 COMPONENTS Interpreter REQUIRED)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
endfunction()

function(generateBuildTimeSourceFile file_path content)
  add_custom_command(
    OUTPUT "${file_path}"
    COMMAND "${CMAKE_COMMAND}" -E echo "${content}" > "${file_path}"
    VERBATIM
  )
endfunction()

function(generateUnsupportedPlatformSourceFile)
  set(source_file "${CMAKE_CURRENT_BINARY_DIR}/osquery_unsupported_platform_target_source_file.cpp")
  set(file_content "#error This target does not support this platform")

  generateBuildTimeSourceFile(${source_file} ${file_content})

  set(unsupported_platform_source_file "${source_file}" PARENT_SCOPE)
endfunction()

function(generateCopyFileTarget name base_path type relative_file_paths destination)

  if(base_path)
    set(base_path "${base_path}/")
  else()
    set(base_path "${CMAKE_CURRENT_SOURCE_DIR}/")
  endif()

  if(type STREQUAL "REGEX")
    if(base_path)
      file(GLOB_RECURSE relative_file_paths RELATIVE "${base_path}" "${base_path}${relative_file_paths}")
    else()
      file(GLOB_RECURSE relative_file_paths "${base_path}${relative_file_paths}")
    endif()
  endif()

  add_custom_target("${name}")

  foreach(file ${relative_file_paths})
    get_filename_component(intermediate_directory "${file}" DIRECTORY)
    list(APPEND intermediate_directories "${intermediate_directory}")
  endforeach()

  list(REMOVE_DUPLICATES intermediate_directories)

  foreach(directory ${intermediate_directories})
    add_custom_command(
      OUTPUT "${destination}/${directory}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${destination}/${directory}"
    )
    list(APPEND created_directories "${destination}/${directory}")
  endforeach()

  list(APPEND "create_dirs_deps"
    "${created_directories}"
    "${destination}"
  )

  add_custom_target("${name}_create_dirs" DEPENDS "${create_dirs_deps}")
  add_custom_command(
    OUTPUT "${destination}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${destination}"
  )

  foreach(file ${relative_file_paths})

    get_filename_component(filename "${file}" NAME)

    if("${filename}" STREQUAL "BUCK")
      continue()
    endif()

    add_custom_command(
      OUTPUT "${destination}/${file}"
      COMMAND "${CMAKE_COMMAND}" -E copy "${base_path}${file}" "${destination}/${file}"
    )
    list(APPEND copied_files "${destination}/${file}")
  endforeach()

  add_custom_target("${name}_copy_files" DEPENDS "${copied_files}")

  add_dependencies("${name}_copy_files" "${name}_create_dirs")
  add_dependencies("${name}" "${name}_copy_files")

  set_target_properties("${name}" PROPERTIES FILES_DESTINATION_DIR "${destination}")
endfunction()

function(add_osquery_executable)
  set(osquery_exe_options EXCLUDE_FROM_ALL;WIN32;MACOSX_BUNDLE)
  set(osquery_exe_ARGN ${ARGN})

  list(GET osquery_exe_ARGN 0 osquery_exe_name)
  list(REMOVE_AT osquery_exe_ARGN 0)

  foreach(arg ${osquery_exe_ARGN})
    list(FIND osquery_exe_options "${arg}" arg_POS)
    if(${arg_POS} EQUAL -1 AND NOT IS_ABSOLUTE "${arg}")
      set(base_path "${CMAKE_CURRENT_SOURCE_DIR}")
      list(APPEND osquery_exe_args "${base_path}/${arg}")
    else()
      list(APPEND osquery_exe_args "${arg}")
    endif()
  endforeach()

  add_executable(${osquery_exe_name} ${osquery_exe_args})

  if("${osquery_exe_name}" MATCHES "-test$" AND DEFINED PLATFORM_POSIX)
    target_link_options("${osquery_exe_name}" PRIVATE -Wno-sign-compare)
  endif()
endfunction()

function(add_osquery_library)
  set(osquery_lib_options STATIC;SHARED;MODULE;OBJECT;UNKNOWN;EXCLUDE_FROM_ALL;IMPORTED;GLOBAL;INTERFACE)
  set(osquery_lib_ARGN ${ARGN})

  list(GET osquery_lib_ARGN 0 osquery_lib_name)
  list(REMOVE_AT osquery_lib_ARGN 0)

  foreach(arg ${osquery_lib_ARGN})
    list(FIND osquery_lib_options "${arg}" arg_POS)
    if(${arg_POS} EQUAL -1 AND NOT IS_ABSOLUTE "${arg}")
      set(base_path "${CMAKE_CURRENT_SOURCE_DIR}")
      list(APPEND osquery_lib_args "${base_path}/${arg}")
    else()
      list(APPEND osquery_lib_args "${arg}")
    endif()
  endforeach()

  add_library(${osquery_lib_name} ${osquery_lib_args})
endfunction()

# This function modifies an existing cache variable but without changing its description
function(overwrite_cache_variable variable_name type value)
  get_property(current_help_string CACHE "${variable_name}" PROPERTY HELPSTRING)
  if(NOT DEFINED current_help_string)
    set(current_help_string "No description")
  endif()
  list(APPEND cache_args "CACHE" "${type}" "${current_help_string}")
  set("${variable_name}" "${value}" ${cache_args} FORCE)
endfunction()

function(generateSpecialTargets)
  # Used to generate all the files necessary to have a complete view of the project in the IDE
  add_custom_target(prepare_for_ide)

  set(excluded_folders
    "libraries/cmake/source"
  )

  set(command_prefix)
  if(OSQUERY_TOOLCHAIN_SYSROOT)
    set(command_prefix "${CMAKE_COMMAND}" -E env "PATH=${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin:$ENV{PATH}")
  endif()

  add_custom_target(format_check
    COMMAND ${command_prefix} "${Python2_EXECUTABLE}" ${CMAKE_SOURCE_DIR}/tools/formatting/format-check.py --exclude-folders ${excluded_folders} origin/master
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    VERBATIM
  )
  add_custom_target(format
    COMMAND ${command_prefix} "${Python2_EXECUTABLE}" ${CMAKE_SOURCE_DIR}/tools/formatting/git-clang-format.py --exclude-folders ${excluded_folders} -f --style=file
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    VERBATIM
  )
endfunction()

function(collectInterfaceOptionsFromTarget)
  set(oneValueArgs TARGET COMPILE DEFINES LINK)
  cmake_parse_arguments(PARSE_ARGV 0 osquery "" "${oneValueArgs}" "")

  if(NOT osquery_TARGET OR NOT TARGET ${osquery_TARGET})
    message(FATAL_ERROR "A valid target has to be provided")
  endif()

  set(target_list ${osquery_TARGET})
  set(target_list_length 1)

  while(${target_list_length} GREATER 0)
    foreach(target ${target_list})

      if(NOT TARGET ${target})
        continue()
      endif()

      get_target_property(target_type ${target} TYPE)

      if(NOT "${target_type}" STREQUAL "INTERFACE_LIBRARY")
        continue()
      endif()

      get_target_property(dependencies ${target} INTERFACE_LINK_LIBRARIES)

      if(NOT "${dependencies}" STREQUAL "dependencies-NOTFOUND")
        list(APPEND new_target_list ${dependencies})
      endif()

      get_target_property(compile_options ${target} INTERFACE_COMPILE_OPTIONS)
      get_target_property(compile_definitions ${target} INTERFACE_COMPILE_DEFINITIONS)
      get_target_property(link_options ${target} INTERFACE_LINK_OPTIONS)

      if(osquery_COMPILE AND NOT "${compile_options}" STREQUAL "compile_options-NOTFOUND")
        list(APPEND compile_options_list ${compile_options})
      endif()

      if(osquery_DEFINES AND NOT "${compile_definitions}" STREQUAL "compile_definitions-NOTFOUND")
        list(APPEND compile_definitions_list ${compile_definitions})
      endif()

      if(osquery_LINK AND NOT "${link_options}" STREQUAL "link_options-NOTFOUND")
        list(APPEND link_options_list ${link_options})
      endif()
    endforeach()

    set(target_list ${new_target_list})
    list(LENGTH target_list target_list_length)
    unset(new_target_list)
  endwhile()

  list(REMOVE_DUPLICATES compile_options_list)
  list(REMOVE_DUPLICATES compile_definitions_list)
  list(REMOVE_DUPLICATES link_options_list)

  if(osquery_COMPILE)
    set(${osquery_COMPILE} ${compile_options_list} PARENT_SCOPE)
  endif()

  if(osquery_LINK_OPTIONS)
    set(${osquery_LINK_OPTIONS} ${link_options_list} PARENT_SCOPE)
  endif()

  if(osquery_DEFINES)
    set(${osquery_DEFINES} ${compile_definitions_list} PARENT_SCOPE)
  endif()

endfunction()

function(copyInterfaceTargetFlagsTo destination_target source_target mode)

  collectInterfaceOptionsFromTarget(TARGET ${source_target}
    COMPILE compile_options_list
    LINK link_options_list
    DEFINES compile_definitions_list
  )

  get_target_property(dest_compile_options_list ${destination_target} INTERFACE_COMPILE_OPTIONS)
  get_target_property(dest_compile_definitions_list ${destination_target} INTERFACE_COMPILE_DEFINITIONS)
  get_target_property(dest_link_options_list ${destination_target} INTERFACE_LINK_OPTIONS)

  if("${dest_compile_options_list}" STREQUAL "dest_compile_options_list-NOTFOUND")
    unset(dest_compile_options_list)
  endif()

  if("${dest_compile_definitions_list}" STREQUAL "dest_compile_definitions_list-NOTFOUND")
    unset(dest_compile_definitions_list)
  endif()

  if("${dest_link_options_list}" STREQUAL "dest_link_options_list-NOTFOUND")
    unset(dest_link_options_list)
  endif()

  list(APPEND dest_compile_options_list ${compile_options_list})
  list(APPEND dest_compile_definitions_list ${compile_definitions_list})
  list(APPEND dest_link_options_list ${link_options_list})

  target_compile_options(${destination_target} ${mode} ${dest_compile_options_list})
  target_compile_definitions(${destination_target} ${mode} ${dest_compile_definitions_list})
  target_link_options(${destination_target} ${mode} ${dest_link_options_list})
endfunction()
