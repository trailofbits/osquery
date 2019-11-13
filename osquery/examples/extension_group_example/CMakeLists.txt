include(${CMAKE_SOURCE_DIR}/external/cmake/cmakelibs.cmake)

project(ext_group_example)

function(osqueryExtensionGroupExampleMain)
  set(project_common_include_dirs
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
  )

  set(example_table_sources
    "${CMAKE_CURRENT_SOURCE_DIR}/src/example.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/example.cpp"
  )

  set(complex_example_table_sources
    "${CMAKE_CURRENT_SOURCE_DIR}/src/complex_example.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/complex_example.cpp"
  )

  addOsqueryExtensionEx("ExampleTable" "table" "example"
    SOURCES ${example_table_sources}
    INCLUDEDIRS  ${project_common_include_dirs}
    MAININCLUDES example.h
  )

  addOsqueryExtensionEx("ComplexExampleTable" "table" "complex_example"
    SOURCES ${complex_example_table_sources}
    INCLUDEDIRS  ${project_common_include_dirs}
    MAININCLUDES complex_example.h
  )

  generateOsqueryExtensionGroup()
endfunction()

osqueryExtensionGroupExampleMain()
