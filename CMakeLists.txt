cmake_minimum_required(VERSION 3.15)
project(ramdisc VERSION 0.1.0 LANGUAGES C)

option(RD_BUILD_SHARED "Build ramdisc as a shared library" ON)
option(RD_BUILD_STATIC "Build ramdisc as a static library" OFF)
option(RD_ENABLE_JOURNAL "Enable journaling stubs" OFF)
option(RD_BUILD_TESTS "Build unit tests" ON)

set(RAMDISC_SOURCES
    src/ramdisc.c
)

if(RD_BUILD_SHARED)
    add_library(ramdisc SHARED ${RAMDISC_SOURCES})
    target_compile_definitions(ramdisc PRIVATE RD_BUILD_DLL)
else()
    add_library(ramdisc STATIC ${RAMDISC_SOURCES})
    target_compile_definitions(ramdisc PUBLIC RD_STATIC)
endif()

if(RD_BUILD_STATIC)
    add_library(ramdisc_static STATIC ${RAMDISC_SOURCES})
    target_compile_definitions(ramdisc_static PUBLIC RD_STATIC)
    set_target_properties(ramdisc_static PROPERTIES OUTPUT_NAME ramdisc)
endif()

set_target_properties(ramdisc PROPERTIES
    OUTPUT_NAME ramdisc
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ramdisc
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_definitions(ramdisc
    PUBLIC RD_ENABLE_JOURNAL=$<BOOL:${RD_ENABLE_JOURNAL}>
)

if(MSVC)
    target_compile_options(ramdisc PRIVATE /W4 /WX)
else()
    target_compile_options(ramdisc PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(RD_BUILD_STATIC)
    target_include_directories(ramdisc_static
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    )
    target_compile_definitions(ramdisc_static
        PUBLIC RD_ENABLE_JOURNAL=$<BOOL:${RD_ENABLE_JOURNAL}>
    )
    if(MSVC)
        target_compile_options(ramdisc_static PRIVATE /W4 /WX)
    else()
        target_compile_options(ramdisc_static PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

add_library(ramdisc::ramdisc ALIAS ramdisc)

include(GNUInstallDirs)
install(TARGETS ramdisc
    EXPORT ramdiscTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES include/ramdisc.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT ramdiscTargets
    FILE ramdiscTargets.cmake
    NAMESPACE ramdisc::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ramdisc
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/ramdiscConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ramdiscConfig.cmake.in)
    file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ramdiscConfig.cmake.in
"@PACKAGE_INIT@\n\ninclude(\"${CMAKE_CURRENT_LIST_DIR}/ramdiscTargets.cmake\")\n")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ramdiscConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/ramdiscConfig.cmake
    @ONLY
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/ramdiscConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/ramdiscConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ramdisc
)

if(RD_BUILD_TESTS)
    enable_testing()
    add_executable(ramdisc_tests tests/ramdisc_tests.c)
    target_link_libraries(ramdisc_tests PRIVATE ramdisc)
    target_include_directories(ramdisc_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    if(MSVC)
        target_compile_options(ramdisc_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(ramdisc_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    set(RAMDISC_TEST_CASES
        root_stat
        create_write_read
        mkdir_readdir
        large_write_indirect
        rmdir_nonempty
        enospc_handling
        block_api
        backing_persistence
        seek_whence
        concurrent_handles
        max_file_size
        path_edge_cases
        enospc_recovery
        double_indirect
        many_handles
    )
    foreach(tc IN LISTS RAMDISC_TEST_CASES)
        add_test(NAME ramdisc.${tc} COMMAND ramdisc_tests --case ${tc})
    endforeach()
    add_test(NAME ramdisc.all COMMAND ramdisc_tests)
endif()
