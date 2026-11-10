# SPDX-FileCopyrightText: 2026 KytyPS5Plus contributors
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.16)
project(KytyPS5Plus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(pkg_extractor
    extractor/main.cpp
    src/pkg.cpp
    src/psf.cpp)
target_include_directories(pkg_extractor PRIVATE src)

if(MSVC)
    target_compile_options(pkg_extractor PRIVATE /W4 /permissive-)
else()
    target_compile_options(pkg_extractor PRIVATE -Wall -Wextra)
endif()

# Tests build synthetic packages with python3 and run the extractor against them.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    enable_testing()
    add_test(NAME synthetic_packages
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/run_tests.py $<TARGET_FILE:pkg_extractor>)
endif()

# Bundle the launcher scripts next to the binary in the build tree.
set(KYTY_SCRIPTS
    extractor/install_pkg.sh extractor/install_pkg.bat
    extractor/batch_install.sh extractor/batch_install.bat
    extractor/readme_linux.txt extractor/readme_windows.txt)
foreach(script ${KYTY_SCRIPTS})
    get_filename_component(script_name ${script} NAME)
    configure_file(${script} ${CMAKE_BINARY_DIR}/${script_name} COPYONLY)
endforeach()

install(TARGETS pkg_extractor RUNTIME DESTINATION .)
install(FILES ${KYTY_SCRIPTS} DESTINATION .)
