cmake_minimum_required(VERSION 2.8.0)

project("tcw" C CXX)

#
# Version
#
set(tcw_VERSION_MAJOR 3)
set(tcw_VERSION_MINOR 1.0)
set(tcw_VERSION ${tcw_VERSION_MAJOR}.${tcw_VERSION_MINOR})
set(PACKAGE_VERSION ${tcw_VERSION})
set(VERSION "${tcw_VERSION}")

#
# if u wanna debug, do like this `cmake -DCMAKE_BUILD_TYPE=Debug`
#
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

#
# Build Options
#
option(BUILD_TESTS  "Build all available test suites"           ON)

if (DEFINED USE_LOG)
    message("use log. synchronous log supported only currently")
    add_definitions(-DUSE_LOG)
endif()

#
# Configuration
#
include("${PROJECT_SOURCE_DIR}/cmake/configuration.cmake")

#
# Modules
#
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/modules")

#
# Concurrentqueue module Required
#
find_package(concurrentqueue REQUIRED)
include_directories(SYSTEM ${concurrentqueue_INCLUDE})

#
# Build
#
include("${PROJECT_SOURCE_DIR}/cmake/manifest.cmake")

include_directories(src)

if (BUILD_TESTS)
    add_subdirectory(tests)
endif()
