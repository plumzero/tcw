cmake_minimum_required(VERSION 2.8.0)

project("eeh" C CXX)

#
# Version
#
set(eeh_VERSION_MAJOR 3)
set(eeh_VERSION_MINOR 1.0)
set(eeh_VERSION ${eeh_VERSION_MAJOR}.${eeh_VERSION_MINOR})
set(PACKAGE_VERSION ${eeh_VERSION})
set(VERSION "${eeh_VERSION}")

#
# if u wanna release, do like this `cmake -DCMAKE_BUILD_TYPE=Release`
#
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

#
# Build Options
#
option(BUILD_TESTS  "Build all available test suites"    ON)

#
# Configuration
#
include("${PROJECT_SOURCE_DIR}/cmake/configuration.cmake")

#
# Modules
#
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/modules")

#
# Build
#
include("${PROJECT_SOURCE_DIR}/cmake/manifest.cmake")

include_directories(.)

if (BUILD_TESTS)
    add_subdirectory(test)
endif()