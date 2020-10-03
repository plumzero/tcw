cmake_minimum_required(VERSION 2.8.0)

#
# Build Options
#
option(BUILD_e_01   "build executable e_01"     OFF)
option(BUILD_f_01   "build executable f_01"     ON)
option(BUILD_f_02   "build executable f_01"     ON)

if (BUILD_e_01)
    add_subdirectory(e-01)
endif()

if (BUILD_f_01)
    add_subdirectory(f-01)
endif()

if (BUILD_f_02)
    add_subdirectory(f-02)
endif()
