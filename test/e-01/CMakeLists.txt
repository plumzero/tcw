cmake_minimum_required(VERSION 2.8.0)

#
# Rapidjson module Required
#
find_package(rapidjson REQUIRED)
include_directories(SYSTEM ${rapidjson_INCLUDE})

#
# other source file depended by test
#
set(OTHERFILE bic.cpp)
include_directories(.)
