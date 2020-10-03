cmake_minimum_required(VERSION 2.8.0)

#
# Rapidjson module Required
#
find_package(rapidjson REQUIRED)
include_directories(SYSTEM ${rapidjson_INCLUDE})

#
# other source file depended by test
#
set(OTHERFILE msg.cpp)
include_directories(.)

#
# build executable test
#
add_executable(socket_event  socket_event.cpp ${MANIFEST} ${OTHERFILE})
target_link_libraries(socket_event pthread)

add_executable(socket_server  socket_server.cpp ${MANIFEST} ${OTHERFILE})
target_link_libraries(socket_server pthread)
