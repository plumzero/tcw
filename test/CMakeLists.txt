cmake_minimum_required(VERSION 2.8.0)

#
# Build Options
#
option(BUILD_EXE_SOCKET_EVENT   "build executable socket_event"     ON)
option(BUILD_EXE_SOCKET_SERVER  "build executable socket_server"    ON)
option(BUILD_EXE_GUARD_DAEMON   "build executable guard_daemon"     ON)

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

if (BUILD_EXE_SOCKET_EVENT)
    add_executable(socket_event  socket_event.cpp ${MANIFEST} ${OTHERFILE})
    target_link_libraries(socket_event pthread)
endif(BUILD_EXE_SOCKET_EVENT)

if (BUILD_EXE_SOCKET_SERVER)
    add_executable(socket_server  socket_server.cpp ${MANIFEST} ${OTHERFILE})
    target_link_libraries(socket_server pthread)
endif(BUILD_EXE_SOCKET_SERVER)

if (BUILD_EXE_GUARD_DAEMON)
    add_executable(guard_daemon  guard_daemon.cpp ${MANIFEST} ${OTHERFILE})
    target_link_libraries(guard_daemon pthread)
endif(BUILD_EXE_GUARD_DAEMON)

