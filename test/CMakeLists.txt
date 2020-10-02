cmake_minimum_required(VERSION 2.8.0)

#
# Build Options
#
option(BUILD_EXE_RAJTEST        "build executable rajtest"          OFF)
option(BUILD_EXE_SOCKET_EVENT   "build executable socket_event"     OFF)
option(BUILD_EXE_SOCKET_SERVER  "build executable socket_server"    OFF)
option(BUILD_EXE_GUARD_DAEMON   "build executable guard_daemon"     ON)
option(BUILD_EXE_SOCKET_CLIENT  "build executable socket_client"    OFF)

#
# Rapidjson module Required
#
find_package(rapidjson REQUIRED)
include_directories(SYSTEM ${rapidjson_INCLUDE})

if (BUILD_EXE_RAJTEST)
    add_executable(rajtest  rajtest.cpp ${MANIFEST})
    target_link_libraries(rajtest)
endif(BUILD_EXE_RAJTEST)

if (BUILD_EXE_SOCKET_EVENT)
    add_executable(socket_event  socket_event.cpp ${MANIFEST})
    target_link_libraries(socket_event pthread)
endif(BUILD_EXE_SOCKET_EVENT)

if (BUILD_EXE_SOCKET_SERVER)
    add_executable(socket_server  socket_server.cpp ${MANIFEST})
    target_link_libraries(socket_server pthread)
endif(BUILD_EXE_SOCKET_SERVER)

if (BUILD_EXE_GUARD_DAEMON)
    add_executable(guard_daemon  guard_daemon.cpp ${MANIFEST})
    target_link_libraries(guard_daemon pthread)
endif(BUILD_EXE_GUARD_DAEMON)

if (BUILD_EXE_SOCKET_CLIENT)
    add_executable(socket_client  socket_client.cpp)
    target_link_libraries(socket_client)
endif(BUILD_EXE_SOCKET_CLIENT)
