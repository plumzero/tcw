
option(BUILD_EXE_RAJTEST        "build executable rajtest"          ON)
option(BUILD_EXE_SOCKET_EVENT   "build executable socket_event"     ON)
option(BUILD_EXE_SOCKET_SERVER  "build executable socket_server"    ON)
option(BUILD_EXE_GUARD_DAEMON   "build executable guard_daemon"     ON)
option(BUILD_EXE_SOCKET_CLIENT  "build executable socket_client"    ON)

include_directories(..)
aux_source_directory(.. SRCS)

if (BUILD_EXE_RAJTEST)
    add_executable(rajtest  rajtest.cpp ${SRCS})
    target_link_libraries(rajtest pthread)
endif(BUILD_EXE_RAJTEST)

if (BUILD_EXE_SOCKET_EVENT)
    add_executable(socket_event  socket_event.cpp ${SRCS})
    target_link_libraries(socket_event pthread)
endif(BUILD_EXE_SOCKET_EVENT)

if (BUILD_EXE_SOCKET_SERVER)
    add_executable(socket_server  socket_server.cpp ${SRCS})
    target_link_libraries(socket_server pthread)
endif(BUILD_EXE_SOCKET_SERVER)

if (BUILD_EXE_GUARD_DAEMON)
    add_executable(guard_daemon  guard_daemon.cpp ${SRCS} ${sdksrcs})
    target_link_libraries(guard_daemon ${hsm_library_name} ${openssl_library_name} -ldl pthread)
endif(BUILD_EXE_GUARD_DAEMON)

if (BUILD_EXE_SOCKET_CLIENT)
    add_executable(socket_client  socket_client.cpp)
    target_link_libraries(socket_client pthread)
endif(BUILD_EXE_SOCKET_CLIENT)