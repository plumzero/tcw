
#ifndef __INCLUDE_MADOLCHE_QUEEN_TIARAMISU_H__
#define __INCLUDE_MADOLCHE_QUEEN_TIARAMISU_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <queue>
#include <utility>
#include <functional>
#include <algorithm>
#include <mutex>
#include <condition_variable>

/** heading direction of bic message or as a ec service type */
enum _linker_or_server_type {
    LINKER_TYPE_NONE          = 0 << 0,
    LINKER_TYPE_POLICY        = 1 << 0,     /** 远端策略 */
    SERVER_TYPE_TRANSFER      = 1 << 1,     /** 本端转发 */
    SERVER_TYPE_ROVER         = 1 << 2,     /** 本端孤儿TCP客户端 */
    SERVER_TYPE_SYNCHRON      = 1 << 3,     /** 本端TCP服务类型一 */
    SERVER_TYPE_RESONATOR     = 1 << 4,     /** 本端TCP服务类型二 */
    LINKER_TYPE_MADOLCHE      = 1 << 5,     /** 模拟下级服务端子进程一 */
    LINKER_TYPE_CHRONOMALY    = 1 << 6,     /** 模拟下级服务端子进程二 */
    LINKER_TYPE_GIMMICKPUPPET = 1 << 7,     /** 模拟下级服务端进程内启动进程 */
    LINKER_TYPE_ALL        = -1,
};

struct NegoHeader
{
    uint8_t     ver[2];             /** 0-major 1-revised */
    uint16_t    bodysize;           /** payload size */
    uint32_t    crc32;
    uint32_t    pholder;            /** placeholder */
    
    NegoHeader() : bodysize(0), pholder(0)
    {
        ver[0] = ver[1] = 0;
    }
};

namespace EEHNS
{
    static int s_eeh_id = 0;    /** maybe chaos */
    
    typedef int FD_t;
    typedef int ID_t;
    typedef int PORT_t;
    typedef int OPTION_t;
    
    typedef _linker_or_server_type  LINKER_TYPE;
};

#define NEGOHSIZE           sizeof(NegoHeader)

#define BUF1KSIZE        1024
#define HEAPSIZE         4096

#define ERRO_FD  stderr
#define INFO_FD  stdout

#define _ECHO(type, format, ...)              \
    do {                                      \
        fprintf(type, format, ##__VA_ARGS__); \
    } while (0)

#define ECHO(type, format, ...)                                            \
    do {                                                                   \
        _ECHO(type ## _FD, "%u %s %3d " format "\n",                       \
                getpid(), "[" #type "] ", __LINE__, ##__VA_ARGS__);        \
    } while (0)


#define _DEBUG(type, format, ...)             \
    do {                                      \
        fprintf(type, format, ##__VA_ARGS__); \
    } while (0)

#define DBUG_FD  stdout

#define DBUG(format, ...)                                            \
    do {                                                             \
        _DEBUG(DBUG_FD, "%u %s %3d " format "\n",                    \
                    getpid(), "[DBUG] ", __LINE__, ##__VA_ARGS__);   \
    } while (0)

#endif // !__INCLUDE_MADOLCHE_QUEEN_TIARAMISU_H__