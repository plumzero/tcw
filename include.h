
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
#include <unordered_map>
#include <queue>
#include <utility>
#include <functional>
#include <algorithm>

#include "config.h"

/** heading direction of bic message or as a ec service type */
// enum _linker_or_server_type {
    // LINKER_TYPE_NONE          = 0 << 0,
    // LINKER_TYPE_POLICY        = 1 << 0,     /** 远端策略 */
    // SERVER_TYPE_TRANSFER      = 1 << 1,     /** 本端转发 */
    // SERVER_TYPE_ROVER         = 1 << 2,     /** 本端孤儿TCP客户端 */
    // SERVER_TYPE_SYNCHRON      = 1 << 3,     /** 本端TCP服务类型一 */
    // SERVER_TYPE_RESONATOR     = 1 << 4,     /** 本端TCP服务类型二 */
    // LINKER_TYPE_MADOLCHE      = 1 << 5,     /** 模拟下级服务端子进程一 */
    // LINKER_TYPE_CHRONOMALY    = 1 << 6,     /** 模拟下级服务端子进程二 */
    // LINKER_TYPE_GIMMICKPUPPET = 1 << 7,     /** 模拟下级服务端进程内启动进程 */
    // LINKER_TYPE_ALL           = -1,
// };

#define  RESERVE_ZONE   1000000L

typedef struct __attribute__ ((__packed__)) {
    uint8_t     ver[2];             /** 0-major 1-revised */
    uint16_t    bodysize;           /** payload size */
    uint32_t    crc32;
    uint32_t    pholder;            /** placeholder */
} NegoHeader;

namespace EEHNS
{
    typedef int FD_t;
    typedef int ID_t;
    typedef int PORT_t;
    typedef int OPTION_t;
    
    typedef uint32_t  _linker_or_server_type;
    typedef _linker_or_server_type  LINKER_TYPE;
};

namespace
{
    inline std::string bin2hex(const std::string& bin)
    {
        std::string hex;
        
        for (const auto & ele : bin) {
            hex.append(1, "0123456789ABCDEF"[static_cast<int>((unsigned char)ele) / 16]);
            hex.append(1, "0123456789ABCDEF"[static_cast<int>((unsigned char)ele) % 16]);
        }
        
        return hex;
    }
	
    inline std::string hex2bin(const std::string& hex)
    {
        std::string bin(hex.size() / 2, '\x0');
        
        char ch, ck;
        int i = 0;
        
        for (const auto & ele : hex) {
            if (ele >= '0' && ele <= '9') ch = ele - '0'; else
            if (ele >= 'A' && ele <= 'F') ch = ele - '7'; else
            if (ele >= 'a' && ele <= 'f') ch = ele - 'W'; else
                return "";
            
            ck = ((i & 1) != 0) ? ch : ch << 4;
            
            bin[i >> 1] = (unsigned char)(bin[i >> 1] | ck);
            i++;
        }
        
        return bin;
    }
    
    template<typename T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    std::string integral2hex(const T& t)
    {    
        const unsigned LE = 1;
        unsigned isLittleEndian = *((char*)&LE);
        
        std::string ts(reinterpret_cast<const char*>((unsigned char*)&t), sizeof(t));
        
        size_t b, e;
        
        isLittleEndian ? (b = 0, e = ts.find_last_not_of('\x0') + 1)
                       : (b = ts.find_first_not_of('\x0'), e = sizeof(t) + 1);

        std::string bin(ts.begin() + b, ts.begin() + e);
            
        // store with big-endian mode
        isLittleEndian ? std::reverse(bin.begin(), bin.end()) : void(0);
        
        return bin.empty() ? "00" : bin2hex(bin);
    }

    template<typename T, class = typename std::enable_if<std::is_integral<T>::value>::type,
             typename S, class = typename std::enable_if<std::is_convertible<S, std::string>::value, std::string>::type>
    T hex2integral(const S& hex)
    {    
        const unsigned LE = 1;
        unsigned isLittleEndian = *((char*)&LE);
        
        std::string bin(hex2bin(hex));

        isLittleEndian ? std::reverse(bin.begin(), bin.end()) : void(0);

        isLittleEndian ? bin.append(sizeof(T) - bin.size(), '\x0')
                       : bin.insert(0, sizeof(T) - bin.size(), '\x0');

        return *reinterpret_cast<const T*>(bin.c_str());
    }
    
};

#define EEHLOG(logger, l, t, ...)                   \
    do {                                            \
        logger->log_out(LOG_LEVEL_ ## l,            \
                        LOG_TYPE_ ## t,             \
                        "[" # l "][" # t "] "       \
                        __VA_ARGS__);               \
    } while (0)

#define EEHERRO(logger, type, fmt, ...)             \
    do {                                            \
        EEHLOG(logger, ERRO, type, "%4d " fmt "\n", \
                    __LINE__, ##__VA_ARGS__);       \
    } while (0)

#define EEHWARN(logger, type, fmt, ...)             \
    do {                                            \
        EEHLOG(logger, WARN, type, "%4d " fmt "\n", \
                    __LINE__, ##__VA_ARGS__);       \
    } while (0)

#define EEHINFO(logger, type, fmt, ...)             \
    do {                                            \
        EEHLOG(logger, INFO, type, "%4d " fmt "\n", \
                    __LINE__, ##__VA_ARGS__);       \
    } while (0)

#define EEHDBUG(logger, type, fmt, ...)             \
    do {                                            \
        EEHLOG(logger, DBUG, type, "%4d " fmt "\n", \
                    __LINE__, ##__VA_ARGS__);       \
    } while (0)
    

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