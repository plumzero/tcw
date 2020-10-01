
#ifndef __TCW_INCLUDE_H__
#define __TCW_INCLUDE_H__

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
#include <set>
#include <unordered_map>
#include <queue>
#include <utility>
#include <functional>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <bitset>

typedef struct __attribute__ ((__packed__)) {
    uint8_t     ver[2];             /** 0-major 1-revised */
    uint16_t    bodysize;           /** payload size */
    uint32_t    crc32;
    uint64_t    origin;
    uint64_t    orient;
    uint64_t    pholder;            /** placeholder */
} NegoHeader;

namespace tcw
{
    typedef int FD_t;
    typedef int ID_t;
    typedef int PORT_t;
    typedef int OPTION_t;
    typedef uint64_t SID_t; 
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

#define __LOG(logger, l, t, ...)                   \
    do {                                            \
        logger->log_out(LOG_LEVEL_ ## l,            \
                        LOG_TYPE_ ## t,             \
                        "[" # l "][" # t "] "       \
                        __VA_ARGS__);               \
    } while (0)

#define Erro(logger, type, fmt, ...)             \
    do {                                            \
        __LOG(logger, ERRO, type, "%4d " fmt "\n", \
                    __LINE__, ##__VA_ARGS__);       \
    } while (0)

#define Warn(logger, type, fmt, ...)             \
    do {                                            \
        __LOG(logger, WARN, type, "%4d " fmt "\n", \
                    __LINE__, ##__VA_ARGS__);       \
    } while (0)

#define Info(logger, type, fmt, ...)             \
    do {                                            \
        __LOG(logger, INFO, type, "%4d " fmt "\n", \
                    __LINE__, ##__VA_ARGS__);       \
    } while (0)

#define Dbug(logger, type, fmt, ...)             \
    do {                                            \
        __LOG(logger, DBUG, type, "%4d " fmt "\n", \
                    __LINE__, ##__VA_ARGS__);       \
    } while (0)
    

#define NEGOHSIZE           sizeof(NegoHeader)

#define BUF1KSIZE        1024
#define HEAPSIZE         4096

#define ERRO_FD  stderr
#define INFO_FD  stdout
#define DBUG_FD  stdout

#define ERRO_COLOR   "\033[31m"
#define INFO_COLOR   "\033[32m"
#define DBUG_COLOR   "\033[34m"
#define END_COLOR    "\033[0m"

#define _ECHO(type, format, ...)              \
    do {                                      \
        fprintf(type, format, ##__VA_ARGS__); \
    } while (0)

#define ECHO(type, format, ...)                                                 \
    do {                                                                        \
        _ECHO(type ## _FD, "%u %s %4d " type ## _COLOR format "\n" END_COLOR,   \
                getpid(), "[" #type "] ", __LINE__, ##__VA_ARGS__);             \
    } while (0)

#endif // !__TCW_INCLUDE_H__
