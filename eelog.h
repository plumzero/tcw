
#ifndef __Epoll_Event_LOG_H__
#define __Epoll_Event_LOG_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

namespace EEHNS {

/** index of fundmental log type */
#define LOG_TYPE_GLOB               0
#define LOG_TYPE_WARD               1
#define LOG_TYPE_FLOW               2
#define LOG_TYPE_CHLD               3
#define LOG_TYPE_SERV               4
#define LOG_TYPE_FUNC               5
#define LOG_TYPE_TEST               6
/** index of user's application log type */
#define LOG_TYPE_USER_MIX          21
#define LOG_TYPE_USER_XYZ          22
/** the first index of extend log type */
#define LOG_TYPE_FIRST_EXT_ID      32

/** log level */
#define LOG_LEVEL_EMER     1U
#define LOG_LEVEL_ALER     2U
#define LOG_LEVEL_CRIT     3U
#define LOG_LEVEL_ERRO     4U
#define LOG_LEVEL_WARN     5U
#define LOG_LEVEL_NOTI     6U
#define LOG_LEVEL_INFO     7U
#define LOG_LEVEL_DBUG     8U

struct log_type {
    const char *log_type_name;
    uint32_t    log_type_level;
};

struct log_type_reg_table {
    uint32_t    log_type_id;
    const char *log_type_name;
};

class Logger
{
public:
    Logger(const char* dir, 
           const char* name, 
           uint32_t limit_size = 1, 
           uint32_t level = LOG_LEVEL_DBUG);
    ~Logger();
public:
    void      log_init(void);
    void      log_free(void);
    int       log_open_stream(FILE* f);
    void      log_set_global_level(uint32_t level);
    uint32_t  log_get_global_level(void);
    int       log_get_level(uint32_t logtype);
    int       log_set_level(uint32_t logtype, uint32_t level);
    int       log_register(const char *name);
    void      log_print_regtab();
    int       log_out(uint32_t level, uint32_t logtype, const char *format, ...);
private:
    int       log_lookup(const char *name);
    int       log_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap);
    int       log_register_internal(const char *name, int id);

private:
    uint32_t         m_nTypeMask;
    uint32_t         m_nLevel;
    const char*      m_szPath;
    uint32_t         m_nLimitSize;
    FILE*            m_pFile;
    struct log_type* m_pLogTypes;
    size_t           m_nLogTypesSize;
};

static const struct log_type_reg_table reg_table[] = {
    { LOG_TYPE_GLOB,     "Global" },
    { LOG_TYPE_WARD,     "Guard"  },
    { LOG_TYPE_FLOW,     "Flow"   },
    { LOG_TYPE_CHLD,     "Child"  },
    { LOG_TYPE_SERV,     "Server" },
    { LOG_TYPE_FUNC,     "Func"   },
    { LOG_TYPE_TEST,     "Test"   },

    { LOG_TYPE_USER_MIX, "mix user application" },
    { LOG_TYPE_USER_XYZ, "xyz user application" },
};

};

#endif // ! __Epoll_Event_LOG_H__