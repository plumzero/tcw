
#include "eelog.h"

namespace EEHNS {

Logger::Logger(const char* dir, 
               const char* name,
               uint32_t limit_size,
               uint32_t level) { 
    
    char path[PATH_MAX] = { 0 };
    char bakpath[PATH_MAX] = { 0 };
    FILE* pf = NULL;
    int ret;
    uint32_t fsize;
    strcpy(path, dir);
    if (access(path, W_OK) != 0) {
        ret = mkdir(path, 0666);
        if (ret < 0 && errno != EEXIST) {
            fprintf(stderr, "could not create a folder for log.\n");
            throw std::runtime_error("could not create a folder for log.");
        }
    }
    if (path[strlen(path) - 1] != '/')
        strcat(path, "/");
    strcpy(bakpath, path);
    strcat(path, name);
    if (access(path, F_OK) == 0) {
        pf = fopen(path, "rb");
        fseek(pf, 0, SEEK_END);
        fsize = ftell(pf);
        fseek(pf, 0, SEEK_SET);
        fclose(pf);
        if (fsize > limit_size * 1024 * 1024) {
            strcat(bakpath, "log.bak");
            if (access(bakpath, F_OK) == 0) {
                if (unlink(bakpath) != 0) {
                    fprintf(stderr, "could not delete the old log.\n");
                    throw std::runtime_error("could not delete the old log.");
                }
            }
            if (rename(path, bakpath) != 0) {
                fprintf(stderr, "could not back-up log.\n");
                throw std::runtime_error("could not back-up log.");
            }
        }
    }
    pf = fopen(path, "a+");
    if (pf == NULL) {
        fprintf(stderr, "could not open the log.\n");
        throw;
    }
    if (level > LOG_LEVEL_DBUG || level < LOG_LEVEL_EMER) {
        fprintf(stderr, "log level is invalid.\n");
        throw std::runtime_error("log level is invalid.");
    }
    log_set_global_level(level);
    m_szPath = strdup(path);
    m_nLimitSize = limit_size;
    m_pFile = pf;
    m_nTypeMask = (uint32_t)~0;
    log_init();
}

Logger::Logger(uint32_t level)
{
    log_set_global_level(level);
    m_szPath="";
    m_nLimitSize = 0;
    m_pFile = stdout;
    m_nTypeMask = (uint32_t)~0;
    log_init();
}

Logger::~Logger() { 
    std::lock_guard<std::mutex> locker(m_mtx);
    log_free();
    if (m_pFile != stdout) free((void*)m_szPath);
    if (m_pFile != stdout && m_pFile != nullptr) fclose(m_pFile);
}

int Logger::log_open_stream(FILE *f)
{
    std::lock_guard<std::mutex> locker(m_mtx);
    m_pFile = f;
    return 0;
}

void Logger::log_set_global_level(uint32_t level)
{
    m_nLevel = (uint32_t)level;
}

uint32_t Logger::log_get_global_level(void)
{
    return m_nLevel;
}

int Logger::log_get_level(uint32_t logtype)
{
    if (logtype >= m_nLogTypesSize)
        return -1;

    return m_pLogTypes[logtype].log_type_level;
}

int Logger::log_set_level(uint32_t logtype, uint32_t loglevel)
{
    if (logtype >= m_nLogTypesSize)
        return -1;
    if (loglevel > LOG_LEVEL_DBUG)
        return -1;

    m_pLogTypes[logtype].log_type_level = loglevel;

    return 0;
}

int Logger::log_lookup(const char *name)
{
    size_t i;

    for (i = 0; i < m_nLogTypesSize; i++) {
        if (m_pLogTypes[i].log_type_name == NULL)
            continue;
        if (strcmp(name, m_pLogTypes[i].log_type_name) == 0)
            return i;
    }

    return -1;
}

int Logger::log_register_internal(const char *name, int id)
{
    char *dup_name = strdup(name);

    if (dup_name == NULL)
        return -ENOMEM;

    m_pLogTypes[id].log_type_name = dup_name;
    m_pLogTypes[id].log_type_level = LOG_LEVEL_INFO;

    return id;
}

int Logger::log_register(const char *name)
{
    struct log_type *new_log_types;
    int id, ret;

    id = log_lookup(name);
    if (id >= 0)
        return id;

    new_log_types = (struct log_type *)realloc(m_pLogTypes, sizeof(struct log_type) * (m_nLogTypesSize + 1));
    if (new_log_types == NULL)
        return -ENOMEM;
    m_pLogTypes = new_log_types;

    ret = log_register_internal(name, m_nLogTypesSize);
    if (ret < 0)
        return ret;

    m_nLogTypesSize++;

    return ret;
}

void Logger::log_print_regtab()
{
    uint32_t i;
    const char* level;
    
    for (i = 0; i < m_nLogTypesSize; i++) {
        if (m_pLogTypes[i].log_type_name) {
            printf("%02d: %-20s ", i, m_pLogTypes[i].log_type_name);
            switch (m_pLogTypes[i].log_type_level) {
                case LOG_LEVEL_EMER:
                    level = "EMERG";
                    break;
                case LOG_LEVEL_ALER:
                    level = "ALERT";
                    break;
                case LOG_LEVEL_CRIT:
                    level = "CRITICAL";
                    break;
                case LOG_LEVEL_ERRO:
                    level = "ERROR";
                    break;
                case LOG_LEVEL_WARN:
                    level = "WARNING";
                    break;
                case LOG_LEVEL_NOTI:
                    level = "NOTICE";
                    break;
                case LOG_LEVEL_INFO:
                    level = "INFO";
                    break;
                case LOG_LEVEL_DBUG:
                    level = "DEBUG";
                    break;
                default:
                    level = "";
                    break;
            }
            if (strcmp(level, "")) printf("%-10s\n", level);
        } else {
            printf("%02d: \n", i);
        }
    }
}

void Logger::log_init(void)
{
    uint32_t i;

    m_pLogTypes = (struct log_type *)calloc(LOG_TYPE_FIRST_EXT_ID, sizeof(struct log_type));
    if (m_pLogTypes == NULL)
        return;

    for (i = 0; i < sizeof(reg_table) / sizeof(reg_table[0]); i++)
        log_register_internal(reg_table[i].log_type_name, reg_table[i].log_type_id);

    m_nLogTypesSize = LOG_TYPE_FIRST_EXT_ID;
}

void Logger::log_free(void)
{
    uint32_t i;
    
    for (i = 0; i < sizeof(reg_table) / sizeof(reg_table[0]); i++) {
        uint32_t id = reg_table[i].log_type_id;
        if (m_pLogTypes[id].log_type_name)
            free((void*)(m_pLogTypes[id].log_type_name));
        m_pLogTypes[id].log_type_name = NULL;
    }

    if (m_pLogTypes) 
        free(m_pLogTypes);
    m_pLogTypes = NULL; 
}

int Logger::log_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap)
{
    std::lock_guard<std::mutex> locker(m_mtx);
    int ret;
    char tbuf[64] = { 0 };

    if (level > m_nLevel)
        return 0;
    if (logtype >= m_nLogTypesSize)
        return -1;
    if (level > m_pLogTypes[logtype].log_type_level)
        return 0;
    
    char bakpath[PATH_MAX] = { 0 };
    if (m_pFile != stdout && ftell(m_pFile) > m_nLimitSize * 1024 * 1024) {
        fclose(m_pFile);
        strcpy(bakpath, m_szPath);
        strcat(bakpath, ".bak");
        if (rename(m_szPath, bakpath) != 0) {
            fprintf(stderr, "could not back-up log, use old as before.\n");
        }
        m_pFile = fopen(m_szPath, "a+");
        if (m_pFile == NULL) {
            fprintf(stderr, "could not open the log.\n");
            throw;
        }
    }
    
    time_t now;
    time(&now);
    tm *tm_now = localtime(&now);
    snprintf(tbuf, 64, "%lu %04d.%02d.%02d %02d:%02d:%02d ",
                        (unsigned long)getpid(),
                        tm_now->tm_year + 1900,
                        tm_now->tm_mon + 1,
                        tm_now->tm_mday,
                        tm_now->tm_hour,
                        tm_now->tm_min,
                        tm_now->tm_sec);
    fprintf(m_pFile, "%s", tbuf);
    ret = vfprintf(m_pFile, format, ap);
    fflush(m_pFile);
    return ret;
}

int Logger::log_out(uint32_t level, uint32_t logtype, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_vlog(level, logtype, format, ap);
    va_end(ap);
    return ret;
}

};