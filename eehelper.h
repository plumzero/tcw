
#ifndef __Epoll_Event_HELPER_H__
#define __Epoll_Event_HELPER_H__

#include "include.h"

/** CRC32 caculate */
template<typename T>
uint32_t crc32calc(T val, size_t size);

template<>
uint32_t crc32calc(const unsigned char *buf, size_t size);

template<>
uint32_t crc32calc(const char *buf, size_t size);

uint32_t crc32calc(std::string fname);

/** add NegoHeader */
template<typename T>
size_t add_header(std::string *out, T val, size_t size);

template<>
size_t add_header(std::string *out, const char *body, size_t bodysize);

template<>
size_t add_header(std::string *out, const unsigned char *body, size_t bodysize);

size_t add_header(std::string *out, const std::string &body);

uint64_t now_time();

#endif // !__Epoll_Event_HELPER_H__