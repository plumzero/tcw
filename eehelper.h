
#ifndef __TCW_HELPER_H__
#define __TCW_HELPER_H__

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

namespace tcw
{
    template <size_t N>
    class BitRing
    {
    public:
        BitRing() { mask.reset(); cur = 0; }
        
        void set()
        {
            mask[cur++ % N] = 1;
        }
        void unset()
        {
            mask[cur++ % N] = 0;
        }
        double ratio()
        {
            size_t i;
            int t = 0;
            for (i = 0; i < mask.size(); i++) {
                if (mask.test(i)) {
                    ++t;
                }
            }
            
            return (double) t / N;
        }
        
    public:
        std::bitset<N> mask;
        int cur;
    };
};

#endif // !__TCW_HELPER_H__