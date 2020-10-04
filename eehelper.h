
#ifndef __TCW_HELPER_H__
#define __TCW_HELPER_H__

#include "include.h"

/** current time(milliseconds) */
uint64_t now_time();

#define ORTHOCODE(orthocode, msg)                   \
    do {                                            \
        uint8_t code = (orthocode) ^ 0;             \
        for (size_t i = 0; i < (msg).size(); i++) { \
            (msg)[i] ^= code;                       \
        }                                           \
    } while (0)

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