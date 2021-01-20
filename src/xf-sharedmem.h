#ifndef XG_GENERATOR_SHAREDMEM_H
#define XG_GENERATOR_SHAREDMEM_H
#include <stdint.h>
#include "dkfw_stats.h"

typedef struct _SHARED_MEM_TAG {
    uint64_t elapsed_ms;

    DKFW_STATS stats_lwip; // 47528 bytes
    char pad1[128000];

    DKFW_STATS stats_generator;  // 13208 bytes
    char pad2[64000];

} SHARED_MEM_T;

#endif

