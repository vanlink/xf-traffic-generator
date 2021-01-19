#ifndef XG_GENERATOR_SHAREDMEM_H
#define XG_GENERATOR_SHAREDMEM_H
#include <stdint.h>
#include "dkfw_stats.h"

typedef struct _SHARED_MEM_TAG {
    DKFW_STATS stats_lwip;
    char pad1[128000];

    uint64_t elapsed_ms;

} SHARED_MEM_T;

#endif

