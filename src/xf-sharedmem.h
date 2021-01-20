#ifndef XG_GENERATOR_SHAREDMEM_H
#define XG_GENERATOR_SHAREDMEM_H
#include <stdint.h>
#include "dkfw_stats.h"
#include "dkfw_profile.h"

typedef struct _SHARED_MEM_TAG {
    int pkt_core_cnt;
    int dispatch_core_cnt;

    uint64_t elapsed_ms;

    DKFW_STATS stats_lwip; // 47528 bytes
    char pad1[128000];

    DKFW_STATS stats_generator;  // 13208 bytes
    char pad2[64000];

    DKFW_PROFILE profile_pkt[MAX_CORES_PER_ROLE];
    DKFW_PROFILE profile_dispatch[MAX_CORES_PER_ROLE];

} SHARED_MEM_T;

#endif

