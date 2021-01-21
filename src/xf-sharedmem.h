#ifndef XG_GENERATOR_SHAREDMEM_H
#define XG_GENERATOR_SHAREDMEM_H
#include <stdint.h>
#include "dkfw_stats.h"
#include "dkfw_profile.h"
#include "xf-stream.h"

typedef struct _SHARED_MEM_STREAM_T_TAG {
    DKFW_STATS stats_stream;  // 9248
    char pad2[18000];
} SHARED_MEM_STREAM_T;

typedef struct _SHARED_MEM_TAG {
    int pkt_core_cnt;
    int dispatch_core_cnt;
    int streams_cnt;

    uint64_t elapsed_ms;

    DKFW_STATS stats_lwip; // 47528 bytes
    char pad1[128000];

    DKFW_STATS stats_generator;  // 11888 bytes
    char pad2[32000];

    DKFW_STATS stats_dispatch;  // 2648 bytes
    char pad3[8000];

    SHARED_MEM_STREAM_T stats_streams[STREAM_CNT_MAX];

    DKFW_PROFILE profile_pkt[MAX_CORES_PER_ROLE];
    DKFW_PROFILE profile_dispatch[MAX_CORES_PER_ROLE];

} SHARED_MEM_T;

extern SHARED_MEM_T *g_generator_shared_mem;

#endif

