#ifndef XG_GENERATOR_H
#define XG_GENERATOR_H
#include <stdint.h>

#include "dkfw_stats.h"
#include "dkfw_timer.h"

enum {
    GENERATOR_STATS_LWIP_PROCESS_FAIL = 0,

    GENERATOR_STATS_TO_DPDK_MBUF_EMPTY,
    GENERATOR_STATS_TO_DPDK_MBUF_SMALL,
    GENERATOR_STATS_TO_DPDK_SEND_FAIL,

    GENERATOR_STATS_LOCAL_PORT_NEXT,
    GENERATOR_STATS_LOCAL_PORT_EMPTY,

    GENERATOR_STATS_PROTOCOL_WRITE_FAIL,
    GENERATOR_STATS_PROTOCOL_HTTP_PARSE_FAIL,
    GENERATOR_STATS_PROTOCOL_DATA_EARLY,

    GENERATOR_STATS_SESSION,

    GENERATOR_STATS_MAX
};

enum {
    DISPATCH_STATS_UNKNOWN_CORE = 0,
    DISPATCH_STATS_CLONE_MBUF_EMPTY,

    DISPATCH_STATS_MAX
};

extern uint64_t tsc_per_sec;
extern uint64_t *g_elapsed_ms;
extern DKFW_STATS *g_generator_stats;
extern tvec_base_t *g_generator_timer_bases;

#define GENERATOR_STATS_RESPOOL_ALLOC_SUCC(id)  DKFW_STATS_RESOURCE_POOL_ALLOC_SUCC_INCR(g_generator_stats, id, RTE_PER_LCORE(g_cpu_id))
#define GENERATOR_STATS_RESPOOL_ALLOC_FAIL(id)  DKFW_STATS_RESOURCE_POOL_ALLOC_FAIL_INCR(g_generator_stats, id, RTE_PER_LCORE(g_cpu_id))
#define GENERATOR_STATS_RESPOOL_FREE(id)        DKFW_STATS_RESOURCE_POOL_ALLOC_FREE_INCR(g_generator_stats, id, RTE_PER_LCORE(g_cpu_id))

#define GENERATOR_STATS_NUM_INC(id)             DKFW_STATS_CNT_INCR(g_generator_stats,id,RTE_PER_LCORE(g_cpu_id))

#define DISPATCH_STATS_NUM_INC(id,core)         DKFW_STATS_CNT_INCR(g_dispatch_stats,id,core)

#endif

