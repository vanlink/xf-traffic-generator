#ifndef XG_GENERATOR_H
#define XG_GENERATOR_H
#include <stdint.h>
#include <rte_per_lcore.h>

#include "dkfw_stats.h"
#include "dkfw_timer.h"
#include "dkfw_profile.h"

#define XF_DEBUG_PROFILE 1

enum {
    PROFILE_ITEM_TIMER,
    PROFILE_ITEM_SEND,
    PROFILE_ITEM_RECV_INTF,
    PROFILE_ITEM_RECV_QUEUE,
    PROFILE_ITEM_MAX,
};

enum {
    PROFILE_SINGLE_A,
    PROFILE_SINGLE_B,
    PROFILE_SINGLE_C,
    PROFILE_SINGLE_D,
    PROFILE_SINGLE_E,
    PROFILE_SINGLE_MAX,
};

#define XF_BASE_DIR "/var/log/xf-traffic-generator"

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

    GENERATOR_STATS_TIMER_MSG_INTERVAL,
    GENERATOR_STATS_TIMER_SESSION_TIMEOUT,

    GENERATOR_STATS_MAX
};

enum {
    DISPATCH_STATS_UNKNOWN_CORE = 0,
    DISPATCH_STATS_CLONE_MBUF_EMPTY,

    DISPATCH_STATS_MAX
};

extern uint64_t tsc_per_sec;
extern uint64_t g_elapsed_ms;
extern DKFW_STATS *g_generator_stats;
extern tvec_base_t *g_generator_timer_bases;

RTE_DECLARE_PER_LCORE(DKFW_PROFILE *, g_profiler);

#define PROFILER_CORE (RTE_PER_LCORE(g_profiler))

#define GENERATOR_STATS_RESPOOL_ALLOC_SUCC(id)  DKFW_STATS_RESOURCE_POOL_ALLOC_SUCC_INCR(g_generator_stats, id, RTE_PER_LCORE(g_cpu_id))
#define GENERATOR_STATS_RESPOOL_ALLOC_FAIL(id)  DKFW_STATS_RESOURCE_POOL_ALLOC_FAIL_INCR(g_generator_stats, id, RTE_PER_LCORE(g_cpu_id))
#define GENERATOR_STATS_RESPOOL_FREE(id)        DKFW_STATS_RESOURCE_POOL_ALLOC_FREE_INCR(g_generator_stats, id, RTE_PER_LCORE(g_cpu_id))

#define GENERATOR_STATS_NUM_INC(id)             DKFW_STATS_CNT_INCR(g_generator_stats,id,RTE_PER_LCORE(g_cpu_id))

#define GENERATOR_STATS_PAIR_START_INC(id)      DKFW_STATS_PAIR_START_INCR(g_generator_stats,id,RTE_PER_LCORE(g_cpu_id))
#define GENERATOR_STATS_PAIR_STOP_INC(id)       DKFW_STATS_PAIR_STOP_INCR(g_generator_stats,id,RTE_PER_LCORE(g_cpu_id))

#define DISPATCH_STATS_NUM_INC(id,core)         DKFW_STATS_CNT_INCR(g_dispatch_stats,id,core)

extern char unique_id[64];

#endif

