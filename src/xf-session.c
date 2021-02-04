#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_launch.h>
#include <rte_memory.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_bitmap.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_net.h>

#include "cjson/cJSON.h"

#include "lwip/init.h"

#include "dkfw_intf.h"
#include "dkfw_core.h"
#include "dkfw_profile.h"
#include "dkfw_ipc.h"
#include "dkfw_timer.h"
#include "dkfw_memory.h"
#include "dpdkframework.h"

#include "xf-sharedmem.h"
#include "xf-session.h"
#include "xf-generator.h"

static struct rte_mempool *sessions[MAX_CORES_PER_ROLE] = {NULL};

int init_sessions(uint64_t cnt)
{
    int i;
    uint64_t cnt_core = cnt / g_pkt_process_core_num;
    char buff[64];

    for(i=0;i<g_pkt_process_core_num;i++){
        sprintf(buff, "sessioncore%d", i);
        sessions[i] = rte_mempool_create(buff, cnt_core, sizeof(SESSION),
                                                    512,
                                                    0, NULL, NULL, NULL, NULL,
                                                    SOCKET_ID_ANY, MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET | MEMPOOL_F_NO_IOVA_CONTIG);
        if(!sessions[i]){
            printf("sessions err.\n");
            return -1;
        }
    }

    printf("init_sessions %lu * %lu = %luMB\n", sizeof(SESSION), cnt, sizeof(SESSION) * cnt / 1000 / 1000);

    return 0;
}

SESSION *session_get(void)
{
    SESSION *sess = NULL;

    if(rte_mempool_get(sessions[LWIP_MY_CPUID], (void **)&sess) < 0) {
        GENERATOR_STATS_RESPOOL_ALLOC_FAIL(GENERATOR_STATS_SESSION);
        return NULL;
    }

    GENERATOR_STATS_RESPOOL_ALLOC_SUCC(GENERATOR_STATS_SESSION);

    bzero(sess, sizeof(SESSION));

    return sess;
}

void session_free(SESSION *sess)
{
    GENERATOR_STATS_RESPOOL_FREE(GENERATOR_STATS_SESSION);
    rte_mempool_put(sessions[LWIP_MY_CPUID], sess);
}

