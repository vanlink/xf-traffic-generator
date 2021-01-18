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

#include "dkfw_intf.h"
#include "dkfw_core.h"
#include "dkfw_profile.h"
#include "dkfw_ipc.h"
#include "dkfw_timer.h"
#include "dkfw_memory.h"
#include "dpdkframework.h"

#include "xf-sharedmem.h"
#include "xf-session.h"

static struct rte_mempool *sessions = NULL;

int init_sessions(uint64_t cnt)
{
    sessions = rte_mempool_create("sessions", cnt, sizeof(SESSION),
                                                    512,
                                                    0, NULL, NULL, NULL, NULL,
                                                    SOCKET_ID_ANY, MEMPOOL_F_NO_IOVA_CONTIG);
    if(!sessions){
        printf("sessions err.\n");
        return -1;
    }

    printf("init_sessions %lu * %lu = %luMB\n", sizeof(SESSION), cnt, sizeof(SESSION) * cnt / 1000 / 1000);

    return 0;
}

