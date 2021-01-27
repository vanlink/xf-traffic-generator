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

#include "lwip/arch.h"
#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/tcp.h"
#include "lwip/memp.h"

#include "dkfw_cps.h"
#include "dpdkframework.h"

#include "xf-tools.h"
#include "xf-stream.h"
#include "xf-protocol-common.h"
#include "xf-protocol-http.h"
#include "xf-sharedmem.h"

int g_stream_cnt = 0;
STREAM *g_streams[STREAM_CNT_MAX];

static int init_stream_stats(DKFW_STATS *stats)
{
    int size;

    size = dkfw_stats_create_with_address(stats, g_pkt_process_core_num, STREAM_STATS_MAX);
    printf("stream stats mem at %p, size=[%d]\n", stats, size);

    dkfw_stats_add_item(stats, STREAM_STATS_TCP_CONN_ATTEMP, DKFW_STATS_TYPE_NUM, "tcp-conn-attemp");
    dkfw_stats_add_item(stats, STREAM_STATS_TCP_CONN_SUCC, DKFW_STATS_TYPE_NUM, "tcp-conn-succ");
    dkfw_stats_add_item(stats, STREAM_STATS_TCP_CLOSE_LOCAL, DKFW_STATS_TYPE_NUM, "tcp-close-local");
    dkfw_stats_add_item(stats, STREAM_STATS_TCP_CLOSE_REMOTE_FIN, DKFW_STATS_TYPE_NUM, "tcp-close-remote-fin");
    dkfw_stats_add_item(stats, STREAM_STATS_TCP_CLOSE_REMOTE_RST, DKFW_STATS_TYPE_NUM, "tcp-close-remote-rst");
    dkfw_stats_add_item(stats, STREAM_STATS_TCP_CLOSE_TIMEOUT, DKFW_STATS_TYPE_NUM, "tcp-close-timeout");
    dkfw_stats_add_item(stats, STREAM_STATS_TCP_CLOSE_ERROR, DKFW_STATS_TYPE_NUM, "tcp-close-err");

    dkfw_stats_add_item(stats, STREAM_STATS_SESSION_TIMEOUT, DKFW_STATS_TYPE_NUM, "session-timeout");

    dkfw_stats_add_item(stats, STREAM_STATS_HTTP_REQUEST, DKFW_STATS_TYPE_NUM, "http-request");
    dkfw_stats_add_item(stats, STREAM_STATS_HTTP_RESPONSE, DKFW_STATS_TYPE_NUM, "http-response");

    return 0;
}

int init_streams(cJSON *json_root)
{
    cJSON *json_stream;
    cJSON *json_array_item;
    STREAM *stream;
    char *str;

    memset(g_streams, 0, sizeof(g_streams));

    json_stream = cJSON_GetObjectItem(json_root, "streams");
    cJSON_ArrayForEach(json_array_item, json_stream){
        stream = rte_zmalloc(NULL, sizeof(STREAM), RTE_CACHE_LINE_SIZE);
        if(!stream){
            printf("init stream mem error.\n");
            return -1;
        }

        if(g_stream_cnt >= STREAM_CNT_MAX){
            printf("too many streams.\n");
            return -1;
        }

        stream->stream_stat = &g_generator_shared_mem->stats_streams[g_stream_cnt].stats_stream;
        init_stream_stats(stream->stream_stat);

        str = cJSON_GetObjectItem(json_array_item, "type")->valuestring;
        if(strstr(str, "httpclient")){
            stream->type = STREAM_TYPE_HTTPCLIENT;
            if(init_stream_http_client(json_array_item, stream) < 0){
                return -1;
            }
        }else if(strstr(str, "httpserver")){
            stream->type = STREAM_TYPE_HTTPSERVER;
            if(init_stream_http_server(json_array_item, stream) < 0){
                return -1;
            }
        }else{
            printf("invalid stream type.\n");
            return -1;
        }

        g_streams[g_stream_cnt] = stream;
        g_stream_cnt++;
    }

    g_generator_shared_mem->streams_cnt = g_stream_cnt;

    return 0;
}

