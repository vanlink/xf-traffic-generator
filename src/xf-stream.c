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

#include "xf-tools.h"
#include "xf-stream.h"
#include "xf-generator.h"
#include "xf-protocol-http.h"

int g_stream_cnt = 0;
STREAM *g_streams[STREAM_CNT_MAX];

static int init_stream_http_client(cJSON *json_root, STREAM *stream)
{
    int i;
    uint64_t cps;

    stream->local_address_ind = cJSON_GetObjectItem(json_root, "local_address_ind")->valueint;
    stream->remote_address_ind = cJSON_GetObjectItem(json_root, "remote_address_ind")->valueint;
    stream->http_message_ind = cJSON_GetObjectItem(json_root, "http_message_ind")->valueint;

    stream->cps = cJSON_GetObjectItem(json_root, "cps")->valueint;
    stream->rpc = cJSON_GetObjectItem(json_root, "rpc")->valueint;
    stream->ipr = cJSON_GetObjectItem(json_root, "ipr")->valueint;

    for(i=0;i<g_lwip_core_cnt;i++){
        cps = stream->cps / g_lwip_core_cnt;
        if(i < (int)(stream->cps % g_lwip_core_cnt)){
            cps++;
        }
        dkfw_cps_create(&stream->dkfw_cps[i], cps, tsc_per_sec);
    }

    stream->send = protocol_http_send;

    return 0;
}

static int init_stream_http_server(cJSON *json_root, STREAM *stream)
{
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
        g_streams[g_stream_cnt] = stream;
        g_stream_cnt++;

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
    }

    return 0;
}

