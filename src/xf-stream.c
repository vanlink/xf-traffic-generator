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
#include "xf-certificate.h"

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

static int init_streams_tls_client(STREAM *stream, cJSON *json_root)
{
    cJSON *json = cJSON_GetObjectItem(json_root, "tlsconf");

    stream->tls_client_config = altcp_tls_create_config_client(json ? (const u8_t *)json->valuestring : NULL, stream->stream_is_tls == STREAM_TLS_TYPE_CNTLS);

    if(!stream->tls_client_config){
        printf("create ssl client config fail.\n");
        return -1;
    }

    return 0;
}

static int init_streams_tls_server(STREAM *stream, cJSON *json_root)
{
    cJSON *json = cJSON_GetObjectItem(json_root, "certificate_ind");
    char *cert, *certpath;
    int cert_len;
    char *key, *keypath;
    int key_len;
    char *password;

    if(json){
        if(certificate_get(json->valueint, &cert, &cert_len, &key, &key_len, &password, &certpath, &keypath) < 0){
            printf("certificate_ind get err.\n");
            return -1;
        }
        stream->tls_server_config = altcp_tls_create_config_server_privkey_cert((u8_t *)keypath, 0, NULL, 0, (u8_t *)certpath, 0);
    }else{
        json = cJSON_GetObjectItem(json_root, "tlsconf");
        if(json){
            stream->tls_server_config = altcp_tls_create_config_server_privkey_cert(NULL, 0, NULL, 0, (u8_t *)json->valuestring, 0);
        }
    }

    if(!stream->tls_server_config){
        printf("create ssl server config fail.\n");
        return -1;
    }

    return 0;
}

int init_streams(cJSON *json_root)
{
    cJSON *json_stream;
    cJSON *json_array_item;
    STREAM *stream;
    char *str = "httpclient";
    cJSON *json;

    memset(g_streams, 0, sizeof(g_streams));

    json_stream = cJSON_GetObjectItem(json_root, "streams");
    cJSON_ArrayForEach(json_array_item, json_stream){
        stream = rte_zmalloc(NULL, sizeof(STREAM), 0);
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

        json = cJSON_GetObjectItem(json_array_item, "tls");
        if(json){
            stream->stream_is_tls = json->valueint;
        }

        json = cJSON_GetObjectItem(json_array_item, "type");
        if(json){
            str = json->valuestring;
        }
        if(strstr(str, "httpclient")){
            stream->type = STREAM_TYPE_HTTPCLIENT;
            if(stream->stream_is_tls){
                if(init_streams_tls_client(stream, json_array_item) < 0){
                    return -1;
                }
            }
            if(init_stream_http_client(json_array_item, stream) < 0){
                return -1;
            }
        }else if(strstr(str, "httpserver")){
            stream->type = STREAM_TYPE_HTTPSERVER;
            if(stream->stream_is_tls){
                if(init_streams_tls_server(stream, json_array_item) < 0){
                    return -1;
                }
            }
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

    if(!g_stream_cnt){
        printf("No streams in config file.\n");
        return -1;
    }

    g_generator_shared_mem->streams_cnt = g_stream_cnt;

    return 0;
}

static int stream_stop_one(STREAM *stream)
{
    if(stream->stream_send_back && stream->stream_send){
        stream->stream_send = NULL;
    }

    return 0;
}

static int stream_start_one(STREAM *stream)
{
    if(stream->stream_send_back && !stream->stream_send){
        stream->stream_send = stream->stream_send_back;
    }

    return 0;
}

int streams_stop(void)
{
    int i;
    STREAM *stream;

    for(i=0;i<g_stream_cnt;i++){
        stream = g_streams[i];
        stream_stop_one(stream);
    }
    return 0;
}

int streams_start(void)
{
    int i;
    STREAM *stream;

    for(i=0;i<g_stream_cnt;i++){
        stream = g_streams[i];
        stream_start_one(stream);
    }
    return 0;
}

