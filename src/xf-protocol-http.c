#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_malloc.h>

#include "cjson/cJSON.h"

#include "lwip/init.h"

#include "xf-tools.h"
#include "xf-stream.h"
#include "xf-protocol-common.h"
#include "xf-protocol-http.h"
#include "xf-session.h"
#include "xf-generator.h"

static int protocol_http_client_session_new(SESSION *session, STREAM *stream)
{
    return 0;
}

int init_stream_http_client(cJSON *json_root, STREAM *stream)
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

    stream->send = protocol_common_send;
    stream->session_new = protocol_http_client_session_new;

    return 0;
}

int init_stream_http_server(cJSON *json_root, STREAM *stream)
{
    return 0;
}

