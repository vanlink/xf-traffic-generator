#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_malloc.h>

#include "cjson/cJSON.h"

#include "lwip/arch.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/tcp.h"

#include "xf-tools.h"
#include "xf-stream.h"
#include "xf-protocol-common.h"
#include "xf-protocol-http.h"
#include "xf-session.h"
#include "xf-generator.h"

static const char *http_req_str = "GET /small.html HTTP/1.1\r\n" "Host: 127.0.0.1\r\n" "User-Agent: tg\r\n" "Accept: */*\r\n" "\r\n";

static int protocol_http_client_connecned(SESSION *session, STREAM *stream, void *pcb)
{
    err_t err2 = ERR_OK;

    err2 = altcp_write(pcb, http_req_str, strlen(http_req_str), 0);
    if (err2 !=  ERR_OK) {
        printf("cb_httpclient_connected altcp_write err=%d.\n", err2);
        return err2;
    }

    err2 = altcp_output(pcb);
    if (err2 !=  ERR_OK) {
        printf("cb_httpclient_connected altcp_output err=%d.\n", err2);
        return err2;
    }

    return 0;
}

static int protocol_http_client_sent(SESSION *session, STREAM *stream, void *pcb, uint16_t sent_len)
{
    return 0;
}

static int protocol_http_client_remote_close(SESSION *session, STREAM *stream, void *pcb)
{
    return 0;
}

static int protocol_http_client_recv(SESSION *session, STREAM *stream, void *pcb, char *data, int datalen)
{
    printf("%s", data);
    return 0;
}

static int protocol_http_client_err(SESSION *session, STREAM *stream)
{
    return 0;
}

static int protocol_http_client_session_new(SESSION *session, STREAM *stream, void *pcb)
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

    stream->stream_send = protocol_common_send;
    stream->stream_session_new = protocol_http_client_session_new;
    stream->stream_connected = protocol_http_client_connecned;
    stream->stream_sent = protocol_http_client_sent;
    stream->stream_recv = protocol_http_client_recv;
    stream->stream_remote_close = protocol_http_client_remote_close;
    stream->stream_err = protocol_http_client_err;

    return 0;
}

int init_stream_http_server(cJSON *json_root, STREAM *stream)
{
    return 0;
}

