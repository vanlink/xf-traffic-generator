#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_common.h>
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
#include "xf-protocol-http-msg.h"

#include "llhttp.h"

#define HTTP_STATE_REQ 0
#define HTTP_STATE_RSP 1

static llhttp_settings_t llhttp_settings_request;
static llhttp_settings_t llhttp_settings_response;

static int llhttp_on_request_complete(llhttp_t *llhttp)
{
    printf("llhttp_on_request_complete\n");
    return HPE_OK;
}

static int llhttp_on_response_complete(llhttp_t *llhttp)
{
    printf("llhttp_on_response_complete\n");
    return HPE_OK;
}

static int protocol_http_client_connecned(SESSION *session, STREAM *stream, void *pcb)
{
    int msg_ind = session->msg_ind;
    uint32_t room = altcp_sndbuf(pcb);
    uint32_t send_cnt;
    err_t err;

    session->proto_state = HTTP_STATE_REQ;
    session->msg = protocol_http_msg_get(stream->http_message_ind, &msg_ind, (int *)&session->msg_len);
    session->msg_ind = msg_ind;

    send_cnt = RTE_MIN(room, session->msg_len);
    if(send_cnt){
        err = altcp_write(pcb, session->msg, send_cnt, (session->msg_len == send_cnt) ? 0 : TCP_WRITE_FLAG_MORE);
        if (err !=  ERR_OK) {
            return -1;
        }
        session->msg_len -= send_cnt;
        if(!session->msg_len){
            session->proto_state = HTTP_STATE_RSP;
        }
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
    if(HPE_OK != llhttp_execute(&session->http_parser, data, datalen)){
        return -1;
    }

    return 0;
}

static int protocol_http_client_err(SESSION *session, STREAM *stream)
{
    return 0;
}

static int protocol_http_client_session_new(SESSION *session, STREAM *stream, void *pcb)
{
    llhttp_init(&session->http_parser, HTTP_RESPONSE, &llhttp_settings_response);
    session->http_parser.data = session;

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

int init_protocol_http(void)
{
    llhttp_settings_init(&llhttp_settings_request);
    llhttp_settings_init(&llhttp_settings_response);

    llhttp_settings_request.on_message_complete = llhttp_on_request_complete;
    llhttp_settings_response.on_message_complete = llhttp_on_response_complete;

    return 0;
}

