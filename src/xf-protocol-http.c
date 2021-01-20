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

static int http_close_session(SESSION *session, struct altcp_pcb *pcb, int abort)
{
    if(pcb) {
        altcp_sent(pcb, NULL);
        altcp_recv(pcb, NULL);
        altcp_err(pcb, NULL);

        if(abort){
            altcp_abort(pcb);
        }else{
            if (altcp_close(pcb) != ERR_OK) {
              altcp_abort(pcb);
            }
        }
    }

    session_free(session);

    return 0;
}

static int llhttp_on_request_complete(llhttp_t *llhttp)
{
    return HPE_OK;
}

static int llhttp_on_response_complete(llhttp_t *llhttp)
{
    SESSION *session = llhttp->data;
    STREAM *stream = session->stream;
    struct altcp_pcb *pcb = (struct altcp_pcb *)session->pcb;

    session->response_ok = 1;

    if(session->proto_state == HTTP_STATE_RSP){
        altcp_output(pcb);
        http_close_session(session, pcb, stream->close_with_rst);
    }

    return HPE_OK;
}

static int http_client_send_data(SESSION *session, STREAM *stream, void *pcb)
{
    uint32_t room = altcp_sndbuf(pcb);
    uint32_t send_cnt;
    err_t err;

    send_cnt = RTE_MIN(room, session->msg_len);
    if(send_cnt){
        err = altcp_write(pcb, session->msg, send_cnt, (session->msg_len == send_cnt) ? 0 : TCP_WRITE_FLAG_MORE);
        if (err !=  ERR_OK) {
            return -1;
        }
        session->msg_len -= send_cnt;
        if(!session->msg_len){
            session->proto_state = HTTP_STATE_RSP;
            // server responsed early.
            if(session->response_ok){
                altcp_output(pcb);
                http_close_session(session, pcb, stream->close_with_rst);
            }
        }
    }

    return 0;
}

static int protocol_http_client_connecned(SESSION *session, STREAM *stream, void *pcb)
{
    int msg_ind = session->msg_ind;

    session->proto_state = HTTP_STATE_REQ;
    session->response_ok = 0;
    session->msg = protocol_http_msg_get(stream->http_message_ind, &msg_ind, (int *)&session->msg_len);
    session->msg_ind = msg_ind;

    return http_client_send_data(session, stream, pcb);
}

static int protocol_http_client_sent(SESSION *session, STREAM *stream, void *pcb, uint16_t sent_len)
{
    if(session->proto_state != HTTP_STATE_REQ){
        return 0;
    }

    return http_client_send_data(session, stream, pcb);
}

static int protocol_http_client_remote_close(SESSION *session, STREAM *stream, void *pcb)
{
    altcp_output(pcb);
    http_close_session(session, pcb, stream->close_with_rst);

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
    http_close_session(session, NULL, 0);
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

