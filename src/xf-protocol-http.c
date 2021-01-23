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

static void http_session_msg_next(SESSION *session, STREAM *stream)
{
    int msg_ind = session->msg_ind;

    session->msg = protocol_http_msg_get(stream->http_message_ind, &msg_ind, (int *)&session->msg_len);
    session->msg_ind = msg_ind;
}

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

    if(session->timer_msg_interval_onfly){
        dkfw_stop_timer(&session->timer_msg_interval);
        GENERATOR_STATS_PAIR_STOP_INC(GENERATOR_STATS_TIMER_MSG_INTERVAL);
    }

    session_free(session);

    return 0;
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
            GENERATOR_STATS_NUM_INC(GENERATOR_STATS_PROTOCOL_WRITE_FAIL);
            return -1;
        }
        altcp_output(pcb);
        session->msg_len -= send_cnt;
        if(!session->msg_len){
            STREAM_STATS_NUM_INC(stream, STREAM_STATS_HTTP_REQUEST);
            session->proto_state = HTTP_STATE_RSP;
            session->msgs_left--;
        }
    }

    return 0;
}

static int http_server_send_data(SESSION *session, STREAM *stream, void *pcb)
{
    uint32_t room = altcp_sndbuf(pcb);
    uint32_t send_cnt;
    err_t err;

    send_cnt = RTE_MIN(room, session->msg_len);
    if(send_cnt){
        err = altcp_write(pcb, session->msg, send_cnt, (session->msg_len == send_cnt) ? 0 : TCP_WRITE_FLAG_MORE);
        if (err !=  ERR_OK) {
            GENERATOR_STATS_NUM_INC(GENERATOR_STATS_PROTOCOL_WRITE_FAIL);
            return -1;
        }
        altcp_output(pcb);
        session->msg_len -= send_cnt;
        if(!session->msg_len){
            STREAM_STATS_NUM_INC(stream, STREAM_STATS_HTTP_RESPONSE);
            session->proto_state = HTTP_STATE_REQ;
        }
    }

    return 0;
}

static int http_client_next_msg_check(SESSION *session, STREAM *stream, void *pcb)
{
    if(session->msgs_left){
        session->proto_state = HTTP_STATE_REQ;
        http_session_msg_next(session, stream);

        if(http_client_send_data(session, stream, pcb) < 0){
            STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_LOCAL);
            http_close_session(session, pcb, 1);
        }
    }else{
        http_close_session(session, pcb, stream->close_with_rst);
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_LOCAL);
    }

    return 0;
}

static int llhttp_on_request_complete(llhttp_t *llhttp)
{
    SESSION *session = llhttp->data;
    STREAM *stream = session->stream;
    struct altcp_pcb *pcb = (struct altcp_pcb *)session->pcb;

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_HTTP_REQUEST);
    session->proto_state = HTTP_STATE_RSP;

    http_session_msg_next(session, stream);
    if(http_server_send_data(session, stream, pcb) < 0){
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_LOCAL);
        http_close_session(session, pcb, 1);
    }

    return HPE_OK;
}

static int llhttp_on_response_complete(llhttp_t *llhttp)
{
    SESSION *session = llhttp->data;
    STREAM *stream = session->stream;
    struct altcp_pcb *pcb = (struct altcp_pcb *)session->pcb;

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_HTTP_RESPONSE);

    if(!session->timer_msg_interval_onfly){
        http_client_next_msg_check(session, stream, pcb);
    }

    return HPE_OK;
}

static void timer_func_http_client_msg(struct timer_list *timer, unsigned long arg)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;
    struct altcp_pcb *pcb = (struct altcp_pcb *)session->pcb;

    dkfw_restart_timer(&g_generator_timer_bases[LWIP_MY_CPUID], timer, *g_elapsed_ms + stream->ipr * 1000);

    http_client_next_msg_check(session, stream, pcb);
}

static int protocol_http_client_connecned(SESSION *session, STREAM *stream, void *pcb)
{
    session->proto_state = HTTP_STATE_REQ;
    http_session_msg_next(session, stream);

    llhttp_init(&session->http_parser, HTTP_RESPONSE, &llhttp_settings_response);
    session->http_parser.data = session;

    if(stream->ipr){
        dkfw_start_timer(&g_generator_timer_bases[LWIP_MY_CPUID], &session->timer_msg_interval, timer_func_http_client_msg, session, *g_elapsed_ms + stream->ipr * 1000);
        session->timer_msg_interval_onfly = 1;
        GENERATOR_STATS_PAIR_START_INC(GENERATOR_STATS_TIMER_MSG_INTERVAL);
    }

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
    http_close_session(session, pcb, stream->close_with_rst);

    return 0;
}

static int protocol_http_client_recv(SESSION *session, STREAM *stream, void *pcb, char *data, int datalen)
{
    if(session->proto_state != HTTP_STATE_RSP){
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_PROTOCOL_DATA_EARLY);
        return -1;
    }

    if(HPE_OK != llhttp_execute(&session->http_parser, data, datalen)){
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_PROTOCOL_HTTP_PARSE_FAIL);
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
    session->msgs_left = stream->rpc;

    return 0;
}

static int protocol_http_server_sent(SESSION *session, STREAM *stream, void *pcb, uint16_t sent_len)
{
    if(session->proto_state != HTTP_STATE_RSP){
        return 0;
    }

    return http_server_send_data(session, stream, pcb);
}

static int protocol_http_server_remote_close(SESSION *session, STREAM *stream, void *pcb)
{
    http_close_session(session, pcb, stream->close_with_rst);

    return 0;
}

static int protocol_http_server_recv(SESSION *session, STREAM *stream, void *pcb, char *data, int datalen)
{
    if(session->proto_state != HTTP_STATE_REQ){
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_PROTOCOL_DATA_EARLY);
        return -1;
    }

    if(HPE_OK != llhttp_execute(&session->http_parser, data, datalen)){
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_PROTOCOL_HTTP_PARSE_FAIL);
        return -1;
    }

    return 0;
}

static int protocol_http_server_err(SESSION *session, STREAM *stream)
{
    http_close_session(session, NULL, 0);
    return 0;
}

static int protocol_http_server_session_new(SESSION *session, STREAM *stream, void *pcb)
{
    llhttp_init(&session->http_parser, HTTP_REQUEST, &llhttp_settings_request);
    session->http_parser.data = session;
    session->proto_state = HTTP_STATE_REQ;

    return 0;
}

int init_stream_http_client(cJSON *json_root, STREAM *stream)
{
    int i;
    uint64_t value;
    cJSON *json_item;

    stream->local_address_ind = cJSON_GetObjectItem(json_root, "local_address_ind")->valueint;
    stream->remote_address_ind = cJSON_GetObjectItem(json_root, "remote_address_ind")->valueint;
    stream->http_message_ind = cJSON_GetObjectItem(json_root, "http_message_ind")->valueint;

    stream->cps = cJSON_GetObjectItem(json_root, "cps")->valueint;
    stream->cps = stream->cps ? stream->cps : 1;
    stream->rpc = cJSON_GetObjectItem(json_root, "rpc")->valueint;
    stream->rpc = stream->rpc ? stream->rpc : 1;
    stream->ipr = cJSON_GetObjectItem(json_root, "ipr")->valueint;

    stream->session_timeout_ms = cJSON_GetObjectItem(json_root, "session_timeout")->valueint * 1000;

    json_item = cJSON_GetObjectItem(json_root, "conn_max_send");

    for(i=0;i<g_lwip_core_cnt;i++){
        value = stream->cps / g_lwip_core_cnt;
        if(i < (int)(stream->cps % g_lwip_core_cnt)){
            value++;
        }
        dkfw_cps_create(&stream->dkfw_cps[i], value, tsc_per_sec);

        if(json_item && json_item->valueint){
            stream->dkfw_cps[i].send_cnt_max = json_item->valueint;
        }
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
    stream->http_message_ind = cJSON_GetObjectItem(json_root, "http_message_ind")->valueint;

    strcpy(stream->listen_ip, cJSON_GetObjectItem(json_root, "listen_ip")->valuestring);
    stream->listen_port = cJSON_GetObjectItem(json_root, "listen_port")->valueint;

    stream->stream_listen = protocol_common_listen;
    stream->stream_session_new = protocol_http_server_session_new;
    stream->stream_sent = protocol_http_server_sent;
    stream->stream_recv = protocol_http_server_recv;
    stream->stream_remote_close = protocol_http_server_remote_close;
    stream->stream_err = protocol_http_server_err;

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

