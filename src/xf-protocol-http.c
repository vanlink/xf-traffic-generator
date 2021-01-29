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
#include "xf-address.h"
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

    if(session->timer_session_timeout_onfly){
        dkfw_stop_timer(&session->timer_session_timeout);
        GENERATOR_STATS_PAIR_STOP_INC(GENERATOR_STATS_TIMER_SESSION_TIMEOUT);
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
        session->response_ok = 0;

        if(http_client_send_data(session, stream, pcb) < 0){
            STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_LOCAL);
            http_close_session(session, pcb, 1);
            return -1;
        }
    }else{
        http_close_session(session, pcb, stream->close_with_rst);
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_LOCAL);
        if(stream->close_with_rst){
            return -1;
        }
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

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_HTTP_RESPONSE);
    session->response_ok = 1;

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

static void timer_func_session_timeout(struct timer_list *timer, unsigned long arg)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;
    struct altcp_pcb *pcb = (struct altcp_pcb *)session->pcb;

    (void)timer;

    session->timer_session_timeout_onfly = 0;

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_SESSION_TIMEOUT);

    http_close_session(session, pcb, 1);

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_LOCAL);
    GENERATOR_STATS_PAIR_STOP_INC(GENERATOR_STATS_TIMER_SESSION_TIMEOUT);
}

static int protocol_http_client_connecned(SESSION *session, STREAM *stream, void *pcb)
{
    session->proto_state = HTTP_STATE_REQ;
    http_session_msg_next(session, stream);
    session->response_ok = 0;

    llhttp_init(&session->http_parser, HTTP_RESPONSE, &llhttp_settings_response);
    session->http_parser.data = session;

    dkfw_start_timer(&g_generator_timer_bases[LWIP_MY_CPUID], &session->timer_session_timeout, timer_func_session_timeout, session, *g_elapsed_ms + stream->session_timeout_ms);
    session->timer_session_timeout_onfly = 1;
    GENERATOR_STATS_PAIR_START_INC(GENERATOR_STATS_TIMER_SESSION_TIMEOUT);

    if(stream->ipr){
        dkfw_start_timer(&g_generator_timer_bases[LWIP_MY_CPUID], &session->timer_msg_interval, timer_func_http_client_msg, session, *g_elapsed_ms + stream->ipr * 1000);
        session->timer_msg_interval_onfly = 1;
        GENERATOR_STATS_PAIR_START_INC(GENERATOR_STATS_TIMER_MSG_INTERVAL);
    }

    return http_client_send_data(session, stream, pcb);
}

static int protocol_http_client_sent(SESSION *session, STREAM *stream, void *pcb, uint16_t sent_len)
{
    (void)sent_len;

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
    (void)stream;
    (void)pcb;

    if(session->proto_state != HTTP_STATE_RSP){
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_PROTOCOL_DATA_EARLY);
        return -1;
    }

    if(HPE_OK != llhttp_execute(&session->http_parser, data, datalen)){
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_PROTOCOL_HTTP_PARSE_FAIL);
        return -1;
    }

    if(session->response_ok){
        if(!session->timer_msg_interval_onfly){
            if(http_client_next_msg_check(session, stream, pcb) < 0){
                return -1;
            }
        }
    }

    return 0;
}

static int protocol_http_client_err(SESSION *session, STREAM *stream)
{
    (void)stream;

    http_close_session(session, NULL, 0);
    return 0;
}

static int protocol_http_client_session_new(SESSION *session, STREAM *stream, void *pcb)
{
    (void)pcb;

    session->msgs_left = stream->rpc;

    return 0;
}

static int protocol_http_server_sent(SESSION *session, STREAM *stream, void *pcb, uint16_t sent_len)
{
    (void)stream;
    (void)pcb;
    (void)sent_len;

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
    (void)stream;
    (void)pcb;

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
    (void)stream;

    http_close_session(session, NULL, 0);
    return 0;
}

static int protocol_http_server_session_new(SESSION *session, STREAM *stream, void *pcb)
{
    (void)stream;
    (void)pcb;

    llhttp_init(&session->http_parser, HTTP_REQUEST, &llhttp_settings_request);
    session->http_parser.data = session;
    session->proto_state = HTTP_STATE_REQ;

    return 0;
}

int init_stream_http_client(cJSON *json_root, STREAM *stream)
{
    int i;
    uint64_t value;
    int a, b;
    cJSON *json;
    DKFW_CPS *cpsinfo;

    stream->local_address_ind = cJSON_GetObjectItem(json_root, "local_address_ind")->valueint;
    stream->remote_address_ind = cJSON_GetObjectItem(json_root, "remote_address_ind")->valueint;
    stream->http_message_ind = cJSON_GetObjectItem(json_root, "http_message_ind")->valueint;

    a = !!local_address_pool_is_ipv6(stream->local_address_ind);
    b = !!remote_address_pool_is_ipv6(stream->remote_address_ind);
    if(a ^ b){
        printf("stream local/remote ip version not match.\n");
        return -1;
    }
    stream->stream_is_ipv6 = a;

    json = cJSON_GetObjectItem(json_root, "cps");
    if(json){
        stream->cps = json->valueint;
    }
    stream->cps = stream->cps ? stream->cps : 1;

    json = cJSON_GetObjectItem(json_root, "rpc");
    if(json){
        stream->rpc = json->valueint;
    }
    stream->rpc = stream->rpc ? stream->rpc : 1;

    json = cJSON_GetObjectItem(json_root, "ipr");
    if(json){
        stream->ipr = json->valueint;
    }

    json = cJSON_GetObjectItem(json_root, "session_timeout");
    if(json){
        stream->session_timeout_ms = json->valueint * 1000;
    }else{
        stream->session_timeout_ms = (stream->rpc * stream->ipr + 3) * 1000;
    }

    json = cJSON_GetObjectItem(json_root, "close_with_rst");
    if(json){
        stream->close_with_rst = json->valueint;
    }

    for(i=0;i<g_lwip_core_cnt;i++){
        value = stream->cps / g_lwip_core_cnt;
        if(i < (int)(stream->cps % g_lwip_core_cnt)){
            value++;
        }
        cpsinfo = &stream->dkfw_cps[i];
        dkfw_cps_create(cpsinfo, value, tsc_per_sec);
        cpsinfo->cps_segs[0].cps_end = value;
        cpsinfo->cps_segs[0].seg_total_ms = 30000;
        cpsinfo->cps_segs[1].cps_start = value;
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
    struct in6_addr start6;
    uint32_t start;

    stream->http_message_ind = cJSON_GetObjectItem(json_root, "http_message_ind")->valueint;
    strcpy(stream->listen_ip, cJSON_GetObjectItem(json_root, "listen_ip")->valuestring);
    stream->listen_port = cJSON_GetObjectItem(json_root, "listen_port")->valueint;

    if(!str_to_ipv4(stream->listen_ip, &start)){
        stream->listen_net_if = lwip_get_netif_from_ipv4(rte_bswap32(start));
        if(!stream->listen_net_if){
            printf("stream listen ip %s not found.\n", stream->listen_ip);
            return -1;
        }
    }else if(!str_to_ipv6(stream->listen_ip, &start6)){
        stream->stream_is_ipv6 = 1;
        stream->listen_net_if = lwip_get_netif_from_ipv6((u8_t *)start6.s6_addr32);
        if(!stream->listen_net_if){
            printf("stream listen ip %s not found.\n", stream->listen_ip);
            return -1;
        }
    }else{
        printf("invalid listen ipaddr.\n");
        return -1;
    }

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

