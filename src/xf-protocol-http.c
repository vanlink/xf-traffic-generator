#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_launch.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
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
#include "xf-simuser.h"

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
            if(stream->stream_is_simuser){
                simuser_delayed_attemp(&stream->stream_cores[LWIP_MY_CPUID].simusers[session->simuser_ind], LWIP_MY_CPUID);
            }
            return -1;
        }
    }else{
        if(stream->stream_is_simuser){
            simuser_attemp(stream, &stream->stream_cores[LWIP_MY_CPUID].simusers[session->simuser_ind], LWIP_MY_CPUID);
        }
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

    if(stream->stream_is_simuser){
        simuser_delayed_attemp(&stream->stream_cores[LWIP_MY_CPUID].simusers[session->simuser_ind], LWIP_MY_CPUID);
    }

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
    if(stream->stream_is_simuser){
        simuser_delayed_attemp(&stream->stream_cores[LWIP_MY_CPUID].simusers[session->simuser_ind], LWIP_MY_CPUID);
    }

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
    if(stream->stream_is_simuser){
        simuser_delayed_attemp(&stream->stream_cores[LWIP_MY_CPUID].simusers[session->simuser_ind], LWIP_MY_CPUID);
    }

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

static void init_stream_cps_one_core(STREAM *stream, int is_simuser, int core_ind, uint64_t value)
{
    int j;
    STREAM_CORE *core = &stream->stream_cores[core_ind];
    DKFW_CPS *cpsinfo = &core->stream_cps;

    dkfw_cps_create(cpsinfo, tsc_per_sec);

    cpsinfo->cps_segs[0].cps_end = value;
    cpsinfo->cps_segs[0].seg_total_ms = 30000;
    cpsinfo->cps_segs[1].cps_start = value;

    if(is_simuser && value){
        core->simuser_all_cnt = value;
        core->simusers = rte_zmalloc(NULL, sizeof(SIMUSER) * value, 0);
        for(j=0;j<(int)value;j++){
            core->simusers[j].simusr_ind = j;
            core->simusers[j].simusr_state = SIMUSR_ST_DISABLED;
            core->simusers[j].simusr_stream = stream;
        }
    }
}

static uint64_t get_per_core_value(uint64_t value_all, int core_ind)
{
    uint64_t value = value_all / g_lwip_core_cnt;

    if(core_ind < (int)(value_all % g_lwip_core_cnt)){
        value++;
    }

    return value;
}

static int init_stream_cps_array(cJSON *json_root, STREAM *stream, int is_simuser)
{
    int i, j;
    uint64_t value;
    cJSON *json_seg, *json;
    uint64_t max_cps = 0;
    uint64_t start, end, time_ms;
    uint64_t start_percore, end_percore;
    STREAM_CORE *core;
    DKFW_CPS *cpsinfo;
    DKFW_CPS_SEG *seg;
    int cnt = 0;

    for(i=0;i<g_lwip_core_cnt;i++){
        core = &stream->stream_cores[i];
        cpsinfo = &core->stream_cps;

        dkfw_cps_create(cpsinfo, tsc_per_sec);
    }

    cJSON_ArrayForEach(json_seg, json_root){

        if(cnt >= DKFW_CPS_SEGS_MAX){
            printf("too many cps segs.\n");
            return -1;
        }

        json = cJSON_GetObjectItem(json_seg, "start");
        if(!json){
            printf("start value req.\n");
            return -1;
        }
        start = json->valueint;

        json = cJSON_GetObjectItem(json_seg, "end");
        if(json){
            end = json->valueint;
        }else{
            end = start;
        }

        json = cJSON_GetObjectItem(json_seg, "time");
        if(json){
            time_ms = json->valueint * 1000;
        }else{
            time_ms = 0;
        }

        if(max_cps < start){
            max_cps = start;
        }
        if(max_cps < end){
            max_cps = end;
        }

        for(i=0;i<g_lwip_core_cnt;i++){
            core = &stream->stream_cores[i];
            cpsinfo = &core->stream_cps;
            seg = &cpsinfo->cps_segs[cpsinfo->cps_segs_cnt];

            start_percore = get_per_core_value(start, i);
            end_percore = get_per_core_value(end, i);

            seg->cps_start = start_percore;
            seg->cps_end = end_percore;
            seg->seg_total_ms = time_ms;

            cpsinfo->cps_segs_cnt++;
        }

        cnt++;
    }

    if(!is_simuser){
        return 0;
    }

    for(i=0;i<g_lwip_core_cnt;i++){
        value = get_per_core_value(max_cps, i);
        if(!value){
            continue;
        }
        core = &stream->stream_cores[i];
        core->simuser_all_cnt = value;
        core->simusers = rte_zmalloc(NULL, sizeof(SIMUSER) * value, 0);
        for(j=0;j<(int)value;j++){
            core->simusers[j].simusr_ind = j;
            core->simusers[j].simusr_state = SIMUSR_ST_DISABLED;
            core->simusers[j].simusr_stream = stream;
        }
    }

    return 0;
}

static int init_stream_cps(cJSON *json, STREAM *stream, int is_simuser)
{
    int i;
    uint64_t value, cps;

    if(json->type == cJSON_Number){
        cps = json->valueint;
        cps = cps ? cps : 1;
        for(i=0;i<g_lwip_core_cnt;i++){
            value = get_per_core_value(cps, i);
            init_stream_cps_one_core(stream, is_simuser, i, value);
        }
    }else if(json->type == cJSON_Array){
        if(init_stream_cps_array(json, stream, is_simuser) < 0){
            return -1;
        }
    }else{
        printf("cps/simuser invalid.\n");
        return -1;
    }

    return 0;
}

int init_stream_http_client(cJSON *json_root, STREAM *stream)
{
    int a, b;
    cJSON *json;
    int is_simuser = 0;

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

    stream->local_address_in_pool_cnt = local_address_num_in_pool_cnt(stream->local_address_ind);
    if(!stream->local_address_in_pool_cnt){
        printf("no addresses in local pool.\n");
        return -1;
    }
    printf("local address pool [%d] addresses [%d].\n", stream->local_address_ind, stream->local_address_in_pool_cnt);

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

    json = cJSON_GetObjectItem(json_root, "cps");
    if(!json){
        json = cJSON_GetObjectItem(json_root, "simuser");
        if(json){
            is_simuser = 1;
        }else{
            printf("cps/simuser required.\n");
            return -1;
        }
    }
    stream->stream_is_simuser = is_simuser;
    if(init_stream_cps(json, stream, is_simuser) < 0){
        return -1;
    }

    if(is_simuser){
        stream->stream_send = protocol_common_send_simuser;
    }else{
        stream->stream_send = protocol_common_send_cps;
    }
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

