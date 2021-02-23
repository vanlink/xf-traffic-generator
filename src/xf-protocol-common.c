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
#include "xf-address.h"
#include "xf-generator.h"
#include "xf-simuser.h"

// err always OK
static inline err_t cb_connected(void *arg, struct altcp_pcb *tpcb, err_t err)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;

    (void)err;

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_SUCC);

    if(unlikely(stream->stream_connected(session, stream, tpcb) < 0)){
        return ERR_ABRT;
    }

    return ERR_OK;
}

static err_t cb_sent(void *arg, struct altcp_pcb *tpcb, u16_t len)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;

    if(unlikely(stream->stream_sent(session, stream, tpcb, len) < 0)){
        return ERR_ABRT;
    }

    return ERR_OK;
}

// we will never refuse data
static err_t cb_recv(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;
    struct pbuf *pcurr;
    err_t ret = ERR_OK;

    (void)err;

    if(unlikely(!p)){
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_REMOTE_FIN);
        if(stream->stream_remote_close(session, stream, tpcb) < 0){
            return ERR_ABRT;
        }
        return ERR_OK;
    }

    pcurr = p;
    while(pcurr){
        altcp_recved(tpcb, pcurr->len);
        if(unlikely(stream->stream_recv(session, stream, tpcb, pcurr->payload, pcurr->len) < 0)){
            ret = ERR_ABRT;
            goto exit;
        }
        pcurr = pcurr->next;
    }

exit:

    pbuf_free(p);

    return ret;
}

static void cb_err(void *arg, err_t err)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;

    if(err == ERR_ABRT){
        // user called tcp_abandon
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_ERROR);
    }else if(err == ERR_TIMEOUT){
        // timer timeout
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_TIMEOUT);
    }else if(err == ERR_RST){
        // reset by remote
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_REMOTE_RST);
    }else if(err == ERR_CLSD){
        // see tcp_input_delayed_close
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_ERROR);
    }else{
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_ERROR);
    }

    stream->stream_err(session, stream);
}

static err_t cb_accept(void *arg, struct altcp_pcb *pcb, err_t err)
{
    STREAM *stream = (STREAM *)arg;
    SESSION *session;

    (void)err;

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_ATTEMP);

    if(unlikely(!pcb)){
        // no memory
        return ERR_ABRT;
    }

    session = session_get();
    if(unlikely(!session)){
        altcp_abort(pcb);
        return ERR_ABRT;
    }

    session->pcb = pcb;
    session->stream = stream;

    altcp_arg(pcb, session);
    altcp_sent(pcb, cb_sent);
    altcp_recv(pcb, cb_recv);
    altcp_poll(pcb, NULL, 10U);
    altcp_err(pcb, cb_err);

    stream->stream_session_new(session, stream, pcb);

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_SUCC);

    return ERR_OK;
}

int protocol_common_send_one(STREAM *stream, int core, uint32_t simuser_ind)
{
    SESSION *session = session_get();
    struct altcp_pcb *newpcb = NULL;
    ip_addr_t *remote_addr;
    err_t err;
    struct tcp_pcb *pcb;
    int ret = 0;
    struct netif *net_if;
    int port;
    int i, force_next;

    if(unlikely(!session)){
        ret = -1;
        goto exit;
    }

    if(unlikely(stream->stream_is_tls)){
        newpcb = altcp_tls_alloc(stream->tls_client_config, stream->stream_is_ipv6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
    }else{
        newpcb = altcp_new(NULL);
    }
    
    if(unlikely(!newpcb)){
        ret = -1;
        goto exit;
    }

    session->pcb = newpcb;
    session->stream = stream;
    session->simuser_ind = simuser_ind;

    if(unlikely(stream->stream_is_tls)){
        pcb = newpcb->inner_conn ? ((struct altcp_pcb *)newpcb->inner_conn)->state : NULL;
    }else{
        pcb = (struct tcp_pcb *)newpcb->state;
    }

    altcp_arg(newpcb, session);
    altcp_sent(newpcb, cb_sent);
    altcp_recv(newpcb, cb_recv);
    altcp_poll(newpcb, NULL, 10U);
    altcp_err(newpcb, cb_err);

    stream->stream_session_new(session, stream, newpcb);

    remote_addr = remote_address_get(stream->remote_address_ind, core, &port);

    force_next = 0;
    for(i=0;i<stream->local_address_in_pool_cnt;i++){
        net_if = local_address_get(stream->local_address_ind, core, force_next);
        tcp_bind_netif(pcb, net_if);
        err = altcp_connect(newpcb, remote_addr, port, cb_connected);
        if (likely(err == ERR_OK)) {
            return ret;
        }
        if (err != ERR_USE) {
            break;
        }
        force_next = 1;
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_LOCAL_PORT_NEXT);
    }
    GENERATOR_STATS_NUM_INC(GENERATOR_STATS_LOCAL_PORT_EMPTY);

    ret = -1;

exit:

    if(newpcb){
        altcp_sent(newpcb, NULL);
        altcp_recv(newpcb, NULL);
        altcp_err(newpcb, NULL);

        altcp_abort(newpcb);
    }

    if(session){
        session_free(session);
    }

    return ret;
}

int protocol_common_send_cps(STREAM *stream, int core, uint64_t tsc, uint64_t ms)
{
    uint64_t i;
    uint64_t send_cnt = dkfw_cps_limited_get(&stream->stream_cores[core].stream_cps, tsc, ms);

    for(i=0;i<send_cnt;i++){
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_ATTEMP);
        protocol_common_send_one(stream, core, 0);
    }

    return send_cnt;
}

int protocol_common_send_simuser(STREAM *stream, int core, uint64_t tsc, uint64_t ms)
{
    int i;
    int simusers_dst = (int)dkfw_cps_abs_value_get(&stream->stream_cores[core].stream_cps, ms);
    int simusers_curr = stream->stream_cores[core].simuser_active_cnt;
    int simusers_all = 0;
    SIMUSER *simusers;

    (void)tsc;

    if(likely(simusers_dst == simusers_curr)){
        return 0;
    }

    simusers = stream->stream_cores[core].simusers;

    if(simusers_dst < simusers_curr){
        for(i=simusers_dst;i<simusers_curr;i++){
            simuser_stop(&simusers[i]);
        }
    }else{
        simusers_all = stream->stream_cores[core].simuser_all_cnt;
        simusers_dst = (simusers_dst < simusers_all) ? simusers_dst : simusers_all;
        for(i=simusers_curr;i<simusers_dst;i++){
            if(simusers[i].simusr_state != SIMUSR_ST_DISABLED){
                continue;
            }
            simuser_start(stream, &simusers[i], core);
        }
    }

    stream->stream_cores[core].simuser_active_cnt = simusers_dst;

    return 1;
}

int protocol_common_listen(STREAM *stream)
{
    struct tcp_pcb *pcb;
    struct altcp_pcb *listenpcb;
    struct altcp_pcb *listenpcbnew;
    struct netif *net_if = stream->listen_net_if;
    err_t ret;

    if(stream->stream_is_tls){
        listenpcb = altcp_tls_alloc(stream->tls_server_config, stream->stream_is_ipv6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
    }else{
        listenpcb = altcp_new(NULL);
    }
    if(!listenpcb){
        return -1;
    }

    if(stream->stream_is_tls){
        pcb = listenpcb->inner_conn ? ((struct altcp_pcb *)listenpcb->inner_conn)->state : NULL;
    }else{
        pcb = (struct tcp_pcb *)listenpcb->state;
    }
    if(pcb){
        tcp_bind_netif(pcb, net_if);
    }
    if(stream->stream_is_ipv6){
        ret = altcp_bind(listenpcb, netif_ip_addr6(net_if, 0), stream->listen_port);
    }else{
        ret = altcp_bind(listenpcb, &net_if->ip_addr, stream->listen_port);
    }
    if(ret != ERR_OK){
        printf("protocol listen bind pcb err.\n");
        return -1;
    }
    altcp_arg(listenpcb, stream);
    listenpcbnew = altcp_listen(listenpcb);
    if(!listenpcbnew){
        printf("protocol listen new pcb err.\n");
        return -1;
    }
    altcp_arg(listenpcbnew, stream);
    altcp_accept(listenpcbnew, cb_accept);

    printf("protocol listen [%s:%d] ok\n", stream->listen_ip, stream->listen_port);

    return 0;
}

