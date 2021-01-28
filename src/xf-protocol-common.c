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

// err always OK
static inline err_t cb_connected(void *arg, struct altcp_pcb *tpcb, err_t err)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;

    (void)err;

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_SUCC);

    if(stream->stream_connected){
        if(stream->stream_connected(session, stream, tpcb) < 0){
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

static err_t cb_sent(void *arg, struct altcp_pcb *tpcb, u16_t len)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;

    if(stream->stream_sent){
        if(stream->stream_sent(session, stream, tpcb, len) < 0){
            return ERR_ABRT;
        }
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

    if(!p){
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CLOSE_REMOTE_FIN);
        if(stream->stream_remote_close){
            if(stream->stream_remote_close(session, stream, tpcb) < 0){
                return ERR_ABRT;
            }
        }
        return ERR_OK;
    }

    if(stream->stream_recv){
        pcurr = p;
        while(pcurr){
            altcp_recved(tpcb, pcurr->len);
            if(stream->stream_recv(session, stream, tpcb, pcurr->payload, pcurr->len) < 0){
                ret = ERR_ABRT;
                goto exit;
            }
            pcurr = pcurr->next;
        }
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

    if(stream->stream_err){
        stream->stream_err(session, stream);
    }
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
    if(!session){
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

    if(stream->stream_session_new){
        stream->stream_session_new(session, stream, pcb);
    }

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_SUCC);

    return ERR_OK;
}

static int protocol_common_send_one(STREAM *stream, int core)
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

    if(stream->is_tls){
        newpcb = altcp_tls_alloc(NULL, IPADDR_TYPE_V4);
    }else{
        newpcb = altcp_new(NULL);
    }
    
    if(unlikely(!newpcb)){
        ret = -1;
        goto exit;
    }

    session->pcb = newpcb;
    session->stream = stream;

    if(stream->is_tls){
        pcb = newpcb->inner_conn ? ((struct altcp_pcb *)newpcb->inner_conn)->state : NULL;
    }else{
        pcb = (struct tcp_pcb *)newpcb->state;
    }

    altcp_arg(newpcb, session);
    altcp_sent(newpcb, cb_sent);
    altcp_recv(newpcb, cb_recv);
    altcp_poll(newpcb, NULL, 10U);
    altcp_err(newpcb, cb_err);

    if(stream->stream_session_new){
        stream->stream_session_new(session, stream, newpcb);
    }

    remote_addr = remote_address_get(stream->remote_address_ind, core, &port);

    force_next = 0;
    for(i=0;i<8;i++){
        net_if = local_address_get(stream->local_address_ind, core, force_next);
        tcp_bind_netif(pcb, net_if);
        err = altcp_connect(newpcb, remote_addr, port, cb_connected);
        if (err == ERR_OK) {
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

static uint64_t remain_cnt[MAX_CORES_PER_ROLE] = {0};

static inline uint64_t get_real_send_cnt(int seq, uint64_t cnt)
{
    if(likely(cnt == 0)){
        if(unlikely(remain_cnt[seq])){
            remain_cnt[seq]--;
            return 1;
        }
        return 0;
    }

    if(likely(cnt == 1)){
        return 1;
    }

    remain_cnt[seq] += (cnt - 1);

    if(remain_cnt[seq] > 64){
        remain_cnt[seq] = 64;
    }

    return 1;
}

int protocol_common_send(STREAM *stream, int core, uint64_t tsc)
{
    int real_cnt, i;
    uint64_t send_cnt = dkfw_cps_get(&stream->dkfw_cps[core], tsc);

    real_cnt = get_real_send_cnt(core, send_cnt);

    for(i=0;i<real_cnt;i++){
        STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_ATTEMP);
        protocol_common_send_one(stream, core);
    }

    return real_cnt;
}

int protocol_common_listen(STREAM *stream)
{
    struct tcp_pcb *pcb;
    struct altcp_pcb *listenpcb;
    struct altcp_pcb *listenpcbnew;
    struct netif *net_if = stream->listen_net_if;
    err_t ret;

    if(stream->is_tls){
        listenpcb = altcp_tls_alloc(NULL, IPADDR_TYPE_V4);
    }else{
        listenpcb = altcp_new(NULL);
    }
    if(!listenpcb){
        return -1;
    }

    if(stream->is_tls){
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

