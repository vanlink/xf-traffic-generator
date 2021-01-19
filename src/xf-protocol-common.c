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

// err always OK
static inline err_t cb_connected(void *arg, struct altcp_pcb *tpcb, err_t err)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;

    if(stream->connected){
        return stream->connected(session, stream);
    }

    return ERR_OK;
}

static err_t cb_sent(void *arg, struct altcp_pcb *tpcb, u16_t len)
{
    SESSION *session = (SESSION *)arg;
    STREAM *stream = session->stream;

    if(stream->sent){
        return stream->sent(session, stream, len);
    }

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

    if(stream->is_tls){
        newpcb = altcp_tls_alloc(NULL, IPADDR_TYPE_V4);
    }else{
        newpcb = altcp_new(NULL);
    }
    
    if(!newpcb){
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
    // altcp_recv(newpcb, cb_httpclient_recv);
    altcp_poll(newpcb, NULL, 2U);
    // altcp_err(newpcb, cb_httpclient_err);

    if(stream->session_new){
        stream->session_new(session, stream);
    }

    remote_addr = remote_address_get(stream->remote_address_ind, core, &port);

    force_next = 0;
    for(i=0;i<2;i++){
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
    }

    ret = -1;

exit:

    if(newpcb){
        altcp_abort(newpcb);
    }

    return ret;
}

int protocol_common_send(STREAM *stream, int core, uint64_t tsc)
{
    uint64_t send_cnt = dkfw_cps_get(&stream->dkfw_cps[core], tsc);

    if(!send_cnt){
        return 0;
    }

    return protocol_common_send_one(stream, core);
}

