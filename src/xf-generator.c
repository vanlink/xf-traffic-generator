#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_launch.h>
#include <rte_memory.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_bitmap.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_net.h>
#include <rte_memcpy.h>
#include <rte_flow.h>

#include "cjson/cJSON.h"

#include "dkfw_intf.h"
#include "dkfw_core.h"
#include "dkfw_profile.h"
#include "dkfw_ipc.h"
#include "dkfw_timer.h"
#include "dkfw_memory.h"
#include "dpdkframework.h"

#include "lwip/arch.h"
#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/tcp.h"
#include "lwip/icmp6.h"
#include "lwip/memp.h"

#include "xf-generator.h"
#include "xf-sharedmem.h"
#include "xf-session.h"
#include "xf-network.h"
#include "xf-address.h"
#include "xf-certificate.h"
#include "xf-protocol-http-msg.h"
#include "xf-stream.h"
#include "xf-capture.h"
#include "xf-protocol-common.h"
#include "xf-protocol-http.h"

typedef struct _DPDK_MBUF_PRIV_TAG {
    struct netif *pnetif;
    uint32_t mbuf_hash;
} MBUF_PRIV_T;

#define MAX_ETH_RCV_PKTS 32
#define MAX_Q_RCV_PKTS 16

RTE_DEFINE_PER_LCORE(DKFW_PROFILE *, g_profiler);

char unique_id[64] = {0};
static char conf_file_path[128] = {0};

static DKFW_CONFIG dkfw_config;

uint64_t tsc_per_sec;
uint64_t g_elapsed_ms;

DKFW_STATS *g_generator_stats = NULL;
DKFW_STATS *g_dispatch_stats = NULL;

static struct rte_mempool *pktmbuf_arp_clone = NULL;

static const char short_options[] = "u:c:";
static const struct option long_options[] = {
    {"unique", required_argument, NULL, 'u'},
    {"conf", required_argument, NULL, 'c'},

    { 0, 0, 0, 0},
};

SHARED_MEM_T *g_generator_shared_mem = NULL;

tvec_base_t *g_generator_timer_bases;

static int cmd_do_exit = 0;

static int cmd_parse_args(int argc, char **argv)
{
    int opt;
    char **argvopt;
    int option_index;

    argvopt = argv;
    while((opt = getopt_long(argc, argvopt, short_options, long_options, &option_index)) != EOF) {
        switch(opt){
            case 'u':
                strcpy(unique_id, optarg);
                break;
            case 'c':
                strcpy(conf_file_path, optarg);
                break;
            default:
                break;
        }
    }

    if(!unique_id[0] || !conf_file_path[0]){
        return -1;
    }

    return 0;
}

u32_t sys_now(void){
    return g_elapsed_ms;
}

static int init_pktmbuf_pool(void)
{
    pktmbuf_arp_clone = rte_pktmbuf_pool_create("mbufarpcolne", 8191, 128, RTE_MBUF_PRIV_ALIGN * 4, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    if(!pktmbuf_arp_clone){
        printf("mbuf pktmbuf_arp_clone err.\n");
        return -1;
    }

    return 0;
}

static int init_lwip_json(cJSON *json_root, void *stats_mem)
{
    int i;
    LWIP_CONFIG_T conf;
    cJSON *json_item;
    cJSON *json_item_1;

    memset(&conf, 0, sizeof(conf));

    conf.lwip_core_cnt = g_pkt_process_core_num;

    conf.mempool_static_obj_cnt[MEMP_ALTCP_PCB] = 4096;
    conf.mempool_static_obj_cnt[MEMP_TCP_PCB_LISTEN] = 4096;
    conf.mempool_static_obj_cnt[MEMP_TCP_PCB] = 4096;
    conf.mempool_static_obj_cnt[MEMP_TCP_SEG] = 8192;
    conf.mempool_static_obj_cnt[MEMP_ARP_QUEUE] = 4096;
    conf.mempool_static_obj_cnt[MEMP_ND6_QUEUE] = 4096;
    conf.mempool_static_obj_cnt[MEMP_PBUF_POOL] = 8192;
    conf.mempool_static_obj_cnt[MEMP_PBUF] = 8192;
    conf.mempool_static_obj_cnt[MEMP_SYS_TIMEOUT] = 2048;

    json_item = cJSON_GetObjectItem(json_root, "mem_static_pools");
    if(json_item){
        if((json_item_1 = cJSON_GetObjectItem(json_item, "pcb-altcp"))){
            conf.mempool_static_obj_cnt[MEMP_ALTCP_PCB] = json_item_1->valueint;
        }
        if((json_item_1 = cJSON_GetObjectItem(json_item, "pcb-tcp-listen"))){
            conf.mempool_static_obj_cnt[MEMP_TCP_PCB_LISTEN] = json_item_1->valueint;
        }
        if((json_item_1 = cJSON_GetObjectItem(json_item, "pcb-tcp"))){
            conf.mempool_static_obj_cnt[MEMP_TCP_PCB] = json_item_1->valueint;
        }
        if((json_item_1 = cJSON_GetObjectItem(json_item, "tcp-seg"))){
            conf.mempool_static_obj_cnt[MEMP_TCP_SEG] = json_item_1->valueint;
        }
        if((json_item_1 = cJSON_GetObjectItem(json_item, "arp-q"))){
            conf.mempool_static_obj_cnt[MEMP_ARP_QUEUE] = json_item_1->valueint;
        }
        if((json_item_1 = cJSON_GetObjectItem(json_item, "nd6-q"))){
            conf.mempool_static_obj_cnt[MEMP_ND6_QUEUE] = json_item_1->valueint;
        }
        if((json_item_1 = cJSON_GetObjectItem(json_item, "pbuf-pool"))){
            conf.mempool_static_obj_cnt[MEMP_PBUF_POOL] = json_item_1->valueint;
        }
        if((json_item_1 = cJSON_GetObjectItem(json_item, "pbuf"))){
            conf.mempool_static_obj_cnt[MEMP_PBUF] = json_item_1->valueint;
        }
        if((json_item_1 = cJSON_GetObjectItem(json_item, "sys-timeout"))){
            conf.mempool_static_obj_cnt[MEMP_SYS_TIMEOUT] = json_item_1->valueint;
        }
    }

    json_item = cJSON_GetObjectItem(json_root, "mem_step_pools");
    if(json_item){
        i = 0;
        cJSON_ArrayForEach(json_item_1, json_item){
            conf.mempool_steps[i].obj_size = cJSON_GetObjectItem(json_item_1, "size")->valueint;
            conf.mempool_steps[i].obj_cnt = cJSON_GetObjectItem(json_item_1, "cnt")->valueint;
            i++;
        }
    }else{
        conf.mempool_steps[0].obj_size = 2048;
        conf.mempool_steps[0].obj_cnt = 16384;
        conf.mempool_steps[1].obj_size = 4096;
        conf.mempool_steps[1].obj_cnt = 8192;
        conf.mempool_steps[2].obj_size = 8192;
        conf.mempool_steps[2].obj_cnt = 4096;
        conf.mempool_steps[3].obj_size = 16384;
        conf.mempool_steps[3].obj_cnt = 2048;
        conf.mempool_steps[4].obj_size = 32768;
        conf.mempool_steps[4].obj_cnt = 2048;
        conf.mempool_steps[5].obj_size = 65536;
        conf.mempool_steps[5].obj_cnt = 2048;
    }

    conf.stats_mem_addr = stats_mem;

    lwip_init(&conf);

    return 0;
}

static __rte_always_inline int pkt_dpdk_to_lwip_real(struct rte_mbuf *m, int seq)
{
    int dpdklen;
    char *dpdkdat;
    err_t ret = 0;
    struct pbuf *p;
    MBUF_PRIV_T *priv;

    priv = (MBUF_PRIV_T *)rte_mbuf_to_priv(m);
    dpdklen = rte_pktmbuf_pkt_len(m);
    dpdkdat = rte_pktmbuf_mtod(m, char *);

    if(unlikely(g_is_capturing)){
        capture_do_capture(seq, dpdkdat, dpdklen);
    }

    p = pbuf_alloc(PBUF_RAW, dpdklen, PBUF_POOL);
    if(!p) {
         ret = -1;
        goto exit;
    }
    p->payload = dpdkdat;
    p->pbuf_hash = priv->mbuf_hash;

#if XF_DEBUG_PROFILE
    DKFW_PROFILE_SINGLE_START(PROFILER_CORE, rte_rdtsc(), PROFILE_SINGLE_A);
#endif
    ret = priv->pnetif->input(p, priv->pnetif);
#if XF_DEBUG_PROFILE
    DKFW_PROFILE_SINGLE_END(PROFILER_CORE, rte_rdtsc(), PROFILE_SINGLE_A);
#endif

    if(ret != ERR_OK){
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_LWIP_PROCESS_FAIL);
        ret = -1;
        pbuf_free(p);
    }

exit:

    rte_pktmbuf_free(m);

    return ret;
}

static __rte_always_inline int get_app_core_seq(int seq, struct rte_mbuf *m, int *dst_core)
{
    int ret = -1;
    char *dpdkdat;
    uint16_t port_humam;
    struct rte_ether_hdr *ethhdr;
    struct rte_ipv4_hdr *ipv4;
    struct rte_ipv6_hdr *ipv6;
    struct rte_tcp_hdr *tcp;
    struct rte_arp_hdr *arp;
    struct rte_flow_item_icmp6_nd_ns *icmpv6;
    MBUF_PRIV_T *priv;
    uint32_t hash_use_ip;
    uint32_t hash_use_port;

    priv = (MBUF_PRIV_T *)rte_mbuf_to_priv(m);
    dpdkdat = rte_pktmbuf_mtod(m, char *);
    ethhdr = (struct rte_ether_hdr *)dpdkdat;

    if(likely(rte_bswap16(ethhdr->ether_type) == RTE_ETHER_TYPE_IPV4)){
        ipv4 = (struct rte_ipv4_hdr *)(dpdkdat + RTE_ETHER_HDR_LEN);
        priv->pnetif = lwip_get_netif_from_ipv4(ipv4->dst_addr);
        if(unlikely(!priv->pnetif)){
            goto exit;
        }
        if(likely(ipv4->next_proto_id == IPPROTO_TCP)){
            tcp = (struct rte_tcp_hdr *)((char *)ipv4 + ((ipv4->version_ihl & 0x0f) << 2));
            port_humam = rte_bswap16(tcp->dst_port);
            if(LWIP_NETIF_LPORT_TCP_IS_LISTEN(priv->pnetif, port_humam)){
                // dst to listen port, hash base on src port
                port_humam = rte_bswap16(tcp->src_port);
                *dst_core = seq;
                hash_use_ip = rte_bswap32(ipv4->src_addr);
                hash_use_port = port_humam;
            }else{
                // dst to client port, hash base on dst port
                *dst_core = port_humam % g_pkt_process_core_num;
                hash_use_ip = rte_bswap32(ipv4->dst_addr);
                hash_use_port = port_humam;
            }
            priv->mbuf_hash = lwip_get_hash_addrport(hash_use_ip, hash_use_port, priv->pnetif->pcb_hash_bucket_cnt);
            ret = 0;
        }else if(ipv4->next_proto_id == IPPROTO_UDP){
        }else if(ipv4->next_proto_id == IPPROTO_ICMP){
        }
    }else if(rte_bswap16(ethhdr->ether_type) == RTE_ETHER_TYPE_ARP){
        arp = (struct rte_arp_hdr *)(dpdkdat + RTE_ETHER_HDR_LEN);
        priv->pnetif = lwip_get_netif_from_ipv4(arp->arp_data.arp_tip);
        if(priv->pnetif){
            if(arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)){
                *dst_core = 0;
                ret = 0;
            }else if(arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)){
                *dst_core = -1;
                ret = 0;
            }
        }else if(arp->arp_data.arp_sip == arp->arp_data.arp_tip){
            priv->pnetif = lwip_get_netif_first_ipv4();
            if(priv->pnetif){
                *dst_core = -1;
                ret = 0;
            }
        }
    }else if(rte_bswap16(ethhdr->ether_type) == RTE_ETHER_TYPE_IPV6){
        ipv6 = (struct rte_ipv6_hdr *)(dpdkdat + RTE_ETHER_HDR_LEN);
        if(ipv6->proto == IPPROTO_TCP){
            tcp = (struct rte_tcp_hdr *)((char *)ipv6 + sizeof(struct rte_ipv6_hdr));
        }else if(ipv6->proto == IPPROTO_UDP){
        }else if(ipv6->proto == IPPROTO_ICMPV6){
            (void)icmpv6;
        }
    }

exit:

    return ret;
}

static void dispatch_second_timer(int seq, uint64_t seconds)
{
    (void)seq;
    (void)seconds;
}

static int dispatch_loop(int seq)
{
    uint64_t time_0, elapsed_second_last = 0;
    int i, cind;
    struct rte_mbuf *pkts_burst[64];
    struct rte_mbuf *pkt, *clone;
    int rx_num, pktind;
    int dst_core = 0;
    MBUF_PRIV_T *priv_src;
    MBUF_PRIV_T *priv_dst;
    int busy;

    PROFILER_CORE = &g_generator_shared_mem->profile_dispatch[seq];

    printf("dispatch loop seq=%d tsc_per_sec=%lu\n", seq, tsc_per_sec);

    while(1){

        time_0 = rte_rdtsc();

        busy = 0;

        DKFW_PROFILE_START(PROFILER_CORE, time_0);

        DKFW_PROFILE_ITEM_START(PROFILER_CORE, time_0, PROFILE_ITEM_TIMER);
        if(g_elapsed_ms - elapsed_second_last >= 1000){

            busy = 1;

            dispatch_second_timer(seq, g_elapsed_ms / 1000);

            elapsed_second_last = g_elapsed_ms;
        }
        time_0 = rte_rdtsc();
        if(busy){
            DKFW_PROFILE_ITEM_END(PROFILER_CORE, time_0, PROFILE_ITEM_TIMER);
        }

        busy = 0;

        DKFW_PROFILE_ITEM_START(PROFILER_CORE, time_0, PROFILE_ITEM_RECV_INTF);

        for(i=0;i<g_dkfw_interfaces_num;i++){
            rx_num = dkfw_rcv_pkt_from_interface(i, seq, pkts_burst, MAX_ETH_RCV_PKTS);
            if(rx_num){

                busy = 1;

                for(pktind=0;pktind<rx_num;pktind++){
                    pkt = pkts_burst[pktind];

                    if(get_app_core_seq(-1, pkt, &dst_core) < 0){
                        DISPATCH_STATS_NUM_INC(DISPATCH_STATS_UNKNOWN_CORE, seq);
                        rte_pktmbuf_free(pkt);
                    }else{
                        if(likely(dst_core >= 0)){
                            if(unlikely(dkfw_send_pkt_to_process_core_q(dst_core, seq, pkt) < 0)){
                                rte_pktmbuf_free(pkt);
                            }
                        }else{
                            priv_src = (MBUF_PRIV_T *)rte_mbuf_to_priv(pkt);
                            for(cind=0;cind<g_pkt_process_core_num;cind++){
                                clone = rte_pktmbuf_clone(pkt, pktmbuf_arp_clone);
                                if (!clone){
                                    DISPATCH_STATS_NUM_INC(DISPATCH_STATS_CLONE_MBUF_EMPTY, seq);
                                    continue;
                                }
                                priv_dst = (MBUF_PRIV_T *)rte_mbuf_to_priv(clone);
                                rte_memcpy(priv_dst, priv_src, sizeof(MBUF_PRIV_T));
                                if(unlikely(dkfw_send_pkt_to_process_core_q(cind, seq, clone) < 0)){
                                    rte_pktmbuf_free(clone);
                                }
                            }
                            rte_pktmbuf_free(pkt);
                        }
                    }
                }
            }
        }

        time_0 = rte_rdtsc();

        if(busy){
            DKFW_PROFILE_ITEM_END(PROFILER_CORE, time_0, PROFILE_ITEM_RECV_INTF);
        }
        
        DKFW_PROFILE_END(PROFILER_CORE, time_0);

        if(unlikely(cmd_do_exit)){
            break;
        }
    }

    return 0;
}

static inline void packet_second_timer(int seq, uint64_t seconds)
{
    (void)seconds;

    if(seq == 0){
        if(g_generator_shared_mem->cmd_exit){
            printf("rcv cmd [exit]\n");
            fflush(stdout);
            g_generator_shared_mem->cmd_exit = 0;
            cmd_do_exit = g_generator_shared_mem->cmd_exit;
        }else if(g_generator_shared_mem->cmd_stop){
            printf("rcv cmd [stop]\n");
            fflush(stdout);
            g_generator_shared_mem->cmd_stop = 0;
            streams_stop();
        }else if(g_generator_shared_mem->cmd_start){
            printf("rcv cmd [start]\n");
            fflush(stdout);
            g_generator_shared_mem->cmd_start = 0;
            streams_start();
        }
    }
}

#define US_PER_S 1000000
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

static int packet_loop(int seq)
{
    int i, send_cnt, cind;
    uint64_t elapsed_ms_last = 0;
    uint64_t elapsed_second_last = 0;
    uint64_t time_0;
    struct rte_mbuf *pkts_burst[64];
    struct rte_mbuf *pkt;
    int rx_num, pktind;
    STREAM *stream;
    int busy;
    int dst_core = 0;
    struct rte_mbuf *clone;
    MBUF_PRIV_T *priv_src;
    MBUF_PRIV_T *priv_dst;
#if USE_TX_BUFFER
    uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    uint64_t diff_tsc, prev_tsc = 0;
#endif

    PROFILER_CORE = &g_generator_shared_mem->profile_pkt[seq];

    printf("packet loop seq=%d tsc_per_sec=%lu\n", seq, tsc_per_sec);

    time_0 = rte_rdtsc();

    g_elapsed_ms = time_0 * 1000ULL / tsc_per_sec;

    lwip_init_per_core(seq, PROFILER_CORE);

    for(i=0;i<g_stream_cnt;i++){
        stream = g_streams[i];
        if(stream->stream_listen){
            if(stream->stream_listen(stream) < 0){
                rte_exit(EXIT_FAILURE, "stream_listen fail.\n");
            }
        }
    }

    printf("===== xf-generator ok =====\n");
    fflush(stdout);

    while(1){

        busy = 0;

        time_0 = rte_rdtsc();

        DKFW_PROFILE_START(PROFILER_CORE, time_0);

        DKFW_PROFILE_ITEM_START(PROFILER_CORE, time_0, PROFILE_ITEM_TIMER);

        if(seq == 0){
            g_elapsed_ms = time_0 * 1000ULL / tsc_per_sec;
        }

#if USE_TX_BUFFER
        diff_tsc = time_0 - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            busy = 1;
            interface_tx_buffer_flush(seq);
            prev_tsc = time_0;
        }
#endif

        if(g_elapsed_ms != elapsed_ms_last){

            busy = 1;

            elapsed_ms_last = g_elapsed_ms;

            if(seq == 0){
                g_generator_shared_mem->elapsed_ms = g_elapsed_ms;
            }

            sys_check_timeouts(g_elapsed_ms);

            dkfw_run_timer(&g_generator_timer_bases[seq], g_elapsed_ms);

            if(g_elapsed_ms - elapsed_second_last >= 1000){

                packet_second_timer(seq, g_elapsed_ms / 1000);
                
                elapsed_second_last = g_elapsed_ms;
            }

        }

        time_0 = rte_rdtsc();

        if(busy){
            DKFW_PROFILE_ITEM_END(PROFILER_CORE, time_0, PROFILE_ITEM_TIMER);
        }

        busy = 0;

        DKFW_PROFILE_ITEM_START(PROFILER_CORE, time_0, PROFILE_ITEM_SEND);

        for(i=0;i<g_stream_cnt;i++){
            stream = g_streams[i];
            if(stream->stream_send){
                send_cnt = stream->stream_send(stream, seq, time_0, g_elapsed_ms);
                if(send_cnt){
                    busy = 1;
                }
            }
        }

        time_0 = rte_rdtsc();

        if(busy){
            DKFW_PROFILE_ITEM_END(PROFILER_CORE, time_0, PROFILE_ITEM_SEND);
        }

        busy = 0;

        if(g_pkt_distribute_core_num){

            DKFW_PROFILE_ITEM_START(PROFILER_CORE, time_0, PROFILE_ITEM_RECV_QUEUE);

            for(i=0;i<g_pkt_distribute_core_num;i++){
                rx_num = dkfw_rcv_pkt_from_process_core_q(seq, i, pkts_burst, MAX_Q_RCV_PKTS);
                if(unlikely(!rx_num)){
                    continue;
                }
                busy = 1;
                for(pktind=0;pktind<rx_num;pktind++){
                    pkt = pkts_burst[pktind];

                    pkt_dpdk_to_lwip_real(pkt, seq);
                }
            }

            time_0 = rte_rdtsc();

            if(busy){
                DKFW_PROFILE_ITEM_END(PROFILER_CORE, time_0, PROFILE_ITEM_RECV_QUEUE);
            }

        }else{

            DKFW_PROFILE_ITEM_START(PROFILER_CORE, time_0, PROFILE_ITEM_RECV_INTF);

            for(i=0;i<g_dkfw_interfaces_num;i++){
                rx_num = dkfw_rcv_pkt_from_interface(i, seq, pkts_burst, MAX_ETH_RCV_PKTS);
                if(!rx_num){
                    continue;
                }
                busy = 1;
                for(pktind=0;pktind<rx_num;pktind++){
                    pkt = pkts_burst[pktind];
                    if(unlikely(get_app_core_seq(seq, pkt, &dst_core) < 0)){
                        DISPATCH_STATS_NUM_INC(DISPATCH_STATS_UNKNOWN_CORE, seq);
                        rte_pktmbuf_free(pkt);
                        continue;
                    }
                    if(likely(dst_core >= 0)){
                        if(dst_core == seq){
                            pkt_dpdk_to_lwip_real(pkt, seq);
                        }else{
                            if(unlikely(dkfw_send_pkt_to_process_core_q(dst_core, seq, pkt) < 0)){
                                rte_pktmbuf_free(pkt);
                            }
                        }
                        continue;
                    }
                    priv_src = (MBUF_PRIV_T *)rte_mbuf_to_priv(pkt);
                    for(cind=0;cind<g_pkt_process_core_num;cind++){
                        clone = rte_pktmbuf_clone(pkt, pktmbuf_arp_clone);
                        if (!clone){
                            DISPATCH_STATS_NUM_INC(DISPATCH_STATS_CLONE_MBUF_EMPTY, seq);
                            continue;
                        }
                        priv_dst = (MBUF_PRIV_T *)rte_mbuf_to_priv(clone);
                        rte_memcpy(priv_dst, priv_src, sizeof(MBUF_PRIV_T));
                        if(cind == seq){
                            pkt_dpdk_to_lwip_real(clone, seq);
                        }else{
                            if(unlikely(dkfw_send_pkt_to_process_core_q(cind, seq, clone) < 0)){
                                rte_pktmbuf_free(clone);
                            }
                        }
                    }
                    rte_pktmbuf_free(pkt);
                }
            }

            time_0 = rte_rdtsc();

            if(busy){
                DKFW_PROFILE_ITEM_END(PROFILER_CORE, time_0, PROFILE_ITEM_RECV_INTF);
            }

            busy = 0;
            DKFW_PROFILE_ITEM_START(PROFILER_CORE, time_0, PROFILE_ITEM_RECV_QUEUE);

            for(i=0;i<g_pkt_process_core_num;i++){
                if(i == seq){
                    continue;
                }
                rx_num = dkfw_rcv_pkt_from_process_core_q(seq, i, pkts_burst, MAX_Q_RCV_PKTS);
                if(!rx_num){
                    continue;
                }
                busy = 1;
                for(pktind=0;pktind<rx_num;pktind++){
                    pkt = pkts_burst[pktind];
                    pkt_dpdk_to_lwip_real(pkt, seq);
                }
            }

            time_0 = rte_rdtsc();

            if(busy){
                DKFW_PROFILE_ITEM_END(PROFILER_CORE, time_0, PROFILE_ITEM_RECV_QUEUE);
            }

        }

        DKFW_PROFILE_END(PROFILER_CORE, time_0);

        if(unlikely(cmd_do_exit)){
            break;
        }
    }

    return 0;
}

static int main_loop(__rte_unused void *dummy)
{
    int i;
    int lcore_id = rte_lcore_id();
    CORE_CONFIG *core;

    for(i=0;i<dkfw_config.cores_pkt_process_num;i++){
        core = &dkfw_config.cores_pkt_process[i];
        if(core->core_ind == lcore_id){
            packet_loop(core->core_seq);
            return 0;
        }
    }

    for(i=0;i<dkfw_config.cores_pkt_dispatch_num;i++){
        core = &dkfw_config.cores_pkt_dispatch[i];
        if(core->core_ind == lcore_id){
            dispatch_loop(core->core_seq);
            return 0;
        }
    }

    return 0;
}

static int init_generator_stats(void *addr)
{
    int size;

    size = dkfw_stats_create_with_address(addr, g_pkt_process_core_num, GENERATOR_STATS_MAX);
    printf("generator stats mem at %p, size=[%d]\n", addr, size);

    g_generator_stats = addr;

    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_LWIP_PROCESS_FAIL, DKFW_STATS_TYPE_NUM, "lwip-fail");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_TO_DPDK_MBUF_EMPTY, DKFW_STATS_TYPE_NUM, "send-mbuf-empty");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_TO_DPDK_MBUF_SMALL, DKFW_STATS_TYPE_NUM, "send-mbuf-small");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_TO_DPDK_SEND_FAIL, DKFW_STATS_TYPE_NUM, "send-pkt-fail");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_LOCAL_PORT_NEXT, DKFW_STATS_TYPE_NUM, "port-next");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_LOCAL_PORT_EMPTY, DKFW_STATS_TYPE_NUM, "port-empty");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_PROTOCOL_WRITE_FAIL, DKFW_STATS_TYPE_NUM, "tcp-write-fail");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_PROTOCOL_HTTP_PARSE_FAIL, DKFW_STATS_TYPE_NUM, "http-parse-fail");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_PROTOCOL_DATA_EARLY, DKFW_STATS_TYPE_NUM, "data-early");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_SESSION, DKFW_STATS_TYPE_RESOURCE_POOL, "session");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_TIMER_MSG_INTERVAL, DKFW_STATS_TYPE_PAIR, "timer-msg-interval");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_TIMER_SESSION_TIMEOUT, DKFW_STATS_TYPE_PAIR, "timer-session-timeout");

    return 0;
}

static int init_dispatch_stats(void *addr)
{
    int size;

    size = dkfw_stats_create_with_address(addr, g_pkt_distribute_core_num ? g_pkt_distribute_core_num : g_pkt_process_core_num, DISPATCH_STATS_MAX);
    printf("dispatch stats mem at %p, size=[%d]\n", addr, size);

    g_dispatch_stats = addr;

    dkfw_stats_add_item(g_dispatch_stats, DISPATCH_STATS_UNKNOWN_CORE, DKFW_STATS_TYPE_NUM, "unknown-core");
    dkfw_stats_add_item(g_dispatch_stats, DISPATCH_STATS_CLONE_MBUF_EMPTY, DKFW_STATS_TYPE_NUM, "clone-empty");

    return 0;
}

static int init_generator_profile(SHARED_MEM_T *sm)
{
    int i;
    DKFW_PROFILE *profile;

    for(i=0;i<g_pkt_process_core_num;i++){
        profile = &sm->profile_pkt[i];
        dkfw_profile_init(profile, PROFILE_ITEM_MAX, PROFILE_SINGLE_MAX);
    }

    for(i=0;i<g_pkt_distribute_core_num;i++){
        profile = &sm->profile_dispatch[i];
        dkfw_profile_init(profile, PROFILE_ITEM_MAX, PROFILE_SINGLE_MAX);
    }

    return 0;
}

int main(int argc, char **argv)
{
    int i, core_pkt_cnt, core_disp_cnt = 0;
    int ret = 0;
    FILE *fp = NULL;
    char *json_str = calloc(1, 1024 * 1024);
    cJSON *json_root = NULL;
    cJSON *json_item;
    cJSON *json_array_item;
    unsigned lcore_id = 0;
    DKFW_PROFILE profile_tmp;

    if(!json_str){
        printf("no mem.\n");
        ret = -1;
        goto err;
    }

    if(cmd_parse_args(argc, argv) < 0){
        printf("invalid arg.\n");
        ret = -1;
        goto err;
    }

    printf("xf generator starts unique_id=[%s], conf=[%s]\n", unique_id, conf_file_path);

    if(!(fp = fopen(conf_file_path, "rb"))){
        printf("can not open conf file.\n");
        ret = -1;
        goto err;
    }
    fread(json_str, 1024 * 1024, 1, fp);
    fclose(fp);
    fp = NULL;

    json_root = cJSON_Parse(json_str);
    if(!json_root){
        printf("json file invalid.\n");
        ret = -1;
        goto err;
    }
    free(json_str);
    json_str = NULL;

    memset(&dkfw_config, 0, sizeof(dkfw_config));
    strcpy(dkfw_config.nuique_name, unique_id);
    dkfw_config.single_process = 1;
    dkfw_config.number_of_channels = 4;

    json_item = cJSON_GetObjectItem(json_root, "cores-process");
    if(!json_item || json_item->type != cJSON_Array){
        printf("cores-process invalid.\n");
        ret = -1;
        goto err;
    }
    core_pkt_cnt = 0;
    json_array_item = NULL;
    cJSON_ArrayForEach(json_array_item, json_item){
        dkfw_config.cores_pkt_process[core_pkt_cnt].core_enabled = 1;
        dkfw_config.cores_pkt_process[core_pkt_cnt].core_ind = json_array_item->valueint;
        core_pkt_cnt++;
    }

    json_item = cJSON_GetObjectItem(json_root, "cores-dispatch");
    if(json_item && json_item->type == cJSON_Array){
        core_disp_cnt = 0;
        json_array_item = NULL;
        cJSON_ArrayForEach(json_array_item, json_item){
            dkfw_config.cores_pkt_dispatch[core_disp_cnt].core_enabled = 1;
            dkfw_config.cores_pkt_dispatch[core_disp_cnt].core_ind = json_array_item->valueint;
            core_disp_cnt++;
        }
    }

    json_item = cJSON_GetObjectItem(json_root, "interfaces");
    if(!json_item || json_item->type != cJSON_Array){
        printf("interfaces invalid.\n");
        ret = -1;
        goto err;
    }
    i = 0;
    json_array_item = NULL;
    cJSON_ArrayForEach(json_array_item, json_item){
        strcpy(dkfw_config.pcis_config[i].pci_name, json_array_item->valuestring);
        dkfw_config.pcis_config[i].nic_tx_desc = 1024;
        i++;
    }

    dkfw_config.nic_rx_pktbuf_cnt = (core_pkt_cnt + core_disp_cnt) > 8 ? 300000 : 150000;

    if(dkfw_init(&dkfw_config) < 0){
        ret = -1;
        goto err;
    }

    tsc_per_sec = rte_get_tsc_hz();
    printf("tsc per second is [%lu]\n", tsc_per_sec);

    g_generator_shared_mem = (SHARED_MEM_T *)dkfw_global_sharemem_get();
    if(!g_generator_shared_mem){
        printf("get shared mem err.\n");
        ret = -1;
        goto err;
    }

    g_generator_shared_mem->pkt_core_cnt = g_pkt_process_core_num;
    g_generator_shared_mem->dispatch_core_cnt = g_pkt_distribute_core_num;
    g_generator_shared_mem->interface_cnt = g_dkfw_interfaces_num;

    if(init_pktmbuf_pool() < 0){
        ret = -1;
        goto err;
    }

    g_elapsed_ms = rte_rdtsc() * 1000ULL / tsc_per_sec;

    init_lwip_json(json_root, &g_generator_shared_mem->stats_lwip);

    init_generator_stats(&g_generator_shared_mem->stats_generator);

    init_dispatch_stats(&g_generator_shared_mem->stats_dispatch);

    init_generator_profile(g_generator_shared_mem);

    json_item = cJSON_GetObjectItem(json_root, "sessions");
    if(init_sessions(json_item ? json_item->valueint : 4096) < 0){
        ret = -1;
        goto err;
    }

    if(init_capture(json_root) < 0){
        ret = -1;
        goto err;
    }

    dkfw_profile_init(&profile_tmp, PROFILE_ITEM_MAX, PROFILE_SINGLE_MAX);
    PROFILER_CORE = &profile_tmp;

    if(init_networks(json_root) < 0){
        ret = -1;
        goto err;
    }

    if(init_addresses(json_root) < 0){
        ret = -1;
        goto err;
    }

    if(init_protocol_http_msg(json_root) < 0){
        ret = -1;
        goto err;
    }

    if(init_certificate(json_root) < 0){
        ret = -1;
        goto err;
    }

    if(init_streams(json_root) < 0){
        ret = -1;
        goto err;
    }

    init_protocol_http();

    g_generator_timer_bases = rte_zmalloc(NULL, sizeof(tvec_base_t) * g_pkt_process_core_num, 0);
    for(i=0;i<g_pkt_process_core_num;i++){
        dkfw_init_timers(&g_generator_timer_bases[i], g_elapsed_ms);
    }

    printf("config done.\n");

    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
           break;
        }
    }

err:
    if(fp){
        fclose(fp);
    }
    if(json_str){
        free(json_str);
    }
    if(json_root){
        cJSON_Delete(json_root);
    }
    dkfw_exit();

    capture_close_all();

    printf("===== xf-generator exit =====\n");
    fflush(stdout);

    return ret;
}

