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
#include "lwip/memp.h"

#include "xf-generator.h"
#include "xf-sharedmem.h"
#include "xf-session.h"
#include "xf-network.h"
#include "xf-address.h"
#include "xf-protocol-http-msg.h"
#include "xf-stream.h"
#include "xf-protocol-common.h"
#include "xf-protocol-http.h"

typedef struct _DPDK_MBUF_PRIV_TAG {
    struct netif *pnetif;
} MBUF_PRIV_T;

#define MAX_RCV_PKTS 32

static char unique_id[64] = {0};
static char conf_file_path[128] = {0};

static DKFW_CONFIG dkfw_config;

uint64_t tsc_per_sec;
uint64_t *g_elapsed_ms;

DKFW_STATS *g_generator_stats = NULL;

static struct rte_mempool *pktmbuf_arp_clone = NULL;

static const char short_options[] = "u:c:";
static const struct option long_options[] = {
    {"unique", required_argument, NULL, 'u'},
    {"conf", required_argument, NULL, 'c'},

    { 0, 0, 0, 0},
};

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
    return *g_elapsed_ms;
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
    }

    conf.stats_mem_addr = stats_mem;

    lwip_init(&conf);

    return 0;
}

static int pkt_dpdk_to_lwip_real(struct rte_mbuf *m)
{
    int dpdklen;
    char *dpdkdat;
    err_t ret = 0;
    struct pbuf *p;
    MBUF_PRIV_T *priv = (MBUF_PRIV_T *)rte_mbuf_to_priv(m);

    dpdklen = rte_pktmbuf_pkt_len(m);
    dpdkdat = rte_pktmbuf_mtod(m, char *);

    p = pbuf_alloc(PBUF_RAW, dpdklen, PBUF_POOL);
    if(!p) {
         ret = -1;
        goto exit;
    }
    p->payload = dpdkdat;

    ret = priv->pnetif->input(p, priv->pnetif);
    if(ret != ERR_OK){
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_LWIP_PROCESS_FAIL);
        ret = -1;
        pbuf_free(p);
    }

exit:

    rte_pktmbuf_free(m);

    return ret;
}


static int get_app_core_seq(struct rte_mbuf *m, int *dst_core)
{
    struct rte_net_hdr_lens hdr_lens = {0, 0, 0, 0, 0, 0, 0};
    char *dpdkdat;
    uint32_t ptype;
    uint16_t port_humam;
    struct rte_ipv4_hdr *ipv4 = NULL;
    struct rte_ipv6_hdr *ipv6 = NULL;
    struct rte_tcp_hdr *tcp = NULL;
    struct rte_udp_hdr *udp = NULL;
    struct rte_icmp_hdr *icmp = NULL;
    struct rte_arp_hdr *arp = NULL;
    MBUF_PRIV_T *priv = (MBUF_PRIV_T *)rte_mbuf_to_priv(m);

    (void)ipv4;
    (void)ipv6;
    (void)udp;
    (void)icmp;

    dpdkdat = rte_pktmbuf_mtod(m, char *);

    ptype = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);

    if(unlikely((ptype & RTE_PTYPE_L2_MASK) != RTE_PTYPE_L2_ETHER)){
        return -1;
    }

    if(unlikely(((struct rte_ether_hdr *)dpdkdat)->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))){
        arp = (struct rte_arp_hdr *)(dpdkdat + RTE_ETHER_HDR_LEN);
        priv->pnetif = lwip_get_netif_from_ipv4(arp->arp_data.arp_tip);
        if(!priv->pnetif){
            return -1;
        }
        if(arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)){
            *dst_core = 0;
        }else if(arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)){
            *dst_core = -1;
        }else{
            return -1;
        }

        return 0;
    }

    if(likely((ptype & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV4)){
        ipv4 = (struct rte_ipv4_hdr *)(dpdkdat + hdr_lens.l2_len);
        priv->pnetif = lwip_get_netif_from_ipv4(ipv4->dst_addr);
        if(!priv->pnetif){
            return -1;
        }
    }else if((ptype & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV6){
        ipv6 = (struct rte_ipv6_hdr *)(dpdkdat + hdr_lens.l2_len);
    }else{
        return -1;
    }

    if(likely((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)){
        tcp = (struct rte_tcp_hdr *)(dpdkdat + hdr_lens.l2_len + hdr_lens.l3_len);
        port_humam = rte_bswap16(tcp->dst_port);
        if(LWIP_NETIF_LPORT_TCP_IS_LISTEN(priv->pnetif, port_humam)){
            // dst to listen port, hash base on src port
            *dst_core = rte_bswap16(tcp->src_port) % g_pkt_process_core_num;
        }else{
            // dst to client port, hash base on dst port
            *dst_core = port_humam % g_pkt_process_core_num;
        }
    }else if((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP){
        udp = (struct rte_udp_hdr *)(dpdkdat + hdr_lens.l2_len + hdr_lens.l3_len);
    }else if((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_ICMP){
        icmp = (struct rte_icmp_hdr *)(dpdkdat + hdr_lens.l2_len + hdr_lens.l3_len);
    }else{
        return -1;
    }

    return 0;
}

static int dispatch_loop(int seq)
{
    int i, cind;
    struct rte_mbuf *pkts_burst[MAX_RCV_PKTS];
    struct rte_mbuf *pkt, *clone;
    int rx_num, pktind;
    int dst_core;
    MBUF_PRIV_T *priv_src;
    MBUF_PRIV_T *priv_dst;

    printf("dispatch loop seq=%d tsc_per_sec=%lu\n", seq, tsc_per_sec);

    while(1){
        for(i=0;i<g_dkfw_interfaces_num;i++){
            rx_num = dkfw_rcv_pkt_from_interface(i, seq, pkts_burst, MAX_RCV_PKTS);
            if(rx_num){
                for(pktind=0;pktind<rx_num;pktind++){
                    pkt = pkts_burst[pktind];

                    if(get_app_core_seq(pkt, &dst_core) < 0){
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
                                    continue;
                                }
                                priv_dst = (MBUF_PRIV_T *)rte_mbuf_to_priv(clone);
                                memcpy(priv_dst, priv_src, sizeof(MBUF_PRIV_T));
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
    }

    return 0;
}

static int packet_loop(int seq)
{
    int i;
    uint64_t elapsed_ms_last = 0;
    uint64_t time_0;
    struct rte_mbuf *pkts_burst[MAX_RCV_PKTS];
    struct rte_mbuf *pkt;
    int rx_num, pktind;
    STREAM *stream;

    printf("packet loop seq=%d tsc_per_sec=%lu\n", seq, tsc_per_sec);

    time_0 = rte_rdtsc();

    *g_elapsed_ms = time_0 * 1000ULL / tsc_per_sec;

    lwip_init_per_core(seq);

    while(1){
        time_0 = rte_rdtsc();

        if(seq == 0){
            *g_elapsed_ms = time_0 * 1000ULL / tsc_per_sec;
        }

        if(*g_elapsed_ms != elapsed_ms_last){
            elapsed_ms_last = *g_elapsed_ms;
            sys_check_timeouts(*g_elapsed_ms);
        }

        for(i=0;i<g_stream_cnt;i++){
            stream = g_streams[i];
            if(stream->stream_send){
                stream->stream_send(stream, seq, time_0);
            }
        }

        for(i=0;i<g_pkt_distribute_core_num;i++){
            rx_num = dkfw_rcv_pkt_from_process_core_q(seq, i, pkts_burst, MAX_RCV_PKTS);
            if(unlikely(!rx_num)){
                continue;
            }
            for(pktind=0;pktind<rx_num;pktind++){
                pkt = pkts_burst[pktind];

                pkt_dpdk_to_lwip_real(pkt);
            }
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
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_PROTOCOL_ERROR, DKFW_STATS_TYPE_NUM, "tcp-error");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_PROTOCOL_WRITE_FAIL, DKFW_STATS_TYPE_NUM, "tcp-write-fail");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_PROTOCOL_HTTP_PARSE_FAIL, DKFW_STATS_TYPE_NUM, "http-parse-fail");
    dkfw_stats_add_item(g_generator_stats, GENERATOR_STATS_SESSION, DKFW_STATS_TYPE_RESOURCE_POOL, "session");

    return 0;
}

int main(int argc, char **argv)
{
    int i;
    int ret = 0;
    FILE *fp = NULL;
    char *json_str = calloc(1, 1024 * 1024);
    cJSON *json_root = NULL;
    cJSON *json_item;
    cJSON *json_array_item;
    SHARED_MEM_T *sm;
    unsigned lcore_id = 0;

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

    json_item = cJSON_GetObjectItem(json_root, "cores-process");
    if(!json_item || json_item->type != cJSON_Array){
        printf("cores-process invalid.\n");
        ret = -1;
        goto err;
    }
    i = 0;
    json_array_item = NULL;
    cJSON_ArrayForEach(json_array_item, json_item){
        dkfw_config.cores_pkt_process[i].core_enabled = 1;
        dkfw_config.cores_pkt_process[i].core_ind = json_array_item->valueint;
        i++;
    }

    json_item = cJSON_GetObjectItem(json_root, "cores-dispatch");
    if(!json_item || json_item->type != cJSON_Array){
        printf("cores-dispatch invalid.\n");
        ret = -1;
        goto err;
    }
    i = 0;
    json_array_item = NULL;
    cJSON_ArrayForEach(json_array_item, json_item){
        dkfw_config.cores_pkt_dispatch[i].core_enabled = 1;
        dkfw_config.cores_pkt_dispatch[i].core_ind = json_array_item->valueint;
        i++;
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
        i++;
    }

    if(dkfw_init(&dkfw_config) < 0){
        ret = -1;
        goto err;
    }

    tsc_per_sec = rte_get_tsc_hz();
    printf("tsc per second is [%lu]\n", tsc_per_sec);

    sm = (SHARED_MEM_T *)dkfw_global_sharemem_get();
    if(!sm){
        printf("get shared mem err.\n");
        ret = -1;
        goto err;
    }

    g_elapsed_ms = &sm->elapsed_ms;

    if(init_pktmbuf_pool() < 0){
        ret = -1;
        goto err;
    }

    *g_elapsed_ms = rte_rdtsc() * 1000ULL / tsc_per_sec;

    init_lwip_json(json_root, &sm->stats_lwip);

    init_generator_stats(&sm->stats_generator);

    if(init_sessions(cJSON_GetObjectItem(json_root, "sessions")->valueint) < 0){
        ret = -1;
        goto err;
    }

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

    if(init_streams(json_root) < 0){
        ret = -1;
        goto err;
    }

    init_protocol_http();

    printf("config done.\n");

    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
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

    return ret;
}

