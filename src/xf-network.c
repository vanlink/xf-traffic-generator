#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "cjson/cJSON.h"

#include <rte_launch.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "dpdkframework.h"

#include "lwip/arch.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"

#include "xf-tools.h"
#include "xf-network.h"
#include "xf-generator.h"
#include "xf-capture.h"

#define MAX_PKT_BURST 32

static int lwip_netif_num_2_phy_port_ind[LWIP_INTERFACE_MAX + 2] = {0};
static struct rte_mempool *pktmbuf_lwip2dpdk = NULL;

static struct rte_eth_dev_tx_buffer *tx_buffer[MAX_PCI_NUM][MAX_CORES_PER_ROLE];

static err_t pkt_lwip_to_dpdk(struct netif *intf, struct pbuf *p)
{
    struct rte_mbuf *m = NULL;
    struct pbuf *lwip_pbuf;
    char *data;
    struct rte_ether_hdr *ethhdr;
    struct rte_ipv4_hdr *iph;
    struct rte_ipv6_hdr *ipv6h;
    struct rte_tcp_hdr *tcphdr;
    struct rte_udp_hdr *udphdr;
    int port, txq;

#if LWIP_TX_ZERO_COPY
    struct rte_mbuf *mseq;

    for(lwip_pbuf = p; lwip_pbuf; lwip_pbuf = lwip_pbuf->next) {
        if(lwip_pbuf->pbuf_dpdk_mbuf){
            mseq = lwip_pbuf->pbuf_dpdk_mbuf;
            data = rte_pktmbuf_mtod(mseq, char *);
            if((char *)lwip_pbuf->payload > data){
                if(unlikely(!rte_pktmbuf_adj(mseq, (char *)lwip_pbuf->payload - data))){
                    GENERATOR_STATS_NUM_INC(GENERATOR_STATS_TO_DPDK_MBUF_SMALL);
                    rte_pktmbuf_free(mseq);
                    return ERR_MEM;
                }
            }else if((char *)lwip_pbuf->payload < data){
                GENERATOR_STATS_NUM_INC(GENERATOR_STATS_TO_DPDK_MBUF_SMALL);
                rte_pktmbuf_free(mseq);
                return ERR_MEM;
            }
            if(!m){
                m = mseq;
            }
        }else{
            mseq = rte_pktmbuf_alloc(pktmbuf_lwip2dpdk);
            if(!mseq) {
                GENERATOR_STATS_NUM_INC(GENERATOR_STATS_TO_DPDK_MBUF_EMPTY);
                return ERR_MEM;
            }
            if(!m){
                m = mseq;
            }
            data = rte_pktmbuf_append(mseq, lwip_pbuf->len);
            if(!data) {
                GENERATOR_STATS_NUM_INC(GENERATOR_STATS_TO_DPDK_MBUF_SMALL);
                rte_pktmbuf_free(m);
                return ERR_MEM;
            }
            rte_memcpy(data, lwip_pbuf->payload, lwip_pbuf->len);
        }
        if (mseq != m){
            rte_pktmbuf_chain(m, mseq);
        }
    }
#else
    m = rte_pktmbuf_alloc(pktmbuf_lwip2dpdk);
    if(!m) {
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_TO_DPDK_MBUF_EMPTY);
        return ERR_MEM;
    }
    for(lwip_pbuf = p; lwip_pbuf; lwip_pbuf = lwip_pbuf->next) {
        data = rte_pktmbuf_append(m, lwip_pbuf->len);
        if(!data) {
            GENERATOR_STATS_NUM_INC(GENERATOR_STATS_TO_DPDK_MBUF_SMALL);
            rte_pktmbuf_free(m);
            return ERR_MEM;
        }
        rte_memcpy(data, lwip_pbuf->payload, lwip_pbuf->len);
    }
#endif

    // rte_pktmbuf_dump(stdout, m, rte_pktmbuf_pkt_len(m));

    data = rte_pktmbuf_mtod(m, char *);

    if(unlikely(g_is_capturing)){
        capture_do_capture(p->cpu_id, data, rte_pktmbuf_data_len(m));
    }

    ethhdr = (struct rte_ether_hdr *)data;

    if(likely(ntohs(ethhdr->ether_type) == RTE_ETHER_TYPE_IPV4)){
        m->ol_flags |= (PKT_TX_IP_CKSUM | PKT_TX_IPV4);
        m->l2_len = sizeof(struct rte_ether_hdr);
        m->l3_len = sizeof(struct rte_ipv4_hdr);
        
        iph = (struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));
        iph->hdr_checksum = 0;

        if(iph->next_proto_id == IPPROTO_TCP){
            m->ol_flags |= PKT_TX_TCP_CKSUM;
            tcphdr = (struct rte_tcp_hdr *)((char *)iph + ((iph->version_ihl & 0x0f) << 2));
            tcphdr->cksum = rte_ipv4_phdr_cksum(iph, m->ol_flags);
        }else if(iph->next_proto_id == IPPROTO_UDP){
            m->ol_flags |= PKT_TX_UDP_CKSUM;
            udphdr = (struct rte_udp_hdr *)((char *)iph + ((iph->version_ihl & 0x0f) << 2));
            udphdr->dgram_cksum = rte_ipv4_phdr_cksum(iph, m->ol_flags);
        }
    }else if(ntohs(ethhdr->ether_type) == RTE_ETHER_TYPE_ARP){
    }else if(ntohs(ethhdr->ether_type) == RTE_ETHER_TYPE_IPV6){
        m->ol_flags |= PKT_TX_IPV6;
        m->l2_len = sizeof(struct rte_ether_hdr);
        m->l3_len = sizeof(struct rte_ipv6_hdr);

        ipv6h = (struct rte_ipv6_hdr *)(data + sizeof(struct rte_ether_hdr));
        if(ipv6h->proto == IPPROTO_TCP){
            m->ol_flags |= PKT_TX_TCP_CKSUM;
            tcphdr = (struct rte_tcp_hdr *)((char *)ipv6h + sizeof(struct rte_ipv6_hdr));
            tcphdr->cksum = rte_ipv6_phdr_cksum(ipv6h, m->ol_flags);
        }else if(ipv6h->proto == IPPROTO_UDP){
            m->ol_flags |= PKT_TX_UDP_CKSUM;
            udphdr = (struct rte_udp_hdr *)((char *)ipv6h + sizeof(struct rte_ipv6_hdr));
            udphdr->dgram_cksum = rte_ipv6_phdr_cksum(ipv6h, m->ol_flags);
        }
    }else{
    }

    port = lwip_netif_num_2_phy_port_ind[intf->num];
    txq = p->cpu_id;

#if USE_TX_BUFFER
    if(unlikely(p->pbuf_send_fast)){
        if (unlikely(rte_eth_tx_burst(port, txq, &m, 1) < 1)) {
            GENERATOR_STATS_NUM_INC(GENERATOR_STATS_TO_DPDK_SEND_FAIL);
            rte_pktmbuf_free(m);
        }
    }else{
        rte_eth_tx_buffer(port, txq, tx_buffer[port][txq], m);
    }
#else
    if (unlikely(rte_eth_tx_burst(port, txq, &m, 1) < 1)) {
        GENERATOR_STATS_NUM_INC(GENERATOR_STATS_TO_DPDK_SEND_FAIL);
        rte_pktmbuf_free(m);
    }
#endif

    return ERR_OK;
}

int interface_tx_buffer_flush(int seq)
{
    int i;

    for(i=0;i<g_dkfw_interfaces_num;i++){
        rte_eth_tx_buffer_flush(i, seq, tx_buffer[i][seq]);
    }

    return 0;
}

static err_t netif_init_local(struct netif *intf)
{
    int port;
    struct rte_ether_addr mac_addr;

    intf->linkoutput = pkt_lwip_to_dpdk;
    intf->output = etharp_output;
    intf->output_ip6 = ethip6_output;
    intf->mtu = 1518;
    intf->mtu6 = 1518 - 20;
    intf->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6;

    port = lwip_netif_num_2_phy_port_ind[intf->num];

    rte_eth_macaddr_get(port, &mac_addr);

    intf->hwaddr[0] = mac_addr.addr_bytes[0];
    intf->hwaddr[1] = mac_addr.addr_bytes[1];
    intf->hwaddr[2] = mac_addr.addr_bytes[2];
    intf->hwaddr[3] = mac_addr.addr_bytes[3];
    intf->hwaddr[4] = mac_addr.addr_bytes[4];
    intf->hwaddr[5] = mac_addr.addr_bytes[5];
    intf->hwaddr_len = sizeof(intf->hwaddr);

    return ERR_OK;
}

static int init_networks_ipv4(cJSON *json_array_item,int interface_ind)
{
    uint32_t ip = 0, start = 0, end = 0, mask = 0, gw = 0, vrouter = 0;
    ip4_addr_t local_ipaddr, local_netmask, local_gw, local_vrouter;
    struct netif *net_if;
    struct netif *netif_vrouter = NULL;
    cJSON *json;
    int hash_cnt = 8192;
    char start_str[128], end_str[128];

    json = cJSON_GetObjectItem(json_array_item, "start");
    if(!json){
        printf("network start req.\n");
        return -1;
    }
    if(str_to_ipv4(json->valuestring, &start) < 0){
        printf("invalid network ip.\n");
        return -1;
    }
    strcpy(start_str, json->valuestring);

    json = cJSON_GetObjectItem(json_array_item, "end");
    if(!json){
        json = cJSON_GetObjectItem(json_array_item, "start");
    }
    if(str_to_ipv4(json->valuestring, &end) < 0){
        printf("invalid network ip.\n");
        return -1;
    }
    strcpy(end_str, json->valuestring);

    json = cJSON_GetObjectItem(json_array_item, "mask");
    if(json){
        if(str_to_ipv4(json->valuestring, &mask) < 0){
            printf("invalid network mask.\n");
            return -1;
        }
    }else{
        printf("network mask req.\n");
        return -1;
    }

    json = cJSON_GetObjectItem(json_array_item, "gw");
    if(json){
        if(str_to_ipv4(json->valuestring, &gw) < 0){
            printf("invalid network gateway.\n");
            return -1;
        }
    }

    json = cJSON_GetObjectItem(json_array_item, "vrouter");
    if(json){
        if(str_to_ipv4(json->valuestring, &vrouter) < 0){
            printf("invalid network vrouter.\n");
            return -1;
        }
    }

    json = cJSON_GetObjectItem(json_array_item, "hashsize");
    if(json){
        hash_cnt = json->valueint;
    }

    printf("add networks [%s] -> [%s], hash per interface=[%d], per core=[%d]\n", start_str, end_str, hash_cnt, hash_cnt / g_pkt_process_core_num);
    hash_cnt = hash_cnt / g_pkt_process_core_num;

    IP4_ADDR(&local_netmask, (mask >> 24) & 0xff,
                            (mask >> 16) & 0xff,
                            (mask >> 8) & 0xff,
                            (mask >> 0) & 0xff);
    IP4_ADDR(&local_gw, (gw >> 24) & 0xff,
                            (gw >> 16) & 0xff,
                            (gw >> 8) & 0xff,
                            (gw >> 0) & 0xff);
    IP4_ADDR(&local_vrouter, (vrouter >> 24) & 0xff,
                            (vrouter >> 16) & 0xff,
                            (vrouter >> 8) & 0xff,
                            (vrouter >> 0) & 0xff);

    if(vrouter){
        netif_vrouter = lwip_get_netif_from_ipv4(ip4_addr_get_u32(&local_vrouter));
        if(!netif_vrouter){
            printf("init net if vrouter interface not found.\n");
            return -1;
        }
    }


    for(ip=start;ip<=end;ip++){
        IP4_ADDR(&local_ipaddr, (ip >> 24) & 0xff,
                            (ip >> 16) & 0xff,
                            (ip >> 8) & 0xff,
                            (ip >> 0) & 0xff);
        net_if = rte_zmalloc(NULL, sizeof(struct netif), 0);
        if(!net_if){
            printf("init net if mem error.\n");
            return -1;
        }
        if(lwip_get_netif_from_ipv4(ip4_addr_get_u32(&local_ipaddr))){
            printf("network addr already exist\n");
            return -1;
        }
        if(!netif_add(net_if, &local_ipaddr, &local_netmask, &local_gw, NULL, netif_init_local, netif_input, hash_cnt)){
            printf("netif_add err.\n");
            return -1;
        }
        net_if->netif_vrouter = netif_vrouter;
        lwip_netif_num_2_phy_port_ind[net_if->num] = interface_ind;
        netif_set_link_up(net_if);
        netif_set_up(net_if);
    }

    return 0;
}

static int init_networks_ipv6(cJSON *json_array_item,int interface_ind)
{
    struct in6_addr start, end, gw, tmpipv6;
    int masklen;
    struct netif *net_if;
    cJSON *json2;
    int num, i;
    uint32_t lastpart;
    ip6_addr_t local_ipv6addr;
    int hash_cnt = 8192;
    char start_str[128], end_str[128];

    json2 = cJSON_GetObjectItem(json_array_item, "start");
    if(json2){
        if(str_to_ipv6(json2->valuestring, &start) < 0){
            printf("invalid ipv6.\n");
            return -1;
        }
    }else{
        printf("no ip start.\n");
        return -1;
    }
    strcpy(start_str, json2->valuestring);

    json2 = cJSON_GetObjectItem(json_array_item, "end");
    if(!json2){
        json2 = cJSON_GetObjectItem(json_array_item, "start");
    }
    if(str_to_ipv6(json2->valuestring, &end) < 0){
        printf("invalid ipv6.\n");
        return -1;
    }
    strcpy(end_str, json2->valuestring);

    json2 = cJSON_GetObjectItem(json_array_item, "gw");
    if(json2){
        if(str_to_ipv6(json2->valuestring, &gw) < 0){
            printf("invalid ipv6.\n");
            return -1;
        }
    }else{
        memset(&gw, 0, sizeof(gw));
    }

    json2 = cJSON_GetObjectItem(json_array_item, "masklen");
    masklen = json2 ? json2->valueint : 64;

    json2 = cJSON_GetObjectItem(json_array_item, "hashsize");
    if(json2){
        hash_cnt = json2->valueint;
    }

    printf("add networks [%s] -> [%s], hash per interface=[%d], per core=[%d]\n", start_str, end_str, hash_cnt, hash_cnt / g_pkt_process_core_num);
    hash_cnt = hash_cnt / g_pkt_process_core_num;

    num = rte_bswap32(end.s6_addr32[3]) - rte_bswap32(start.s6_addr32[3]) + 1;
    for(i=0;i<num;i++){
        lastpart = rte_bswap32(rte_bswap32(start.s6_addr32[3]) + i);
        memcpy(&tmpipv6, &start, sizeof(tmpipv6));
        tmpipv6.s6_addr32[3] = lastpart;

        net_if = rte_zmalloc(NULL, sizeof(struct netif), 0);
        if(!net_if){
            printf("init net if mem error.\n");
            return -1;
        }

        if(!netif_add(net_if, NULL, NULL, NULL, NULL, netif_init_local, netif_input, hash_cnt)){
            printf("netif_add ipv6 err.\n");
            return -1;
        }
        IP6_ADDR(&local_ipv6addr, tmpipv6.s6_addr32[0], tmpipv6.s6_addr32[1], tmpipv6.s6_addr32[2], tmpipv6.s6_addr32[3]);
        if(lwip_get_netif_from_ipv6((u8_t *)tmpipv6.s6_addr32)){
            printf("network addr6 already exist\n");
            return -1;
        }
        netif_ip6_addr_set(net_if, 0, &local_ipv6addr);
        netif_ip6_addr_set_state(net_if, 0, IP6_ADDR_PREFERRED);
        IP6_ADDR(&local_ipv6addr, gw.s6_addr32[0], gw.s6_addr32[1], gw.s6_addr32[2], gw.s6_addr32[3]);
        memcpy(&net_if->ip6_gw, &local_ipv6addr, sizeof(local_ipv6addr));
        net_if->ip6_masklen = masklen;
        lwip_netif_num_2_phy_port_ind[net_if->num] = interface_ind;
        netif_set_link_up(net_if);
        netif_set_up(net_if);
    }

    return 0;
}

int init_networks(cJSON *json_root)
{
    cJSON *json_networks = cJSON_GetObjectItem(json_root, "networks");
    cJSON *json_array_item;
    int interface_ind;
    char *val_string;
    uint32_t start;
    struct in6_addr start6;
    int i, j;
    int allcores = g_pkt_process_core_num + g_pkt_distribute_core_num;

    for(i=0;i<g_dkfw_interfaces_num;i++){
        for(j=0;j<g_pkt_process_core_num;j++){
            tx_buffer[i][j] = rte_zmalloc_socket(NULL, RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0, SOCKET_ID_ANY);
            if (!tx_buffer[i][j]){
                printf("init tx_buffer err.\n");
                return -1;
            }
            rte_eth_tx_buffer_init(tx_buffer[i][j], MAX_PKT_BURST);
        }
    }

    pktmbuf_lwip2dpdk = rte_pktmbuf_pool_create("mbuflwip2dpdk", (allcores > 8) ? 131071 : 65535, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    if(!pktmbuf_lwip2dpdk){
        printf("mbuf pktmbuf_lwip2dpdk err.\n");
        return -1;
    }

    cJSON_ArrayForEach(json_array_item, json_networks){

        interface_ind = cJSON_GetObjectItem(json_array_item, "interface_ind")->valueint;

        val_string = cJSON_GetObjectItem(json_array_item, "start")->valuestring;

        if(!str_to_ipv4(val_string, &start)){
            if(init_networks_ipv4(json_array_item, interface_ind) < 0){
                return -1;
            }
        }else if(!str_to_ipv6(val_string, &start6)){
            if(init_networks_ipv6(json_array_item, interface_ind) < 0){
                return -1;
            }
        }else{
            printf("invalid ipaddr %s.\n", val_string);
            return -1;
        }
    }

    return 0;
}

