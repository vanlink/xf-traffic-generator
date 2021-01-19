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

#include "lwip/arch.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"

#include "xf-tools.h"
#include "xf-network.h"

static struct netif *lwip_netifs_ptr[LWIP_INTERFACE_MAX];
static int lwip_netif_num_2_phy_port_ind[LWIP_INTERFACE_MAX + 2] = {0};
static struct rte_mempool *pktmbuf_lwip2dpdk = NULL;

static err_t pkt_lwip_to_dpdk(struct netif *intf, struct pbuf *p)
{
    struct rte_mbuf *m;
    struct pbuf *lwip_pbuf;
    int ret;
    char *data;
    struct rte_ether_hdr *ethhdr;
    struct rte_ipv4_hdr *iph;
    struct rte_ipv6_hdr *ipv6h;
    struct rte_tcp_hdr *tcphdr;
    struct rte_udp_hdr *udphdr;

    m = rte_pktmbuf_alloc(pktmbuf_lwip2dpdk);
    if(!m) {
        return ERR_MEM;
    }

    for(lwip_pbuf = p; lwip_pbuf; lwip_pbuf = lwip_pbuf->next) {
        data = rte_pktmbuf_append(m, lwip_pbuf->len);
        if(!data) {
            rte_pktmbuf_free(m);
            return ERR_MEM;
        }
        rte_memcpy(data, lwip_pbuf->payload, lwip_pbuf->len);
    }

    data = rte_pktmbuf_mtod(m, char *);
    
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

    ret = rte_eth_tx_burst(lwip_netif_num_2_phy_port_ind[intf->num], p->cpu_id, &m, 1);
    if (unlikely(ret < 1)) {
        rte_pktmbuf_free(m);
    }

    return ERR_OK;
}

static err_t netif_init_local(struct netif *intf)
{
    int port;
    struct rte_ether_addr mac_addr;

    intf->linkoutput = pkt_lwip_to_dpdk;
    intf->output = etharp_output;
    intf->output_ip6 = ethip6_output;
    intf->mtu = 1518;
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

int init_networks(cJSON *json_root)
{
    cJSON *json_networks = cJSON_GetObjectItem(json_root, "networks");
    cJSON *json_array_item;
    uint32_t ip = 0, start = 0, end = 0, mask = 0, gw = 0;
    struct netif *net_if;
    ip4_addr_t local_ipaddr, local_netmask, local_gw;
    int ind = 0;
    int interface_ind;

    pktmbuf_lwip2dpdk = rte_pktmbuf_pool_create("mbuflwip2dpdk", 65534, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    if(!pktmbuf_lwip2dpdk){
        printf("mbuf pktmbuf_lwip2dpdk err.\n");
        return -1;
    }

    memset(lwip_netifs_ptr, 0, sizeof(struct netif *) * LWIP_INTERFACE_MAX);

    cJSON_ArrayForEach(json_array_item, json_networks){

        interface_ind = cJSON_GetObjectItem(json_array_item, "interface_ind")->valueint;

        str_to_ipv4(cJSON_GetObjectItem(json_array_item, "start")->valuestring, &start);
        str_to_ipv4(cJSON_GetObjectItem(json_array_item, "end")->valuestring, &end);
        str_to_ipv4(cJSON_GetObjectItem(json_array_item, "mask")->valuestring, &mask);
        str_to_ipv4(cJSON_GetObjectItem(json_array_item, "gw")->valuestring, &gw);

        for(ip=start;ip<=end;ip++){
            IP4_ADDR(&local_ipaddr, (ip >> 24) & 0xff,
                                (ip >> 16) & 0xff,
                                (ip >> 8) & 0xff,
                                (ip >> 0) & 0xff);
            IP4_ADDR(&local_netmask, (mask >> 24) & 0xff,
                                    (mask >> 16) & 0xff,
                                    (mask >> 8) & 0xff,
                                    (mask >> 0) & 0xff);
            IP4_ADDR(&local_gw, (gw >> 24) & 0xff,
                                    (gw >> 16) & 0xff,
                                    (gw >> 8) & 0xff,
                                    (gw >> 0) & 0xff);
            net_if = rte_zmalloc(NULL, sizeof(struct netif), RTE_CACHE_LINE_SIZE);
            if(!net_if){
                printf("init net if mem error.\n");
                return -1;
            }
            lwip_netifs_ptr[ind] = net_if;

            if(!netif_add(net_if, &local_ipaddr, &local_netmask, &local_gw, NULL, netif_init_local, netif_input, 0)){
                printf("netif_add %d err.\n", ind);
                return -1;
            }
            lwip_netif_num_2_phy_port_ind[net_if->num] = interface_ind;
            netif_set_link_up(net_if);
            netif_set_up(net_if);

            ind++;
        }
    }

    return 0;
}
