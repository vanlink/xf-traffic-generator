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

#include "dkfw_intf.h"
#include "dkfw_core.h"
#include "dkfw_profile.h"
#include "dkfw_ipc.h"
#include "dkfw_timer.h"
#include "dkfw_memory.h"
#include "dpdkframework.h"

#include "xf-tools.h"
#include "xf-address.h"

#define MAX_ADDRESS_POOLS 32

#define LOCAL_ADDRESS_TYPE_PORT_RR 0
#define LOCAL_ADDRESS_TYPE_IP_RR   1

typedef struct _ADDRESS_LOCAL_ONE_t {
    int address_cnt;
    int address_curr;
    struct netif *netif_ptrs[LWIP_INTERFACE_MAX + 2];
} ADDRESS_LOCAL_ONE;

typedef struct _ADDRESS_LOCAL_t {
    int type;
    int is_ipv6;
    ADDRESS_LOCAL_ONE addresses[LWIP_CORES_MAX];
} ADDRESS_LOCAL;

typedef struct _ADDRESS_REMOTE_ONE_t {
    int address_cnt;
    int address_curr;
    int port;
    int weight_config[LWIP_INTERFACE_MAX + 2];
    int weight[LWIP_INTERFACE_MAX + 2];
    ip_addr_t address[LWIP_INTERFACE_MAX + 2];
} ADDRESS_REMOTE_ONE;

typedef struct _ADDRESS_REMOTE_t {
    int is_ipv6;
    ADDRESS_REMOTE_ONE addresses[LWIP_CORES_MAX];
} ADDRESS_REMOTE;

static ADDRESS_LOCAL *local_address_ptr[MAX_ADDRESS_POOLS];

static ADDRESS_REMOTE *remote_address_ptr[MAX_ADDRESS_POOLS];

int init_addresses(cJSON *json_root)
{
    cJSON *json_addresses;
    cJSON *json_array_item;
    cJSON *json_address_one;
    uint32_t ip = 0, start = 0, end = 0, port, weight;
    int ind = 0, i;
    ADDRESS_LOCAL *local_address;
    ADDRESS_LOCAL_ONE *local_address_one;
    ADDRESS_REMOTE *remote_address;
    ADDRESS_REMOTE_ONE *remote_address_one;
    char *str;

    memset(local_address_ptr, 0, sizeof(local_address_ptr));
    json_addresses = cJSON_GetObjectItem(json_root, "local_addresses");
    cJSON_ArrayForEach(json_array_item, json_addresses){
        local_address = rte_zmalloc(NULL, sizeof(ADDRESS_LOCAL), RTE_CACHE_LINE_SIZE);
        if(!local_address){
            printf("init local_address mem error.\n");
            return -1;
        }

        str = cJSON_GetObjectItem(json_array_item, "type")->valuestring;
        if(strstr(str, "ip")){
            local_address->type = LOCAL_ADDRESS_TYPE_IP_RR;
        }else{
            local_address->type = LOCAL_ADDRESS_TYPE_PORT_RR;
        }
        for(i=0;i<g_lwip_core_cnt;i++){
            local_address_one = &local_address->addresses[i];
            cJSON_ArrayForEach(json_address_one, cJSON_GetObjectItem(json_array_item, "addresses")){
                str_to_ipv4(cJSON_GetObjectItem(json_address_one, "start")->valuestring, &start);
                str_to_ipv4(cJSON_GetObjectItem(json_address_one, "end")->valuestring, &end);
                for(ip=start;ip<=end;ip++){
                    local_address_one->netif_ptrs[local_address_one->address_cnt] = lwip_get_netif_from_ipv4(rte_bswap32(ip));
                    if(!local_address_one->netif_ptrs[local_address_one->address_cnt]){
                        printf("local_address not found in interfaces.\n");
                        return -1;
                    }
                    local_address_one->address_cnt++;
                }
            }
        }

        local_address_ptr[ind] = local_address;
        ind++;
        if(ind >= MAX_ADDRESS_POOLS){
            printf("local_address pools too many.\n");
            return -1;
        }
    }

    ind = 0;
    memset(remote_address_ptr, 0, sizeof(remote_address_ptr));
    json_addresses = cJSON_GetObjectItem(json_root, "remote_addresses");
    cJSON_ArrayForEach(json_array_item, json_addresses){
        remote_address = rte_zmalloc(NULL, sizeof(ADDRESS_REMOTE), RTE_CACHE_LINE_SIZE);
        if(!remote_address){
            printf("init remote_address mem error.\n");
            return -1;
        }

        for(i=0;i<g_lwip_core_cnt;i++){
            remote_address_one = &remote_address->addresses[i];
            cJSON_ArrayForEach(json_address_one, cJSON_GetObjectItem(json_array_item, "addresses")){
                str_to_ipv4(cJSON_GetObjectItem(json_address_one, "start")->valuestring, &start);
                str_to_ipv4(cJSON_GetObjectItem(json_address_one, "end")->valuestring, &end);
                port = cJSON_GetObjectItem(json_address_one, "port")->valueint;
                weight = cJSON_GetObjectItem(json_address_one, "weight")->valueint;
                for(ip=start;ip<=end;ip++){
                    ip_addr_set_ip4_u32(&remote_address_one->address[remote_address_one->address_cnt], rte_bswap32(ip));
                    remote_address_one->weight_config[remote_address_one->address_cnt] = weight;
                    remote_address_one->weight[remote_address_one->address_cnt] = weight;
                    remote_address_one->address_cnt++;
                    remote_address_one->port = port;
                }
            }
        }

        remote_address_ptr[ind] = remote_address;
        ind++;
        if(ind >= MAX_ADDRESS_POOLS){
            printf("remote_address pools too many.\n");
            return -1;
        }
    }

    return 0;
}

struct netif *local_address_get(int ind, int core, int force_next)
{
    ADDRESS_LOCAL_ONE *address = &local_address_ptr[ind]->addresses[core];
    struct netif *ret = address->netif_ptrs[address->address_curr];

    if(local_address_ptr[ind]->type == LOCAL_ADDRESS_TYPE_IP_RR || force_next){
        address->address_curr++;
        if(address->address_curr >= address->address_cnt){
            address->address_curr = 0;
        }
    }

    return ret;
}

ip_addr_t *remote_address_get(int ind, int core, int *port)
{
    ADDRESS_REMOTE_ONE *address = &remote_address_ptr[ind]->addresses[core];
    int curr = address->address_curr;
    ip_addr_t *ret = &address->address[curr];

    *port = address->port;

    address->weight[curr]--;
    if(address->weight[curr] < 1){
        address->weight[curr] = address->weight_config[curr];
        address->address_curr++;
        if(address->address_curr >= address->address_cnt){
            address->address_curr = 0;
        }
    }

    return ret;
}

