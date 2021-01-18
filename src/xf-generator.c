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

#include "xf-sharedmem.h"
#include "xf-session.h"

static char unique_id[64] = {0};
static char conf_file_path[128] = {0};

static DKFW_CONFIG dkfw_config;

static uint64_t tsc_per_sec;
static uint64_t *g_elapsed_ms;

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

static struct rte_mempool *pktmbuf_lwip2dpdk = NULL;
static struct rte_mempool *pktmbuf_arp_clone = NULL;

static int init_pktmbuf_pool(void)
{
    pktmbuf_lwip2dpdk = rte_pktmbuf_pool_create("mbuflwip2dpdk", 65534, 512, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    if(!pktmbuf_lwip2dpdk){
        printf("mbuf pktmbuf_lwip2dpdk err.\n");
        return -1;
    }

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

    init_lwip_json(json_root, &sm->stats_lwip);

    if(init_sessions(cJSON_GetObjectItem(json_root, "sessions")->valueint) < 0){
        ret = -1;
        goto err;
    }

    printf("config done.\n");

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

