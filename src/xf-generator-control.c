#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_launch.h>
#include <rte_memory.h>

#include "cjson/cJSON.h"

#include "dkfw_stats.h"
#include "dkfw_memory.h"
#include "dkfw_ipc.h"

#include "xf-sharedmem.h"

static int to_stat = 0;

static char unique[64] = {0};

static const char short_options[] = "u:s";

static const struct option long_options[] = {
    {"unique", required_argument, NULL, 'u'},

    {"stat", no_argument, NULL, 's'},

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
                strcpy(unique, optarg);
                break;
            case 's':
                to_stat = 1;
                break;
            default:
                break;
        }
    }

    if(!unique[0]){
        return -1;
    }

    return 0;
}

static int do_stat(void)
{
    SHARED_MEM_T *sm;
    cJSON *json_root;
    char *str;
    char buff[64];
    
    sm = (SHARED_MEM_T *)dkfw_global_sharemem_get();
    if(!sm){
        printf("sm get err.\n");
        return -1;
    }

    json_root = cJSON_CreateObject();
    sprintf(buff, "%lu", sm->elapsed_ms);
    cJSON_AddItemToObject(json_root, "elapsed_ms", cJSON_CreateString(buff));
    
    cJSON_AddItemToObject(json_root, "pkt_core_cnt", cJSON_CreateNumber(sm->pkt_core_cnt));
    cJSON_AddItemToObject(json_root, "dispatch_core_cnt", cJSON_CreateNumber(sm->dispatch_core_cnt));
    
    cJSON_AddItemToObject(json_root, "lwip", dkfw_stats_to_json(&sm->stats_lwip));
    cJSON_AddItemToObject(json_root, "generator", dkfw_stats_to_json(&sm->stats_generator));

    str = cJSON_Print(json_root);
    
    printf("%s", str);
    free(str);
    cJSON_Delete(json_root);

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;

    if(cmd_parse_args(argc, argv) < 0){
        printf("invalid arg.\n");
        return -1;
    }
    
    if(dkfw_ipc_client_init(unique, 0) < 0){
        printf("dpdk init err.\n");
        return -1;
    }

    if(to_stat){
        do_stat();
    }else{
        do_stat();
    }

    dkfw_ipc_client_exit();

    return ret;
}

