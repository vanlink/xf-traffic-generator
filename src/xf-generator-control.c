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

static int to_exit = 0;
static int to_start = 0;
static int to_stop = 0;

static char unique[64] = {0};

static const char short_options[] = "u:ers";

static const struct option long_options[] = {
    {"unique", required_argument, NULL, 'u'},

    {"exit", no_argument, NULL, 'e'},
    {"start", no_argument, NULL, 'r'},
    {"stop", no_argument, NULL, 's'},

    { 0, 0, 0, 0},
};

static SHARED_MEM_T *g_sm;

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
            case 'e':
                to_exit = 1;
                break;
            case 'r':
                to_start = 1;
                break;
            case 's':
                to_stop = 1;
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

    g_sm = (SHARED_MEM_T *)dkfw_global_sharemem_get();
    if(!g_sm){
        printf("sm get err.\n");
        return -1;
    }

    if(to_exit){
        printf("command exit.\n");
        g_sm->cmd_exit = 1;
    }else if(to_stop){
        printf("command stop.\n");
        g_sm->cmd_stop = 1;
    }else if(to_start){
        printf("command start.\n");
        g_sm->cmd_start = 1;
    }else {
        printf("unknown cmd.\n");
        return -1;
    }

    dkfw_ipc_client_exit();

    return ret;
}

