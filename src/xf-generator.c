#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "cjson/cJSON.h"

#include "dpdkframework.h"

static char unique_id[64] = {0};
static char conf_file_path[128] = {0};

static DKFW_CONFIG dkfw_config;

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

int main(int argc, char **argv)
{
    int i;
    int ret = 0;
    FILE *fp = NULL;
    char *json_str = calloc(1, 1024 * 1024);
    cJSON *json_root = NULL;
    cJSON *json_item;
    cJSON *json_item_1;
    cJSON *json_array_item;

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

