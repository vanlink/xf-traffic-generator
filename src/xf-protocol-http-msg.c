#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_malloc.h>

#include "cjson/cJSON.h"

#include "xf-tools.h"
#include "xf-protocol-http-msg.h"

#define MSG_POOLS_MAX 32
#define MSGS_PER_POOL_MAX 32

typedef struct _PROTOCOL_HTTP_MSG_ONE_t {
    int len;
    char *msg;
    rte_iova_t msg_iova;
} PROTOCOL_HTTP_MSG_ONE;

typedef struct _PROTOCOL_HTTP_MSG_t {
    int message_cnt;
    PROTOCOL_HTTP_MSG_ONE messages[MSGS_PER_POOL_MAX];
} PROTOCOL_HTTP_MSG;

static PROTOCOL_HTTP_MSG *http_message_pools[MSG_POOLS_MAX];

static char *http_msg_req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: xf-traffic-generator\r\nAccept: */*\r\n\r\n";
static char *http_msg_rsp = "HTTP/1.1 200 OK\r\nServer: xf-traffic-generator\r\nContent-Type: text/html\r\nContent-Length: 18\r\n\r\n<html>hello</html>";

int init_protocol_http_msg(cJSON *json_root)
{
    cJSON *json_messages = cJSON_GetObjectItem(json_root, "http_messages");
    cJSON *json_array_item;
    cJSON *json_msg;
    PROTOCOL_HTTP_MSG *msg;
    int ind = 0;
    char *path;
    PROTOCOL_HTTP_MSG_ONE *msg_one;

    cJSON_ArrayForEach(json_array_item, json_messages){
        msg = rte_zmalloc(NULL, sizeof(PROTOCOL_HTTP_MSG), 0);
        if(!msg){
            printf("init http_msg mem error.\n");
            return -1;
        }
        http_message_pools[ind] = msg;
        ind++;

        if(ind >= MSG_POOLS_MAX){
            printf("http msg pools too many.\n");
            return -1;
        }

        cJSON_ArrayForEach(json_msg, cJSON_GetObjectItem(json_array_item, "messages")){
            path = cJSON_GetObjectItem(json_msg, "path")->valuestring;
            msg_one = &msg->messages[msg->message_cnt];
            msg_one->msg = read_file_to_buff(path, &msg_one->len);
            if(!msg_one->msg){
                printf("failed to load http msg file [%s].\n", path);
                return -1;
            }
            msg_one->msg_iova = rte_malloc_virt2iova(msg_one->msg);
            if(msg_one->msg_iova == RTE_BAD_IOVA){
                printf("failed to load http msg iova file [%s].\n", path);
                return -1;
            }
            printf("loaded http msg file [%s] size=[%d]\n", path, msg_one->len);
            msg->message_cnt++;

            if(msg->message_cnt >= MSGS_PER_POOL_MAX){
                printf("http msgs in a pool too many.\n");
                return -1;
            }
        }
    }

    if(!ind){
        msg = rte_zmalloc(NULL, sizeof(PROTOCOL_HTTP_MSG), 0);
        if(!msg){
            printf("init http_msg mem error.\n");
            return -1;
        }
        http_message_pools[0] = msg;
        msg_one = &msg->messages[0];
        msg_one->len = strlen(http_msg_req);
        msg_one->msg = rte_malloc(NULL, msg_one->len + 1, 0);
        if(!msg_one->msg){
            printf("failed to load http msg.\n");
            return -1;
        }
        strcpy(msg_one->msg, http_msg_req);
        msg_one->msg_iova = rte_malloc_virt2iova(msg_one->msg);
        if(msg_one->msg_iova == RTE_BAD_IOVA){
            printf("failed to load http msg iova.\n");
            return -1;
        }
        msg->message_cnt = 1;

        msg = rte_zmalloc(NULL, sizeof(PROTOCOL_HTTP_MSG), 0);
        if(!msg){
            printf("init http_msg mem error.\n");
            return -1;
        }
        http_message_pools[1] = msg;
        msg_one = &msg->messages[0];
        msg_one->len = strlen(http_msg_rsp);
        msg_one->msg = rte_malloc(NULL, msg_one->len + 1, 0);
        if(!msg_one->msg){
            printf("failed to load http msg.\n");
            return -1;
        }
        strcpy(msg_one->msg, http_msg_rsp);
        msg_one->msg_iova = rte_malloc_virt2iova(msg_one->msg);
        if(msg_one->msg_iova == RTE_BAD_IOVA){
            printf("failed to load http msg iova.\n");
            return -1;
        }
        msg->message_cnt = 1;
    }

    return 0;
}

char *protocol_http_msg_get(int pool_ind, int *msg_ind, int *msg_len, rte_iova_t *msg_iova)
{
    int i = *msg_ind;
    PROTOCOL_HTTP_MSG *pool = http_message_pools[pool_ind];
    PROTOCOL_HTTP_MSG_ONE *one = &pool->messages[i % pool->message_cnt];

    i = (i + 1) % pool->message_cnt;
    *msg_ind = i;

    *msg_len = one->len;

    if(msg_iova){
        *msg_iova = one->msg_iova;
    }

    return one->msg;
}

