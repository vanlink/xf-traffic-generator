#ifndef XG_GENERATOR_PROTOCOL_HTTP_MSG_H
#define XG_GENERATOR_PROTOCOL_HTTP_MSG_H
#include <stdint.h>
#include "cjson/cJSON.h"

extern int init_protocol_http_msg(cJSON *json_root);
extern char *protocol_http_msg_get(int pool_ind, int *msg_ind, int *msg_len);
#endif

