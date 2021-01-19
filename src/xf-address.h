#ifndef XG_GENERATOR_ADDRESS_H
#define XG_GENERATOR_ADDRESS_H
#include <stdint.h>
#include "cjson/cJSON.h"

#define LOCAL_ADDRESS_TYPE_PORT_RR 0
#define LOCAL_ADDRESS_TYPE_IP_RR   1

extern int init_addresses(cJSON *json_root);

#endif

