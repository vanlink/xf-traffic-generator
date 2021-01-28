#ifndef XG_GENERATOR_NETWORK_H
#define XG_GENERATOR_NETWORK_H
#include <stdint.h>
#include <netinet/in.h>
#include "cjson/cJSON.h"

#define USE_TX_BUFFER 0

extern int init_networks(cJSON *json_root);
extern int interface_tx_buffer_flush(int seq);

#endif

