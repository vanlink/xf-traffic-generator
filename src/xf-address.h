#ifndef XG_GENERATOR_ADDRESS_H
#define XG_GENERATOR_ADDRESS_H
#include <stdint.h>
#include "cjson/cJSON.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"

extern int init_addresses(cJSON *json_root);
extern struct netif *local_address_get(int ind, int core, int force_next);
extern ip_addr_t *remote_address_get(int ind, int core, int *port);
extern int local_address_pool_is_ipv6(int ind);
extern int remote_address_pool_is_ipv6(int ind);

#endif

