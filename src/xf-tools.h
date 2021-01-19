#ifndef XG_GENERATOR_TOOLS_H
#define XG_GENERATOR_TOOLS_H
#include <stdint.h>
#include <netinet/in.h>

extern int str_to_ipv4(char *str, uint32_t *ipv4);
extern int str_to_ipv6(char *str, struct in6_addr *addr);
extern char *read_file_to_buff(char *filename, int *sizeout);

#endif

