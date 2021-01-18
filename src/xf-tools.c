#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "xf-tools.h"

int str_to_ipv4(char *str, uint32_t *ipv4)
{
    struct in_addr addr;

    if(!inet_pton(AF_INET, str, &addr)){
        return -1;
    }
    *ipv4 = htonl(addr.s_addr);
    return 0;
}

int str_to_ipv6(char *str, struct in6_addr *addr)
{
    if(!inet_pton(AF_INET6, str, addr)){
        return -1;
    }

    return 0;
}

