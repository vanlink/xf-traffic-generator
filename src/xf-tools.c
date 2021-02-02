#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <rte_malloc.h>

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

static int get_file_size(char *filename)
{
    struct stat statbuf;

    if(stat(filename, &statbuf) < 0){
        return -1;
    }

    return statbuf.st_size;
}

char *read_file_to_buff(char *filename, int *sizeout)
{
    int size = get_file_size(filename);
    char *buff;
    FILE *fp = NULL;
    int n;

    *sizeout = size;

    if(size < 1){
        return NULL;
    }

    buff = rte_zmalloc(NULL, size + 4, RTE_CACHE_LINE_SIZE);
    if(!buff){
        return NULL;
    }

    if(!(fp = fopen(filename, "rb"))){
        rte_free(buff);
        return NULL;
    }
    n = fread(buff, 1, size, fp);
    fclose(fp);

    if(n != size){
        rte_free(buff);
        return NULL;
    }

    return buff;
}

