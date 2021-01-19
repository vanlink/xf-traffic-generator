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
#include "xf-stream.h"
#include "xf-protocol-http.h"

static int protocol_http_send_one(STREAM *stream, int core)
{
    return 0;
}

int protocol_http_send(STREAM *stream, int core, uint64_t tsc)
{
    uint64_t send_cnt = dkfw_cps_get(&stream->dkfw_cps[core], tsc);

    if(!send_cnt){
        return 0;
    }

    protocol_http_send_one(stream, core);

    return 0;
}

