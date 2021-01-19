#ifndef XG_GENERATOR_STREAM_H
#define XG_GENERATOR_STREAM_H
#include <stdint.h>
#include "cjson/cJSON.h"
#include "dkfw_cps.h"
#include "lwip/opt.h"

#define STREAM_CNT_MAX 32

#define STREAM_TYPE_HTTPCLIENT 0
#define STREAM_TYPE_HTTPSERVER 1

typedef struct _STREAM_t STREAM;

typedef int (*STREAM_SEND_FUNC)(STREAM *, int, uint64_t);

typedef struct _STREAM_t {
    int type;

    int local_address_ind;
    int remote_address_ind;
    int http_message_ind;

    uint64_t cps;  // conn per second
    uint64_t rpc;  // req per conn
    uint64_t ipr;  // interval per(between) req

    DKFW_CPS dkfw_cps[LWIP_CORES_MAX];

    STREAM_SEND_FUNC send;
} STREAM;

extern int g_stream_cnt;
extern STREAM *g_streams[STREAM_CNT_MAX];

extern int init_streams(cJSON *json_root);

#endif

