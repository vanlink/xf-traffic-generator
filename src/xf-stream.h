#ifndef XG_GENERATOR_STREAM_H
#define XG_GENERATOR_STREAM_H
#include <stdint.h>
#include "cjson/cJSON.h"
#include "dkfw_cps.h"
#include "lwip/opt.h"
#include "xf-session.h"

#define STREAM_CNT_MAX 32

#define STREAM_TYPE_HTTPCLIENT 0
#define STREAM_TYPE_HTTPSERVER 1

typedef struct _STREAM_t STREAM;
typedef struct _session_info_t SESSION;

typedef int (*STREAM_SEND_FUNC)(STREAM *, int, uint64_t);
typedef int (*STREAM_SESSION_NEW_FUNC)(SESSION *, STREAM *);
typedef int (*STREAM_CONNECTED_FUNC)(SESSION *, STREAM *);
typedef int (*STREAM_SENT_FUNC)(SESSION *, STREAM *, uint16_t);

typedef struct _STREAM_t {
    int type;

    int local_address_ind;
    int remote_address_ind;
    int http_message_ind;

    int is_tls;

    uint64_t cps;  // conn per second
    uint64_t rpc;  // req per conn
    uint64_t ipr;  // interval per(between) req

    DKFW_CPS dkfw_cps[LWIP_CORES_MAX];

    STREAM_SEND_FUNC send;
    STREAM_SESSION_NEW_FUNC session_new;
    STREAM_CONNECTED_FUNC connected;
    STREAM_SENT_FUNC sent;
} STREAM;

extern int g_stream_cnt;
extern STREAM *g_streams[STREAM_CNT_MAX];

extern int init_streams(cJSON *json_root);

#endif

