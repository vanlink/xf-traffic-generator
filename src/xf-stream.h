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

typedef int (*STREAM_SEND_FUNC)(STREAM *, int core, uint64_t tsc);
typedef int (*STREAM_SESSION_NEW_FUNC)(SESSION *, STREAM *, void *pcb);
typedef int (*STREAM_CONNECTED_FUNC)(SESSION *, STREAM *, void *pcb);
typedef int (*STREAM_SENT_FUNC)(SESSION *, STREAM *, void *pcb, uint16_t);
typedef int (*STREAM_REMOTE_CLOSE_FUNC)(SESSION *, STREAM *, void *pcb);
typedef int (*STREAM_RECV_FUNC)(SESSION *, STREAM *, void *pcb, char *data, int datalen);
typedef int (*STREAM_ERR_FUNC)(SESSION *, STREAM *);

typedef struct _STREAM_t {
    int type;

    int local_address_ind;
    int remote_address_ind;
    int http_message_ind;

    int is_tls;
    int close_with_rst;

    uint64_t cps;  // conn per second
    uint64_t rpc;  // req per conn
    uint64_t ipr;  // interval per(between) req

    DKFW_CPS dkfw_cps[LWIP_CORES_MAX];

    STREAM_SEND_FUNC stream_send;
    STREAM_SESSION_NEW_FUNC stream_session_new;
    STREAM_CONNECTED_FUNC stream_connected;
    STREAM_SENT_FUNC stream_sent;
    STREAM_REMOTE_CLOSE_FUNC stream_remote_close;
    STREAM_RECV_FUNC stream_recv;
    STREAM_ERR_FUNC stream_err;
} STREAM;

extern int g_stream_cnt;
extern STREAM *g_streams[STREAM_CNT_MAX];

extern int init_streams(cJSON *json_root);

#endif

