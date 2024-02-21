#ifndef XG_GENERATOR_STREAM_H
#define XG_GENERATOR_STREAM_H
#include <stdint.h>
#include "cjson/cJSON.h"

#include "dkfw_cps.h"
#include "dkfw_stats.h"

#include "lwip/opt.h"
#include "lwip/netif.h"
#include "lwip/altcp_tls.h"

#include "xf-session.h"
#include "xf-simuser.h"

#define STREAM_CNT_MAX 32

#define STREAM_TYPE_HTTPCLIENT 0
#define STREAM_TYPE_HTTPSERVER 1

enum {
    STREAM_STATS_TCP_CONN_ATTEMP,
    STREAM_STATS_TCP_CONN_SUCC,
    STREAM_STATS_TCP_CLOSE_LOCAL,
    STREAM_STATS_TCP_CLOSE_REMOTE_FIN,
    STREAM_STATS_TCP_CLOSE_REMOTE_RST,
    STREAM_STATS_TCP_CLOSE_TIMEOUT,
    STREAM_STATS_TCP_CLOSE_ERROR,

    STREAM_STATS_SESSION_TIMEOUT,

    STREAM_STATS_HTTP_REQUEST,
    STREAM_STATS_HTTP_RESPONSE,

    STREAM_STATS_MAX
};

typedef struct _STREAM_t STREAM;
typedef struct _session_info_t SESSION;

typedef int (*STREAM_LISTEN_FUNC)(STREAM *);
typedef int (*STREAM_SEND_FUNC)(STREAM *, int core, uint64_t tsc, uint64_t ms);
typedef int (*STREAM_SESSION_NEW_FUNC)(SESSION *, STREAM *, void *pcb);
typedef int (*STREAM_CONNECTED_FUNC)(SESSION *, STREAM *, void *pcb);
typedef int (*STREAM_SENT_FUNC)(SESSION *, STREAM *, void *pcb, uint16_t);
typedef int (*STREAM_REMOTE_CLOSE_FUNC)(SESSION *, STREAM *, void *pcb);
typedef int (*STREAM_RECV_FUNC)(SESSION *, STREAM *, void *pcb, char *data, int datalen);
typedef int (*STREAM_ERR_FUNC)(SESSION *, STREAM *);

typedef struct _STREAM_CORE_t {
    SIMUSER *simusers;
    int simuser_active_cnt;
    int simuser_all_cnt;

    DKFW_CPS stream_cps;
} STREAM_CORE;

typedef struct _STREAM_t {
    int type;

    int local_address_ind;
    int local_address_in_pool_cnt;

    int remote_address_ind;
    int http_message_ind;

    int stream_is_simuser;
    int stream_is_ipv6;
    int close_with_rst;

    int stream_is_tls;
    struct altcp_tls_config *tls_client_config;
    struct altcp_tls_config *tls_server_config;

    char listen_ip[64];
    struct netif *listen_net_if;
    uint16_t listen_port;

    uint64_t rpc;  // reqs per conn
    uint64_t ipr;  // interval per req(between reqs), in sec

    uint64_t session_timeout_ms;

    DKFW_STATS *stream_stat;

    STREAM_SEND_FUNC stream_send;
    STREAM_SEND_FUNC stream_send_back;
    STREAM_SESSION_NEW_FUNC stream_session_new;
    STREAM_CONNECTED_FUNC stream_connected;
    STREAM_SENT_FUNC stream_sent;
    STREAM_REMOTE_CLOSE_FUNC stream_remote_close;
    STREAM_RECV_FUNC stream_recv;
    STREAM_ERR_FUNC stream_err;
    STREAM_LISTEN_FUNC stream_listen;

    STREAM_CORE stream_cores[MAX_CORES_PER_ROLE];
} STREAM;

extern int g_stream_cnt;
extern STREAM *g_streams[STREAM_CNT_MAX];

extern int init_streams(cJSON *json_root);

extern int streams_stop(void);
extern int streams_start(void);

#define STREAM_STATS_NUM_INC(stream,id)             DKFW_STATS_CNT_INCR(stream->stream_stat,id,RTE_PER_LCORE(g_cpu_id))

#endif

