#ifndef XG_GENERATOR_SESSION_H
#define XG_GENERATOR_SESSION_H
#include <stdint.h>
#include <rte_common.h>
#include "llhttp.h"
#include "dkfw_timer.h"

typedef struct _session_info_t {
    void *pcb;
    void *stream;

    uint32_t proto_state :4,
             msg_ind     :7,
             response_ok :1,
             msgs_left   :8,
             timer_msg_interval_onfly    :1,
             timer_session_timeout_onfly :1,
             spare1      :10;

    uint32_t simuser_ind;

#if LWIP_TX_ZERO_COPY
    rte_iova_t session_msg_iova;
#endif
    const char *session_msg;
    uint32_t msg_len;

    struct timer_list timer_session_timeout;
    struct timer_list timer_msg_interval;

    llhttp_t http_parser;
} SESSION;

extern int init_sessions(uint64_t cnt);
extern SESSION *session_get(void);
extern void session_free(SESSION *sess);

#endif

