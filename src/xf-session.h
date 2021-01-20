#ifndef XG_GENERATOR_SESSION_H
#define XG_GENERATOR_SESSION_H
#include <stdint.h>
#include "llhttp.h"

typedef struct _session_info_t {
    void *pcb;
    void *stream;

    uint32_t proto_state :4,
             msg_ind     :7,
             spare1      :21;

    const char *msg;
    uint32_t msg_len;

    llhttp_t http_parser;
} SESSION;

extern int init_sessions(uint64_t cnt);
extern SESSION *session_get(void);
extern void session_free(SESSION *sess);

#endif

