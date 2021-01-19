#ifndef XG_GENERATOR_SESSION_H
#define XG_GENERATOR_SESSION_H
#include <stdint.h>
#include "xf-stream.h"

#define SESSION_TYPE_HTTP_CLIENT 0
#define SESSION_TYPE_HTTP_SERVER 1

typedef struct _session_info_t {
    void *pcb;
    STREAM *stream;
} SESSION;

extern int init_sessions(uint64_t cnt);
extern SESSION *session_get(void);
extern void session_free(SESSION *sess);

#endif

