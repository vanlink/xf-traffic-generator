#ifndef XG_GENERATOR_SESSION_H
#define XG_GENERATOR_SESSION_H
#include <stdint.h>
#include "lwip/altcp.h"

typedef struct _session_info_t {
    struct altcp_pcb *pcb;

    uint32_t type  :4,
             spare :28;

} SESSION;

extern int init_sessions(uint64_t cnt);
extern SESSION *session_get(void);
extern void session_free(SESSION *sess);

#endif

