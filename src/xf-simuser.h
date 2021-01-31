#ifndef XG_GENERATOR_SIMUSER_H
#define XG_GENERATOR_SIMUSER_H
#include <stdint.h>
#include "dkfw_timer.h"

#define SIMUSER_FAIL_INTERVAL_MS 3000

enum {
    SIMUSR_ST_DISABLED,
    SIMUSR_ST_RUNNING,

    SIMUSR_ST_MAX
};

typedef struct _STREAM_t STREAM;

typedef struct _SIMUSER_t {
    int simusr_ind;
    uint8_t simusr_state;

    STREAM *simusr_stream;

    void *pcb;

    uint8_t simusr_timer_onfly;
    struct timer_list simusr_timer;
}SIMUSER;

extern int simuser_start(STREAM *stream, SIMUSER *simuser, int core);
extern int simuser_stop(SIMUSER *simuser);
extern int simuser_attemp(STREAM *stream, SIMUSER *simuser, int core);
extern int simuser_delayed_attemp(SIMUSER *simuser, int core);

#endif

