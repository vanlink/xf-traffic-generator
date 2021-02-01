#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include "dkfw_timer.h"

#include "xf-simuser.h"
#include "xf-generator.h"
#include "xf-protocol-common.h"

static void timer_func_simuser_restart(struct timer_list *timer, unsigned long arg)
{
    int ret;
    SIMUSER *simuser = (SIMUSER *)arg;
    STREAM *stream = simuser->simusr_stream;

    simuser->simusr_timer_onfly = 0;

    if(simuser->simusr_state != SIMUSR_ST_RUNNING){
        return;
    }

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_ATTEMP);
    ret = protocol_common_send_one(stream, LWIP_MY_CPUID, simuser->simusr_ind);
    if(ret < 0){
        dkfw_start_timer(&g_generator_timer_bases[LWIP_MY_CPUID], timer, timer_func_simuser_restart, simuser, *g_elapsed_ms + SIMUSER_FAIL_INTERVAL_MS);
        simuser->simusr_timer_onfly = 1;
    }
}

int simuser_attemp(STREAM *stream, SIMUSER *simuser, int core)
{
    int ret;

    if(simuser->simusr_state != SIMUSR_ST_RUNNING){
        return 0;
    }

    STREAM_STATS_NUM_INC(stream, STREAM_STATS_TCP_CONN_ATTEMP);
    ret = protocol_common_send_one(stream, core, simuser->simusr_ind);
    if(ret < 0){
        if(simuser->simusr_timer_onfly){
            dkfw_stop_timer(&simuser->simusr_timer);
        }
        dkfw_start_timer(&g_generator_timer_bases[core], &simuser->simusr_timer, timer_func_simuser_restart, simuser, *g_elapsed_ms + SIMUSER_FAIL_INTERVAL_MS);
        simuser->simusr_timer_onfly = 1;
    }

    return 0;
}

int simuser_delayed_attemp(SIMUSER *simuser, int core)
{

    if(simuser->simusr_state != SIMUSR_ST_RUNNING){
        return 0;
    }

    if(!simuser->simusr_timer_onfly){
        dkfw_start_timer(&g_generator_timer_bases[core], &simuser->simusr_timer, timer_func_simuser_restart, simuser, *g_elapsed_ms + SIMUSER_FAIL_INTERVAL_MS);
        simuser->simusr_timer_onfly = 1;
    }

    return 0;
}

int simuser_start(STREAM *stream, SIMUSER *simuser, int core)
{

    simuser->simusr_state = SIMUSR_ST_RUNNING;

    return simuser_attemp(stream, simuser, core);
}

int simuser_stop(SIMUSER *simuser)
{
    if(simuser->simusr_timer_onfly){
        simuser->simusr_timer_onfly = 0;
        dkfw_stop_timer(&simuser->simusr_timer);
    }
    simuser->simusr_state = SIMUSR_ST_DISABLED;

    return 0;
}

