#ifndef XG_GENERATOR_PROTOCOL_COMMON_H
#define XG_GENERATOR_PROTOCOL_COMMON_H
#include <stdint.h>
#include "xf-stream.h"

extern int protocol_common_send(STREAM *stream, int core, uint64_t tsc, uint64_t ms);
extern int protocol_common_listen(STREAM *stream);
#endif

