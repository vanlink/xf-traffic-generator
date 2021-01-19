#ifndef XG_GENERATOR_PROTOCOL_HTTP_H
#define XG_GENERATOR_PROTOCOL_HTTP_H
#include <stdint.h>
#include "xf-stream.h"

extern int protocol_http_send(STREAM *stream, int core, uint64_t tsc);

#endif

