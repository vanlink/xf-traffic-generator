#ifndef XG_GENERATOR_PROTOCOL_HTTP_H
#define XG_GENERATOR_PROTOCOL_HTTP_H
#include <stdint.h>
#include "cjson/cJSON.h"
#include "xf-stream.h"

extern int init_stream_http_client(cJSON *json_root, STREAM *stream);
extern int init_stream_http_server(cJSON *json_root, STREAM *stream);

#endif

