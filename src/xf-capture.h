#ifndef XG_GENERATOR_CAPTURE_H
#define XG_GENERATOR_CAPTURE_H
#include <stdint.h>
#include "cjson/cJSON.h"

extern int g_is_capturing;

extern int init_capture(cJSON *json_root);
extern int capture_do_capture(int seq, const char *packet_bytes, int pktlen);
extern void capture_close_all(void);
#endif

