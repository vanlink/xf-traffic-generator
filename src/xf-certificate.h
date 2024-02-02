#ifndef XG_GENERATOR_CERTIFICATE_H
#define XG_GENERATOR_CERTIFICATE_H
#include <stdint.h>
#include "cjson/cJSON.h"

extern int init_certificate(cJSON *json_root);
extern int certificate_get(int ind, char **pcert, int *cert_len, char **pkey, int *key_len, char **ppassword, char **pcert_path, char **pkey_path);

#endif

