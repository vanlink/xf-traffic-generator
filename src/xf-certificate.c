#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_malloc.h>

#include "cjson/cJSON.h"

#include "xf-tools.h"
#include "xf-protocol-http-msg.h"

#define CERTIFICATES_MAX 32

typedef struct _CERTIFICATE_t {
    char *certificate;
    int certificate_len;

    char *key;
    int key_len;

    char password[128];
} CERTIFICATE;

static int certificate_num = 0;
static CERTIFICATE certificates[CERTIFICATES_MAX];

int init_certificate(cJSON *json_root)
{
    cJSON *json_messages = cJSON_GetObjectItem(json_root, "certificates");
    cJSON *json_array_item;
    CERTIFICATE *cert;
    cJSON *json;

    memset(certificates, 0, sizeof(certificates));

    cJSON_ArrayForEach(json_array_item, json_messages){
        cert = &certificates[certificate_num];

        json = cJSON_GetObjectItem(json_array_item, "certificate");
        if(!json){
            printf("no certificate file.\n");
            return -1;
        }
        cert->certificate = read_file_to_buff(json->valuestring, &cert->certificate_len);
        if(!cert->certificate){
            printf("can not open certificate file [%s].\n", json->valuestring);
            return -1;
        }

        json = cJSON_GetObjectItem(json_array_item, "key");
        if(!json){
            printf("no key file.\n");
            return -1;
        }
        cert->key = read_file_to_buff(json->valuestring, &cert->key_len);
        if(!cert->key){
            printf("can not open key file [%s].\n", json->valuestring);
            return -1;
        }

        json = cJSON_GetObjectItem(json_array_item, "password");
        if(json){
            strcpy(cert->password, json->valuestring);
        }

        certificate_num++;
        if(certificate_num >= CERTIFICATES_MAX){
            printf("too many certificates.\n");
            return -1;
        }
    }

    printf("%d certificates loaded.\n", certificate_num);

    return 0;
}

int certificate_get(int ind, char **pcert, int *cert_len, char **pkey, int *key_len, char **ppassword)
{
    CERTIFICATE *cert;

    if(ind >= certificate_num){
        return -1;
    }

    cert = &certificates[ind];

    *pcert = cert->certificate;
    *cert_len = cert->certificate_len;
    *pkey = cert->key;
    *key_len = cert->key_len;
    *ppassword = cert->password;

    return 0;
}

