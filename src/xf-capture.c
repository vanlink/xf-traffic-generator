#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <pcap.h>

#include "cjson/cJSON.h"

#include "dpdkframework.h"

#include "xf-generator.h"
#include "xf-capture.h"

int g_is_capturing = 0;

static pcap_t *pcap_dead_handle[MAX_CORES_PER_ROLE] = {NULL};
static pcap_dumper_t *pcap_dumper[MAX_CORES_PER_ROLE] = {NULL};

static void get_pcap_name(int seq, char *buff)
{
    sprintf(buff, "%s/%s/capture-%s-%d.pcap", XF_BASE_DIR, unique_id, unique_id, seq);
}

int init_capture(cJSON *json_root)
{
    int i;
    char buff[256];
    cJSON *json;

    json = cJSON_GetObjectItem(json_root, "capture");
    if(!json){
        return 0;
    }
    json = cJSON_GetObjectItem(json, "enabled");
    if(!json){
        return 0;
    }
    if(!json->valueint){
        return 0;
    }
    printf("pcaket capture is on\n");

    g_is_capturing = 1;

    for(i=0;i<g_pkt_process_core_num;i++){
        pcap_dead_handle[i] = pcap_open_dead(1, 10000);
        if(!pcap_dead_handle[i]){
            printf("capture open pcap_dead_handle err.\n");
            return -1;
        }

        get_pcap_name(i, buff);
        pcap_dumper[i] = pcap_dump_open(pcap_dead_handle[i], buff);
        if(!pcap_dumper[i]) {
            printf("capture open pcap_dumper err.\n");
            return -1;
        }

        printf("pcaket capture [%s]\n", buff);
    }

    return 0;
}

int capture_do_capture(int seq, const char *packet_bytes, int pktlen)
{
    struct pcap_pkthdr h;
    struct timeval now;

    gettimeofday(&now, NULL);
    h.ts.tv_sec = now.tv_sec;
    h.ts.tv_usec = now.tv_usec;
    h.caplen = pktlen;
    h.len = pktlen;

    pcap_dump((u_char *)pcap_dumper[seq], &h, (const u_char *)packet_bytes);

    return 0;
}

void capture_close_all(void)
{
    int i;

    g_is_capturing = 0;

    for(i=0;i<g_pkt_process_core_num;i++){
        if(pcap_dumper[i]){
            pcap_dump_close(pcap_dumper[i]);
            pcap_dumper[i] = NULL;
        }
    }
}

