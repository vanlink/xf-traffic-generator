#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_launch.h>
#include <rte_memory.h>
#include <rte_ethdev.h>

#include "cjson/cJSON.h"

#include "dkfw_stats.h"
#include "dkfw_memory.h"
#include "dkfw_ipc.h"

#include "xf-sharedmem.h"

#define ROUTE_START()       if (0) {
#define ROUTE(METHOD,URI)   } else if (strstr(uri,URI)==uri&&strcmp(METHOD,method)==0) {
#define ROUTE_GET(URI)      ROUTE("GET", URI) 
#define ROUTE_POST(URI)     ROUTE("POST", URI) 
#define ROUTE_END()         } else printf(\
                                "HTTP/1.1 500 Not Handled\r\n\r\n" \
                                "The server has no handler to the request.\r\n" \
                            );

typedef struct { char *name, *value; } header_t;

static header_t reqhdr[17] = { {"\0", "\0"} };
static int listenfd;
static int clientfd;
static char    *method, *uri, *qs, *prot;
static char    *payload;
static int      payload_size;
static char buf[65535];

static void route(void);

static void startServer(const char *port)
{
    struct addrinfo hints, *res, *p;

    // getaddrinfo for host
    memset (&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo( "127.0.0.1", port, &hints, &res) != 0)
    {
        perror ("getaddrinfo() error");
        exit(1);
    }
    // socket and bind
    for (p = res; p!=NULL; p=p->ai_next)
    {
        int option = 1;
        listenfd = socket (p->ai_family, p->ai_socktype, 0);
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
        if (listenfd == -1) continue;
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
    }
    if (p==NULL)
    {
        perror ("socket() or bind()");
        exit(1);
    }

    freeaddrinfo(res);

    // listen for incoming connections
    if ( listen (listenfd, 1024) != 0 )
    {
        perror("listen() error");
        exit(1);
    }
}

static char *request_header(const char* name)
{
    header_t *h = reqhdr;
    while(h->name) {
        if (strcmp(h->name, name) == 0) return h->value;
        h++;
    }
    return NULL;
}

static void respond(int n)
{
    int rcvd;
    rcvd=recv(clientfd, buf, 65535, 0);

    (void)n;

    if (rcvd<0)    // receive error
        fprintf(stderr,("recv() error\n"));
    else if (rcvd==0)    // receive socket closed
        fprintf(stderr,"Client disconnected upexpectedly.\n");
    else    // message received
    {
        buf[rcvd] = '\0';

        method = strtok(buf,  " \t\r\n");
        uri    = strtok(NULL, " \t");
        prot   = strtok(NULL, " \t\r\n"); 

        // fprintf(stderr, "\x1b[32m + [%s] %s\x1b[0m\n", method, uri);
        
        if ((qs = strchr(uri, '?')))
        {
            *qs++ = '\0'; //split URI
        } else {
            qs = uri - 1; //use an empty string
        }

        header_t *h = reqhdr;
        char *t = NULL, *t2;
        while(h < reqhdr+16) {
            char *k,*v,*t = NULL;
            k = strtok(NULL, "\r\n: \t"); if (!k) break;
            v = strtok(NULL, "\r\n");     while(*v && *v==' ') v++;
            h->name  = k;
            h->value = v;
            h++;
            // fprintf(stderr, "[H] %s: %s\n", k, v);
            t = v + 1 + strlen(v);
            if (t[1] == '\r' && t[2] == '\n') break;
        }
        t++; // now the *t shall be the beginning of user payload
        t2 = request_header("Content-Length"); // and the related header if there is  
        payload = t;
        payload_size = t2 ? atol(t2) : (rcvd-(t-buf));

        // call router
        route();
    }
}

static void serve_forever(const char *PORT)
{
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int slot=0;

    // Setting all elements to -1: signifies there is no client connected
    startServer(PORT);
    
    // Ignore SIGCHLD to avoid zombie threads
    signal(SIGCHLD,SIG_IGN);

    // ACCEPT connections
    while (1)
    {
        addrlen = sizeof(clientaddr);
        clientfd = accept (listenfd, (struct sockaddr *) &clientaddr, &addrlen);

        if (clientfd < 0)
        {
            perror("accept() error");
        }
        else
        {
            respond(slot);

            shutdown(clientfd, SHUT_RDWR);
            close(clientfd);
        }
    }
}

/* ----------------------------- above is http server ------------------------------------ */
static char listen_port[64] = {0};
static char unique[64] = {0};
static const char short_options[] = "u:p:";

static const struct option long_options[] = {
    {"unique", required_argument, NULL, 'u'},
    {"port", required_argument, NULL, 'p'},
    { 0, 0, 0, 0},
};

static SHARED_MEM_T *g_sm;

static int cmd_parse_args(int argc, char **argv)
{
    int opt;
    char **argvopt;
    int option_index;

    argvopt = argv;
    while((opt = getopt_long(argc, argvopt, short_options, long_options, &option_index)) != EOF) {
        switch(opt){
            case 'u':
                strcpy(unique, optarg);
                break;
            case 'p':
                strcpy(listen_port, optarg);
                break;
            default:
                break;
        }
    }

    if(!unique[0]){
        return -1;
    }

    return 0;
}

static void response_404(void)
{
    const char * msg= "HTTP/1.1 404 NOT FOUND\r\n\r\n";
    send(clientfd, msg, strlen(msg), 0);
}

static void response_json_header(int ct_len)
{
    char buff[1024];

    sprintf(buff, "HTTP/1.1 200 OK\r\n");
    send(clientfd, buff, strlen(buff), 0);
    sprintf(buff, "Content-Type: application/json\r\n");
    send(clientfd, buff, strlen(buff), 0);
    sprintf(buff, "Content-Length: %d\r\n\r\n", ct_len);
    send(clientfd, buff, strlen(buff), 0);
}

static void http_response_json_buff(const char *buff)
{
    int len = strlen(buff);

    response_json_header(len);
    send(clientfd, buff, len, 0);
}

static int http_response_json_json(cJSON *json_root)
{
    int ret = 0;
    const char *jsonstr = cJSON_Print(json_root);

    if(!jsonstr){
        ret = -1;
        goto exit;
    }

    http_response_json_buff(jsonstr);

exit:
    if(json_root){
        cJSON_Delete(json_root);
    }
    if(jsonstr){
        free((void *)jsonstr);
    }

    return ret;
}

static cJSON *make_json_basic(void)
{
    char buff[64];
    cJSON *json_root = cJSON_CreateObject();

    sprintf(buff, "%lu", g_sm->elapsed_ms);
    cJSON_AddItemToObject(json_root, "elapsed_ms", cJSON_CreateString(buff));

    cJSON_AddItemToObject(json_root, "pkt_core_cnt", cJSON_CreateNumber(g_sm->pkt_core_cnt));
    cJSON_AddItemToObject(json_root, "dispatch_core_cnt", cJSON_CreateNumber(g_sm->dispatch_core_cnt));
    cJSON_AddItemToObject(json_root, "streams_cnt", cJSON_CreateNumber(g_sm->streams_cnt));
    cJSON_AddItemToObject(json_root, "interface_cnt", cJSON_CreateNumber(g_sm->interface_cnt));

    return json_root;
}

static cJSON *make_json_cpu(void)
{
    cJSON *json_root = cJSON_CreateObject();
    cJSON *json_array;
    int i;
    DKFW_PROFILE *profiler;
    char buff[64];

    sprintf(buff, "%lu", g_sm->elapsed_ms);
    cJSON_AddItemToObject(json_root, "elapsed_ms", cJSON_CreateString(buff));

    json_array = cJSON_CreateArray();
    for(i=0;i<g_sm->pkt_core_cnt;i++){
        profiler = &g_sm->profile_pkt[i];
        cJSON_AddItemToArray(json_array, dkfw_profile_to_json(profiler));
    }
    cJSON_AddItemToObject(json_root, "profile_pkt", json_array);

    json_array = cJSON_CreateArray();
    for(i=0;i<g_sm->dispatch_core_cnt;i++){
        profiler = &g_sm->profile_dispatch[i];
        cJSON_AddItemToArray(json_array, dkfw_profile_to_json(profiler));
    }
    cJSON_AddItemToObject(json_root, "profile_dispatch", json_array);

    return json_root;
}

static cJSON *make_json_stat_streams(void)
{
    char buff[64];
    cJSON *json_root = cJSON_CreateObject();
    int i;
    cJSON *json_array = cJSON_CreateArray();

    sprintf(buff, "%lu", g_sm->elapsed_ms);
    cJSON_AddItemToObject(json_root, "elapsed_ms", cJSON_CreateString(buff));

    for(i=0;i<g_sm->streams_cnt;i++){
        cJSON_AddItemToArray(json_array, dkfw_stats_to_json(&g_sm->stats_streams[i].stats_stream));
    }
    cJSON_AddItemToObject(json_root, "streams", json_array);

    return json_root;
}

static cJSON *make_json_interfaces(void)
{
     char buff[64];
    cJSON *json_root = cJSON_CreateObject();
    cJSON *json_array = cJSON_CreateArray();
    int i;
    struct rte_eth_stats port_stats;
    cJSON *json_item;

    sprintf(buff, "%lu", g_sm->elapsed_ms);
    cJSON_AddItemToObject(json_root, "elapsed_ms", cJSON_CreateString(buff));

    for(i=0;i<g_sm->interface_cnt;i++){
        memset(&port_stats, 0, sizeof(port_stats));
        rte_eth_stats_get(i, &port_stats);
        json_item = cJSON_CreateObject();
        sprintf(buff, "%lu", port_stats.ipackets);
        cJSON_AddItemToObject(json_item, "ipackets", cJSON_CreateString(buff));
        sprintf(buff, "%lu", port_stats.opackets);
        cJSON_AddItemToObject(json_item, "opackets", cJSON_CreateString(buff));
        sprintf(buff, "%lu", port_stats.ibytes * 8);
        cJSON_AddItemToObject(json_item, "ibits", cJSON_CreateString(buff));
        sprintf(buff, "%lu", port_stats.obytes * 8);
        cJSON_AddItemToObject(json_item, "obits", cJSON_CreateString(buff));
        sprintf(buff, "%lu", port_stats.imissed);
        cJSON_AddItemToObject(json_item, "imissed", cJSON_CreateString(buff));
        sprintf(buff, "%lu", port_stats.ierrors);
        cJSON_AddItemToObject(json_item, "ierrors", cJSON_CreateString(buff));
        sprintf(buff, "%lu", port_stats.oerrors);
        cJSON_AddItemToObject(json_item, "oerrors", cJSON_CreateString(buff));
        sprintf(buff, "%lu", port_stats.rx_nombuf);
        cJSON_AddItemToObject(json_item, "rx_nombuf", cJSON_CreateString(buff));
        cJSON_AddItemToArray(json_array, json_item);
    }
    cJSON_AddItemToObject(json_root, "interfaces", json_array);

    return json_root;
}

static void route(void)
{
    int retval = 0;

    ROUTE_START()

    ROUTE_GET("/")
    {
        if(uri){
            if(!strcasecmp(uri, "/get_stat_lwip")){
            }else if(!strcasecmp(uri, "/get_stat_generator")){
            }else if(!strcasecmp(uri, "/get_stat_dispatch")){
            }else if(!strcasecmp(uri, "/get_stat_stream")){
                http_response_json_json(make_json_stat_streams());
            }else if(!strcasecmp(uri, "/get_cpu")){
                http_response_json_json(make_json_cpu());
            }else if(!strcasecmp(uri, "/get_basic")){
                http_response_json_json(make_json_basic());
            }else if(!strcasecmp(uri, "/get_interface")){
                http_response_json_json(make_json_interfaces());
            }else{
                retval = -1;
            }
        }

        if(retval < 0){
            response_404();
        }
    }

    ROUTE_END()
}

int main(int argc, char **argv)
{
    int ret = 0;

    if(cmd_parse_args(argc, argv) < 0){
        printf("invalid arg.\n");
        ret = -1;
        goto exit;
    }

    printf("daemon u=[%s] port=[%s]\n", unique, listen_port);

    if(dkfw_ipc_client_init(unique, 0) < 0){
        printf("dpdk init err.\n");
        ret = -1;
        goto exit;
    }

    g_sm = (SHARED_MEM_T *)dkfw_global_sharemem_get();
    if(!g_sm){
        printf("sm get err.\n");
        ret = -1;
        goto exit;

    }

    printf("===== xf-generator daemon ok =====\n");
    fflush(stdout);

    serve_forever(listen_port);

exit:

    dkfw_ipc_client_exit();

    return ret;
}

