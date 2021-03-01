#!/usr/bin/python
import os
import sys
import getopt
import traceback
import json
import time
import copy
import pprint
import requests

from libtools import *

UNIQUE = "xxxxxx"
CONF = "./conf.json"

def fill_conf_json(confjson):
    clientcnt = 0
    servercnt = 0
    cpsall = 0
    concurrall = 0

    for stream in confjson.get("streams", []):
        if stream["type"].lower() == "httpclient":
            clientcnt += 1
            rpc = stream.get("rpc", 1)
            rpc = rpc or 1
            ipr = stream.get("ipr", 0)
            cpsconf = stream.get("cps")
            cpsone = 0
            if isinstance(cpsconf, int):
                cpsone = cpsconf
            elif isinstance(cpsconf, list):
                for cpsstep in cpsconf:
                    if cpsstep.get("start", 0) > cpsone:
                        cpsone = cpsstep.get("start", 0)
                    if cpsstep.get("end", 0) > cpsone:
                        cpsone = cpsstep.get("end", 0)
            cpsall += cpsone
            if ipr:
                concurrall += rpc * ipr * cpsone
        elif stream["type"].lower() == "httpserver":
            servercnt += 1

    if clientcnt and servercnt:
        cpsall = cpsall * 105 // 100
        concurrall *= 2
        concurrall = concurrall * 105 // 100
        if concurrall < 4096:
            concurrall = 4096
    elif clientcnt:
        cpsall = cpsall * 105 // 100
        concurrall = concurrall * 105 // 100
        if concurrall < 4096:
            concurrall = 4096
    else:
        concurrall = confjson.get("sessions", 0)
        concurrall = concurrall * 105 // 100
        if concurrall < 65536:
            concurrall = 65536

    stpool = confjson.setdefault("mem_static_pools", {})
    stpool.setdefault("pcb-altcp", concurrall)
    stpool.setdefault("pcb-tcp", concurrall + 2 * cpsall)  # 2msl * cps
    stpool.setdefault("tcp-seg", 16384)
    stpool.setdefault("pbuf", 16384)
    stpool.setdefault("pbuf-pool", 4096)
    stpool.setdefault("pcb-tcp-listen", 4096)
    stpool.setdefault("arp-q", 2048)
    stpool.setdefault("nd6-q", 2048)
    stpool.setdefault("sys-timeout", 2048)

    confjson.setdefault("sessions", concurrall)

    if "mem_step_pools" not in confjson:
        confjson["mem_step_pools"] = [
            {"size":2048, "cnt":16384},
            {"size":4096, "cnt":4096},
            {"size":8192, "cnt":2048},
            {"size":16384, "cnt":1024},
            {"size":32768, "cnt":512},
            {"size":65536, "cnt":256}
        ]

# ------------------------------ main ------------------------------
if __name__ != '__main__':
    sys.exit(0)

try:
    kvs, leftargs = getopt.getopt(sys.argv[1:],
                                  "u:c:", [
                                      "unique=",
                                      "conf=",
                                   ]
                                  )
    for k, v in kvs:
        if k in ("-u", "--unique"):
            UNIQUE = v
        elif k in ("-c", "--conf"):
            CONF = v
except Exception as e:
    print("Invalid args.")
    sys.exit(-1)

print("start xf-generator to u=[%s] c=[%s]" % (UNIQUE, CONF))

if not UNIQUE:
    print("Invalid UNIQUE.")
    sys.exit(-1)

pidsnow = get_unique_pids(UNIQUE)
print(pidsnow)

if pidsnow:
    print("same unique exists already.")
    sys.exit(-1)

lport = None
for port in range(60000, 65000):
    if not is_local_port_in_use(port):
        lport = port
        break
if not lport:
    print("can not select local port.")
    sys.exit(-1)

os.system("mkdir -p %s" % (DIR_LOG_BASE))

DIR_UNIQUE = os.path.join(DIR_LOG_BASE, UNIQUE)
print("DIR_UNIQUE is [%s]" % (DIR_UNIQUE))
os.system("rm -rf %s" % (DIR_UNIQUE))
os.system("mkdir -p %s" % (DIR_UNIQUE))

conjson = None
with open(CONF, "r") as f:
    try:
        conjson = json.load(f)
    except:
        pass
if not conjson:
    print("invalid config json file.")
    sys.exit(-1)
fill_conf_json(conjson)
conffinal = os.path.join(DIR_UNIQUE, CONF_FILE_NAME)
with open(conffinal, "w") as f:
    json.dump(conjson, f, indent=4)
if not os.path.isfile(conffinal):
    print("can not gen config json file.")
    sys.exit(-1)

outfile = os.path.join(DIR_UNIQUE, MAIN_EXEC_OUT)
cmd = "nohup %s --unique=%s -c %s > %s 2>&1 &" % (MAIN_EXEC_NAME, UNIQUE, conffinal, outfile)
print("====== start main =======")
print(cmd)
os.system(cmd)
for i in range(0, 60):
    time.sleep(1)
    print(".", end='', flush=True)
    if ok_str_found(outfile):
        print()
        break
else:
    print("start fail.")
    sys.exit(-1)

outfile = os.path.join(DIR_UNIQUE, DAEMON_EXEC_OUT)
cmd = "nohup %s --unique=%s -p %s > %s 2>&1 &" % (DAEMON_EXEC_NAME, UNIQUE, lport, outfile)
print("====== start daemon =======")
print(cmd)
os.system(cmd)
for i in range(0, 60):
    time.sleep(1)
    print(".", end='', flush=True)
    if ok_str_found(outfile):
        print()
        break
else:
    print("start fail.")
    sys.exit(-1)

outfile = os.path.join(DIR_UNIQUE, DAEMON_PY_OUT)
cmd = "nohup python3 %s --unique=%s -p %s > %s 2>&1 &" % (DAEMON_PY_NAME, UNIQUE, lport, outfile)
print("====== start daemon =======")
print(cmd)
os.system(cmd)
for i in range(0, 60):
    time.sleep(1)
    print(".", end='', flush=True)
    if ok_str_found(outfile):
        print()
        break
else:
    print("start fail.")
    sys.exit(-1)

print("====== ALL DONE p=[%s] =======" % (lport))
