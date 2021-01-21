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

UNIQUE = "unknown"
PORT = 60000

DIR_UNIQUE = None

PACKET_CORE_CNT = 1
DISPATCH_CORE_CNT = 1
STREAM_CNT = 1

CPU_PACKET_LAST = [None] * 32
CPU_DISPATCH_LAST = [None] * 32

def get_log_filename_packet_cpu(seq):
    filename = "cpu-packet-%s.stat" % (seq)
    return os.path.join(DIR_UNIQUE, filename)

def get_log_filename_dispatch_cpu(seq):
    filename = "cpu-dispatch-%s.stat" % (seq)
    return os.path.join(DIR_UNIQUE, filename)

def get_log_filename_stream(stream_seq, core_seq):
    if core_seq >= 0:
        filename = "stream-%s-core-%s.stat" % (stream_seq, core_seq)
    else:
        filename = "stream-%s-core-%s.stat" % (stream_seq, "all")
    return os.path.join(DIR_UNIQUE, filename)

def write_log_to_file(filename, data):
    try:
        with open(filename, "a") as f:
            f.write(data)
    except Exception as e:
        print(e)

def get_dict_from_url(url):
    urlall = "http://127.0.0.1:%s%s" % (PORT, url)
    r = None
    try:
        r = requests.get(urlall, timeout=2)
    except:
        return None
    if not r:
        return None
    if not r.text:
        return None
    ret = None
    try:
        ret = json.loads(r.text)
    except:
        return None
    return ret

def do_log_cpu_one(now, last, filename, ms):
    diff = StatDict(now) - StatDict(last)
    diff_work = 0
    diff_all = diff["all_time"]

    data = "%-20s" % (ms)
    for i in diff["items_time"]:
        diff_work = diff_work + i
        item_cpu = i * 100 / diff_all
        data = data + "%-10.2f" % (item_cpu)
    all_cpu = diff_work * 100 / diff_all
    data = data + "%-10.2f\n" % (all_cpu)

    write_log_to_file(filename, data)

def do_log_cpu():
    r = get_dict_from_url("/get_cpu")
    if not r:
        return

    ms = r["elapsed_ms"]

    for i in range(0, PACKET_CORE_CNT):
        filename = get_log_filename_packet_cpu(i)
        now = r["profile_pkt"][i]
        if CPU_PACKET_LAST[i]:
            do_log_cpu_one(now, CPU_PACKET_LAST[i], filename, ms)
        CPU_PACKET_LAST[i] = now

    for i in range(0, DISPATCH_CORE_CNT):
        filename = get_log_filename_dispatch_cpu(i)
        now = r["profile_dispatch"][i]
        if CPU_DISPATCH_LAST[i]:
            do_log_cpu_one(now, CPU_DISPATCH_LAST[i], filename, ms)
        CPU_DISPATCH_LAST[i] = now

# ------------------------------ main ------------------------------
if __name__ != '__main__':
    sys.exit(0)

try:
    kvs, leftargs = getopt.getopt(sys.argv[1:],
                                  "u:p:", [
                                      "unique=",
                                      "port=",
                                   ]
                                  )
    for k, v in kvs:
        if k in ("-u", "--unique"):
            UNIQUE = v
        elif k in ("-p", "--port"):
            PORT = int(v)
except Exception as e:
    print("Invalid args.")
    sys.exit(-1)

print("connect to u=[%s] p=[%s]" % (UNIQUE, PORT))

if not UNIQUE:
    print("Invalid UNIQUE.")
    sys.exit(-1)

os.system("mkdir -p %s" % (DIR_LOG_BASE))

DIR_UNIQUE = os.path.join(DIR_LOG_BASE, UNIQUE)
print("DIR_UNIQUE is [%s]" % (DIR_UNIQUE))
os.system("rm -rf %s" % (DIR_UNIQUE))
os.system("mkdir -p %s" % (DIR_UNIQUE))

r = get_dict_from_url("/get_basic")
PACKET_CORE_CNT = r["pkt_core_cnt"]
DISPATCH_CORE_CNT = r["dispatch_core_cnt"]
STREAM_CNT = r["streams_cnt"]

print("pkt=[%s] dispatch=[%s] stream=[%s]" % (PACKET_CORE_CNT, DISPATCH_CORE_CNT, STREAM_CNT))

cnt = 0
while True:
    time.sleep(1)
    cnt = cnt + 1
    if cnt % 5 == 0:
        do_log_cpu()
