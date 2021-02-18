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
INTERFACE_CNT = 1

CPU_PACKET_LAST = [None] * 64
CPU_DISPATCH_LAST = [None] * 64

STATS_STREAM_LAST = None
STATS_STREAM_SUM_LAST = [None] * 64

STATS_INTERFACES_LAST = None

def get_log_filename_interface(seq):
    filename = "interface-%s.stat" % (seq)
    return os.path.join(DIR_UNIQUE, filename)

def get_log_filename_interface_rate(seq):
    filename = "interface-%s-rate.stat" % (seq)
    return os.path.join(DIR_UNIQUE, filename)

def get_log_filename_packet_cpu(seq):
    filename = "cpu-packet-%s.stat" % (seq)
    return os.path.join(DIR_UNIQUE, filename)

def get_log_filename_packet_cpu_loopcnt(seq):
    filename = "cpu-packet-loopcnt-%s.stat" % (seq)
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

def get_log_filename_stream_rate(stream_seq, core_seq):
    if core_seq >= 0:
        filename = "stream-%s-core-%s-rate.stat" % (stream_seq, core_seq)
    else:
        filename = "stream-%s-core-%s-rate.stat" % (stream_seq, "all")
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

    data = data + " | "

    all_cpu = diff_work * 100 / diff_all
    data = data + "%-6.2f" % (all_cpu)

    if diff.get("singles_time"):
        data = data + " | "
        for i in diff["singles_time"]:
            item_cpu = i * 100 / diff_all
            a = "%.2f" % (item_cpu)
            b = "(%.2f)" % (item_cpu * 100 / all_cpu)
            data = data + "%-15s" % (a + b)

    data = data + "\n"

    write_log_to_file(filename, data)

def do_log_cpu_loopcnt_one(now, last, filename, ms):
    diff = StatDict(now) - StatDict(last)
    
    data = "%-20s" % (ms)
    
    for i in range(0, len(diff["items_time"])):
        tscs = diff["items_time"][i]
        loops = diff["items_time_cnt"][i]
        if loops:
            tpl = tscs // loops
        else:
            tpl = 0
        data = data + "%-10s" % (tpl)
    
    data = data + " | "
    
    for i in range(0, len(diff["singles_time"])):
        tscs = diff["singles_time"][i]
        loops = diff["singles_time_cnt"][i]
        if loops:
            tpl = tscs // loops
        else:
            tpl = 0
        data = data + "%-10s" % (tpl)

    data = data + "\n"
    write_log_to_file(filename, data)

def do_log_cpu():
    r = get_dict_from_url("/get_cpu")
    if not r:
        return

    ms = r["elapsed_ms"]

    for i in range(0, PACKET_CORE_CNT):
        filename = get_log_filename_packet_cpu(i)
        filename_loopcnt = get_log_filename_packet_cpu_loopcnt(i)
        now = r["profile_pkt"][i]
        if CPU_PACKET_LAST[i]:
            do_log_cpu_one(now, CPU_PACKET_LAST[i], filename, ms)
            do_log_cpu_loopcnt_one(now, CPU_PACKET_LAST[i], filename_loopcnt, ms)
        CPU_PACKET_LAST[i] = now

    for i in range(0, DISPATCH_CORE_CNT):
        filename = get_log_filename_dispatch_cpu(i)
        now = r["profile_dispatch"][i]
        if CPU_DISPATCH_LAST[i]:
            do_log_cpu_one(now, CPU_DISPATCH_LAST[i], filename, ms)
        CPU_DISPATCH_LAST[i] = now

def get_stream_ms(streamdict):
    return int(streamdict["elapsed_ms"])

def get_stream_item(streamdict, stream_ind, core):
    return streamdict["streams"][stream_ind]["core_%s" % (core)]

def do_log_stream_core_one(now, filename, ms):
    data = "%-20s" % (ms)
    data = data + "%-15s" % (now["tcp-conn-attemp"])
    data = data + "%-15s" % (now["tcp-conn-succ"])
    data = data + "%-15s" % (now["tcp-close-local"])
    data = data + "%-15s" % (now["tcp-close-remote-fin"])
    data = data + "%-15s" % (now["tcp-close-remote-rst"])
    data = data + "%-15s" % (now["tcp-close-timeout"])
    data = data + "%-15s" % (now["tcp-close-err"])
    data = data + "%-15s" % (now["http-request"])
    data = data + "%-15s" % (now["http-response"])
    data = data + "\n"

    write_log_to_file(filename, data)

def do_log_stream_core_rete_one(now, filename, ms, ms_diff):
    data = "%-20s" % (ms)
    data = data + "%-15.2f" % (now["tcp-conn-attemp"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["tcp-conn-succ"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["tcp-close-local"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["tcp-close-remote-fin"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["tcp-close-remote-rst"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["tcp-close-timeout"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["tcp-close-err"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["http-request"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["http-response"] * 1000 / ms_diff)
    data = data + "\n"

    write_log_to_file(filename, data)

def do_log_stream():
    global STATS_STREAM_LAST
    r = get_dict_from_url("/get_stat_stream")
    if not r:
        return
    
    if not STATS_STREAM_LAST:
        STATS_STREAM_LAST = copy.deepcopy(r)
        return

    ms = r["elapsed_ms"]

    ms_diff = int(ms) - int(STATS_STREAM_LAST["elapsed_ms"])

    r_diff = StatDict(r) - StatDict(STATS_STREAM_LAST)
    
    STATS_STREAM_LAST = copy.deepcopy(r)

    for stream_ind in range(0, STREAM_CNT):
        stream_sum_now = None
        for core in range(0, PACKET_CORE_CNT):
            
            filename = get_log_filename_stream(stream_ind, core)
            now = get_stream_item(r, stream_ind, core)
            do_log_stream_core_one(now, filename, ms)
            if stream_sum_now:
                stream_sum_now = StatDict(stream_sum_now) + StatDict(now)
            else:
                stream_sum_now = StatDict(now)

            filename = get_log_filename_stream_rate(stream_ind, core)
            now = get_stream_item(r_diff, stream_ind, core)
            do_log_stream_core_rete_one(now, filename, ms, ms_diff)

        filename = get_log_filename_stream(stream_ind, -1)
        do_log_stream_core_one(stream_sum_now, filename, ms)
        
        if STATS_STREAM_SUM_LAST[stream_ind]:
            sum_diff = StatDict(stream_sum_now) - STATS_STREAM_SUM_LAST[stream_ind]
            filename = get_log_filename_stream_rate(stream_ind, -1)
            do_log_stream_core_rete_one(sum_diff, filename, ms, ms_diff)
        STATS_STREAM_SUM_LAST[stream_ind] = StatDict(stream_sum_now)

def do_log_interface_one(now, filename, ms):
    data = "%-20s" % (ms)
    data = data + "%-15s" % (now["ipackets"])
    data = data + "%-15s" % (now["opackets"])
    data = data + "%-15s" % (now["ibits"])
    data = data + "%-15s" % (now["obits"])
    data = data + "%-15s" % (now["imissed"])
    data = data + "%-15s" % (now["ierrors"])
    data = data + "%-15s" % (now["oerrors"])
    data = data + "%-15s" % (now["rx_nombuf"])
    data = data + "\n"

    write_log_to_file(filename, data)

def do_log_interface_rete_one(now, filename, ms, ms_diff):
    data = "%-20s" % (ms)
    data = data + "%-15.2f" % (now["ipackets"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["opackets"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["ibits"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["obits"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["imissed"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["ierrors"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["oerrors"] * 1000 / ms_diff)
    data = data + "%-15.2f" % (now["rx_nombuf"] * 1000 / ms_diff)
    data = data + "\n"

    write_log_to_file(filename, data)

def do_log_interfaces():
    global STATS_INTERFACES_LAST
    r = get_dict_from_url("/get_interface")
    if not r:
        return
    
    if not STATS_INTERFACES_LAST:
        STATS_INTERFACES_LAST = r
        return

    ms = r["elapsed_ms"]
    ms_diff = int(ms) - int(STATS_INTERFACES_LAST["elapsed_ms"])
    
    for intf_ind in range(0, INTERFACE_CNT):
        filename = get_log_filename_interface(intf_ind)
        now = r["interfaces"][intf_ind]
        do_log_interface_one(now, filename, ms)
        
        last = STATS_INTERFACES_LAST["interfaces"][intf_ind]
        diff = StatDict(now) - StatDict(last)
        filename = get_log_filename_interface_rate(intf_ind)
        do_log_interface_rete_one(diff, filename, ms, ms_diff)

    STATS_INTERFACES_LAST = r

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

DIR_UNIQUE = os.path.join(DIR_LOG_BASE, UNIQUE)
print("DIR_UNIQUE is [%s]" % (DIR_UNIQUE))

r = get_dict_from_url("/get_basic")
PACKET_CORE_CNT = r["pkt_core_cnt"]
DISPATCH_CORE_CNT = r["dispatch_core_cnt"]
STREAM_CNT = r["streams_cnt"]
INTERFACE_CNT = r["interface_cnt"]

print("pkt=[%s] dispatch=[%s] stream=[%s] interface=[%s]" % (PACKET_CORE_CNT, DISPATCH_CORE_CNT, STREAM_CNT, INTERFACE_CNT))

print("===== xf-generator stats ok =====", flush=True);

cnt = 0
while True:
    time.sleep(1)
    cnt = cnt + 1
    if cnt % 5 == 0:
        do_log_cpu()
        do_log_stream()
        do_log_interfaces()
