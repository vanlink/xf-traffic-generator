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

outfile = os.path.join(DIR_UNIQUE, MAIN_EXEC_OUT)
cmd = "nohup %s --unique=%s -c %s > %s 2>&1 &" % (MAIN_EXEC_NAME, UNIQUE, CONF, outfile)
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
