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

UNIQUE = None

TO_KILL = False
TO_LWIP = False
TO_GENERATOR = False
TO_DISPATCH = False
TO_STREAM = False
TO_INTERFACE = False

# ------------------------------ main ------------------------------
if __name__ != '__main__':
    sys.exit(0)

try:
    kvs, leftargs = getopt.getopt(sys.argv[1:],
                                  "u:klgdsi", [
                                      "unique=",
                                      "kill",
                                      "lwip",
                                      "generator",
                                      "dispatch",
                                      "stream",
                                      "interface",
                                   ]
                                  )
    for k, v in kvs:
        if k in ("-u", "--unique"):
            UNIQUE = v
        elif k in ("-k", "--kill"):
            TO_KILL = True
        elif k in ("-l", "--lwip"):
            TO_LWIP = True
        elif k in ("-g", "--generator"):
            TO_GENERATOR = True
        elif k in ("-d", "--dispatch"):
            TO_DISPATCH = True
        elif k in ("-s", "--stream"):
            TO_STREAM = True
        elif k in ("-i", "--interface"):
            TO_INTERFACE = True
except Exception as e:
    print("Invalid args.")
    sys.exit(-1)

if TO_KILL:
    if not UNIQUE:
        print("No unique ID.")
        sys.exit(-1)
    pids = get_unique_pids(UNIQUE)
    if not pids:
        print("No unique found.")
        sys.exit(-1)
    for i in pids:
        os.system("kill -9 %s" % (i))
    pids = get_unique_pids(UNIQUE)
    if pids:
        print("Kill fail %s." % (pids))
    print("Unique ID [%s] killed." % (UNIQUE))
    sys.exit(0)

if TO_LWIP or TO_GENERATOR or TO_DISPATCH or TO_STREAM or TO_INTERFACE:
    if TO_LWIP:
        url = "get_stat_lwip"
    elif TO_GENERATOR:
        url = "get_stat_generator"
    elif TO_DISPATCH:
        url = "get_stat_dispatch"
    elif TO_STREAM:
        url = "get_stat_stream"
    elif TO_INTERFACE:
        url = "get_interface"
    
    lport = get_unique_lport(UNIQUE)
    if not lport:
        print("Unique ID [%s] local port not found." % (UNIQUE))

    cmd = 'curl http://127.0.0.1:%s/%s' % (lport, url)
    (ret, outstr, errstr) = run_cmd_wrapper(cmd, check_interval=0.1, timeout=3)
    
    obj = json.loads(outstr)
    s = json.dumps(NonzeroDict(obj), indent=2)
    print(s)
