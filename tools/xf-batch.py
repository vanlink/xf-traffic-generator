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

# ------------------------------ main ------------------------------
if __name__ != '__main__':
    sys.exit(0)

try:
    kvs, leftargs = getopt.getopt(sys.argv[1:],
                                  "u:k", [
                                      "unique=",
                                      "kill",
                                   ]
                                  )
    for k, v in kvs:
        if k in ("-u", "--unique"):
            UNIQUE = v
        elif k in ("-k", "--kill"):
            TO_KILL = True
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
        print("Kill fail.")
    print("Unique ID killed.")