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
