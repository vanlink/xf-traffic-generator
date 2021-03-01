#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
import time
import subprocess
import json
import re
import copy
import socket

DIR_LOG_BASE = "/var/log/xf-traffic-generator"

UNIQUE_KEY = "unique"

MAIN_EXEC_NAME = "./xf-generator-main"
DAEMON_EXEC_NAME = "./xf-generator-daemon"
DAEMON_PY_NAME = "../tools/xf-daemon.py"

CONF_FILE_NAME = "conf.json"

MAIN_EXEC_OUT = "xf-generator-main.out"
DAEMON_EXEC_OUT = "xf-generator-daemon.out"
DAEMON_PY_OUT = "xf-daemon-py.out"

OK_STR = "===== xf-generator"

class NonzeroDict(dict):
    def __init__(self, d):
        dict.__init__(self, d)
        for key, val in d.items():
            if not val:
                self.pop(key)
                continue

            if isinstance(val, (str,)):
                if val.isdigit():
                    val = int(val)
                    if val:
                        self[key] = val
                    else:
                        self.pop(key)
                    continue
            elif isinstance(val, dict):
                tmp = NonzeroDict(val)
                if tmp:
                    self[key] = tmp
                else:
                    self.pop(key)
                continue
            elif isinstance(val, list):
                dstarray = []
                for i in val:
                    tmp = NonzeroDict(i)
                    if tmp:
                        dstarray.append(tmp)
                if dstarray:
                    self[key] = dstarray
                else:
                    self.pop(key)
                continue

            self[key] = val

class StatDict(dict):
    def __init__(self, d):
        dict.__init__(self, d)
        for key, val in d.items():
            if isinstance(val, (str,)) and val.isdigit():
                self[key] = int(val)
            elif isinstance(val, dict):
                self[key] = StatDict(val)
            elif isinstance(val, list) and len(val):
                if isinstance(val[0], dict):
                    self[key] = list(map(lambda x :StatDict(x), val))
                elif isinstance(val[0], (str,)):
                    self[key] = list(map(lambda x :int(x), val))
                else:
                    self[key] = val
            else:
                self[key] = val
    @staticmethod
    def keys_all(me, oth):
        return list(set(me.keys()) | set(oth.keys()))
    @staticmethod
    def add_sub(me, oth, to_add):
        ret = {}
        for key in StatDict.keys_all(me, oth):
            val_me = me.get(key, 0)
            val_oth = oth.get(key, 0)
            if key in me and key not in oth:
                if isinstance(val_me, (str)) and str(val_me).isdigit():
                    val_me = int(val_me)
                ret[key] = val_me
                continue
            if key not in me and key in oth:
                if isinstance(val_oth, (str)) and str(val_oth).isdigit():
                    val_oth = int(val_oth)
                ret[key] = val_oth
                continue
            if isinstance(val_me, (str, int)) and isinstance(val_oth, (str, int)) and \
               str(val_me).isdigit() and str(val_oth).isdigit():
                if to_add:
                    ret[key] = int(val_me) + int(val_oth)
                else:
                    ret[key] = int(val_me) - int(val_oth)
            elif type(val_me) == type(val_oth):
                if isinstance(val_me, dict):
                    if to_add:
                        ret[key] = StatDict(val_me) + StatDict(val_oth)
                    else:
                        ret[key] = StatDict(val_me) - StatDict(val_oth)
                elif isinstance(val_me, list) and len(val_me):
                    if isinstance(val_me[0], dict):
                        if to_add:
                            ret[key] = list(map(lambda x :StatDict(x[0]) + StatDict(x[1]), zip(val_me, val_oth)))
                        else:
                            ret[key] = list(map(lambda x :StatDict(x[0]) - StatDict(x[1]), zip(val_me, val_oth)))
                    elif isinstance(val_me[0], (str, int)):
                        maxitems = max(len(val_me), len(val_oth))
                        diff = abs(len(val_me) - len(val_oth))
                        if diff:
                            if len(val_me) < maxitems:
                                val_me.extend([0] * diff)
                            else:
                                val_oth.extend([0] * diff)
                        if to_add:
                            ret[key] = list(map(lambda x :int(x[0]) + int(x[1]) ,zip(val_me, val_oth)))
                        else:
                            ret[key] = list(map(lambda x :int(x[0]) - int(x[1]) ,zip(val_me, val_oth)))
        return ret

    def __add__(self, oth):
        return self.add_sub(self, oth, 1)

    def __sub__(self, oth):
        return self.add_sub(self, oth, 0)

    @staticmethod
    def mul_div(me, divnum, to_mul):
        ret = {}
        for key, val_me in me.items():
            if isinstance(val_me, (str, int)) and str(val_me).isdigit():
                if to_mul:
                    ret[key] = int(val_me) * divnum
                else:
                    ret[key] = int(val_me) / divnum
            elif isinstance(val_me, dict):
                if to_mul:
                    ret[key] = StatDict(val_me) * divnum
                else:
                    ret[key] = StatDict(val_me) / divnum
            elif isinstance(val_me, list) and len(val_me):
                if isinstance(val_me[0], dict):
                    if to_mul:
                        ret[key] = list(map(lambda x :StatDict(x) * divnum,val_me))
                    else:
                        ret[key] = list(map(lambda x :StatDict(x) / divnum,val_me))
                elif isinstance(val_me[0], (str, int)):
                    if to_mul:
                        ret[key] = list(map(lambda x :int(x) * divnum,val_me))
                    else:
                        ret[key] = list(map(lambda x :int(x) / divnum,val_me))
        return ret

    def __div__(self, divnum):
        return self.mul_div(self, divnum, 0)
    def __mul__(self, divnum):
        return self.mul_div(self, divnum, 1)
    def __int__(self):
        for key, val in self.items():
            if isinstance(val, (str,)):
                self[key] = int(val)
            elif isinstance(val, dict):
                self[key] = int(StatDict(val))
            elif isinstance(val, list):
                ret[key] = list(map(lambda x :StatDict(x) * divnum,val_me))

def run_cmd_wrapper(cmd, check_interval=0.5, timeout=10, asyncdo=False):
    ret = -1
    fin = None
    outstr = ""
    errstr = ""

    toreal = int(timeout / check_interval)

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if asyncdo:
        return p

    time.sleep(check_interval)
    for _ in range(toreal):
        fin = p.poll()
        if fin is not None:
            break
        time.sleep(check_interval)

    if fin is None:
        errstr = "[wrapper] cmd [%s] not finish." % cmd
        try:
            p.kill()
        except:
            pass
        try:
            p.terminate()
        except:
            pass
    else:
        ret = fin
        if p.stdout:
            outstr = p.stdout.read()
        if p.stderr:
            errstr = p.stderr.read()

    return (ret, outstr, errstr)

def get_unique_pids(unique):
    pids = {
        "main_exec": None,
        "daemon_exec": None,
        "daemon_py": None
    }
    
    pidsarray = []

    cmd = "ps aux|grep '%s .*--%s=%s '|grep -v grep|awk '{print $2}'" % (MAIN_EXEC_NAME, UNIQUE_KEY, unique)
    (ret, outstr, errstr) = run_cmd_wrapper(cmd, check_interval=0.1, timeout=2)
    if outstr:
        outstr = outstr.strip()
        if outstr.isdigit():
            pids["main_exec"] = int(outstr)
            pidsarray.append(int(outstr))

    cmd = "ps aux|grep '%s .*--%s=%s '|grep -v grep|awk '{print $2}'" % (DAEMON_EXEC_NAME, UNIQUE_KEY, unique)
    (ret, outstr, errstr) = run_cmd_wrapper(cmd, check_interval=0.1, timeout=2)
    if outstr:
        outstr = outstr.strip()
        if outstr.isdigit():
            pids["daemon_exec"] = int(outstr)
            pidsarray.append(int(outstr))

    cmd = "ps aux|grep '%s .*--%s=%s '|grep -v grep|awk '{print $2}'" % (DAEMON_PY_NAME, UNIQUE_KEY, unique)
    (ret, outstr, errstr) = run_cmd_wrapper(cmd, check_interval=0.1, timeout=2)
    if outstr:
        outstr = outstr.strip()
        if outstr.isdigit():
            pids["daemon_py"] = int(outstr)
            pidsarray.append(int(outstr))

    return pidsarray

def ok_str_found(filename):
    cmd = 'cat %s 2>&1 | grep "%s" > /dev/null' % (filename, OK_STR)
    if os.system(cmd):
        return False
    return True

def is_local_port_in_use(port):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", int(port)))
        s.listen(1)
    except:
        return True
    finally:
        try:
            s.close()
        except:
            pass
    
    return False

def get_unique_lport(unique):
    cmd = 'ps -e -o pid,command|egrep "%s .*\-\-%s=%s "' % (DAEMON_EXEC_NAME, UNIQUE_KEY, unique)
    (ret, outstr, errstr) = run_cmd_wrapper(cmd, check_interval=0.1, timeout=2)
    if not outstr:
        return None
    outstr = outstr.strip()
    if not outstr:
        return None

    m = re.match(r'^.+ -p (\d+)', str(outstr))
    if not m:
        return None

    return int(m.groups()[0])
