#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
import time
import subprocess
import json
import re
import copy

DIR_LOG_BASE = "/var/log/xf-traffic-generator"

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