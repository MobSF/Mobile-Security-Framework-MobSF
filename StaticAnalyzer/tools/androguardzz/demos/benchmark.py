#!/usr/bin/env python

import sys, os
import cProfile

# http://code.activestate.com/recipes/286222-memory-usage/
_proc_status = '/proc/%d/status' % os.getpid()

_scale = {'kB': 1024.0, 'mB': 1024.0*1024.0,
          'KB': 1024.0, 'MB': 1024.0*1024.0}

def _VmB(VmKey):
    global _proc_status, _scale
     # get pseudo file  /proc/<pid>/status
    try:
        t = open(_proc_status)
        v = t.read()
        t.close()
    except:
        return 0.0  # non-Linux?
     # get VmKey line e.g. 'VmRSS:  9999  kB\n ...'
    i = v.index(VmKey)
    v = v[i:].split(None, 3)  # whitespace
    if len(v) < 3:
        return 0.0  # invalid format?
     # convert Vm value to bytes
    return float(v[1]) * _scale[v[2]]


def memory(since=0.0):
    '''Return memory usage in bytes.
    '''
    return _VmB('VmSize:') - since


def resident(since=0.0):
    '''Return resident memory usage in bytes.
    '''
    return _VmB('VmRSS:') - since


def stacksize(since=0.0):
    '''Return stack size in bytes.
    '''
    return _VmB('VmStk:') - since

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL + "./")

import androguard, analysis

# a directory with apks files"

TEST = "./apks/"

l = []
for i in os.walk( TEST ) :
    for j in i[2] :
        l.append( i[0] + j )

print len(l), l

_a = androguard.Androguard( l )

print "MEMORY : ", memory() / _scale["MB"], "RESIDENT ", resident() / _scale["MB"], "STACKSIZE ", stacksize() / _scale["MB"]
