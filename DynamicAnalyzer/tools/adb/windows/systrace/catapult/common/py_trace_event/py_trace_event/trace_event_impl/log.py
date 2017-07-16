# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import atexit
import json
import os
import sys
import time
import threading

from py_trace_event import trace_time

from py_utils import lock


_lock = threading.Lock()

_enabled = False
_log_file = None

_cur_events = [] # events that have yet to be buffered

_tls = threading.local() # tls used to detect forking/etc
_atexit_regsitered_for_pid = None

_control_allowed = True


class TraceException(Exception):
  pass

def _note(msg, *args):
  pass
#  print "%i: %s" % (os.getpid(), msg)


def _locked(fn):
  def locked_fn(*args,**kwargs):
    _lock.acquire()
    try:
      ret = fn(*args,**kwargs)
    finally:
      _lock.release()
    return ret
  return locked_fn

def _disallow_tracing_control():
  global _control_allowed
  _control_allowed = False

def trace_enable(log_file=None):
  _trace_enable(log_file)

@_locked
def _trace_enable(log_file=None):
  global _enabled
  if _enabled:
    raise TraceException("Already enabled")
  if not _control_allowed:
    raise TraceException("Tracing control not allowed in child processes.")
  _enabled = True
  global _log_file
  if log_file == None:
    if sys.argv[0] == '':
      n = 'trace_event'
    else:
      n = sys.argv[0]
    log_file = open("%s.json" % n, "ab", False)
    _note("trace_event: tracelog name is %s.json" % n)
  elif isinstance(log_file, basestring):
    _note("trace_event: tracelog name is %s" % log_file)
    log_file = open("%s" % log_file, "ab", False)
  elif not hasattr(log_file, 'fileno'):
    raise TraceException(
        "Log file must be None, a string, or file-like object with a fileno()")

  _log_file = log_file
  with lock.FileLock(_log_file, lock.LOCK_EX):
    _log_file.seek(0, os.SEEK_END)

    lastpos = _log_file.tell()
    creator = lastpos == 0
    if creator:
      _note("trace_event: Opened new tracelog, lastpos=%i", lastpos)
      _log_file.write('[')

      tid = threading.current_thread().ident
      if not tid:
        tid = os.getpid()
      x = {"ph": "M", "category": "process_argv",
           "pid": os.getpid(), "tid": threading.current_thread().ident,
           "ts": trace_time.Now(),
           "name": "process_argv", "args": {"argv": sys.argv}}
      _log_file.write("%s\n" % json.dumps(x))
    else:
      _note("trace_event: Opened existing tracelog")
    _log_file.flush()

@_locked
def trace_flush():
  if _enabled:
    _flush()

@_locked
def trace_disable():
  global _enabled
  if not _control_allowed:
    raise TraceException("Tracing control not allowed in child processes.")
  if not _enabled:
    return
  _enabled = False
  _flush(close=True)

def _flush(close=False):
  global _log_file
  with lock.FileLock(_log_file, lock.LOCK_EX):
    _log_file.seek(0, os.SEEK_END)
    if len(_cur_events):
      _log_file.write(",\n")
      _log_file.write(",\n".join([json.dumps(e) for e in _cur_events]))
      del _cur_events[:]

    if close:
      # We might not be the only process writing to this logfile. So,
      # we will simply close the file rather than writign the trailing ] that
      # it technically requires. The trace viewer understands that this may
      # happen and will insert a trailing ] during loading.
      pass
    _log_file.flush()

  if close:
    _note("trace_event: Closed")
    _log_file.close()
    _log_file = None
  else:
    _note("trace_event: Flushed")

@_locked
def trace_is_enabled():
  return _enabled

@_locked
def add_trace_event(ph, ts, category, name, args=None):
  global _enabled
  if not _enabled:
    return
  if not hasattr(_tls, 'pid') or _tls.pid != os.getpid():
    _tls.pid = os.getpid()
    global _atexit_regsitered_for_pid
    if _tls.pid != _atexit_regsitered_for_pid:
      _atexit_regsitered_for_pid = _tls.pid
      atexit.register(_trace_disable_atexit)
      _tls.pid = os.getpid()
      del _cur_events[:] # we forked, clear the event buffer!
    tid = threading.current_thread().ident
    if not tid:
      tid = os.getpid()
    _tls.tid = tid

  _cur_events.append({"ph": ph,
                      "category": category,
                      "pid": _tls.pid,
                      "tid": _tls.tid,
                      "ts": ts,
                      "name": name,
                      "args": args or {}});

def trace_begin(name, args=None):
  add_trace_event("B", trace_time.Now(), "python", name, args)

def trace_end(name, args=None):
  add_trace_event("E", trace_time.Now(), "python", name, args)

def _trace_disable_atexit():
  trace_disable()

def is_tracing_controllable():
  global _control_allowed
  return _control_allowed
