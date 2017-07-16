#!/usr/bin/env python

# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import functools
import inspect
import os
import sys
import time


def GetCatapultDir():
  return os.path.normpath(
      os.path.join(os.path.dirname(__file__), '..', '..', '..'))


def IsRunningOnCrosDevice():
  """Returns True if we're on a ChromeOS device."""
  lsb_release = '/etc/lsb-release'
  if sys.platform.startswith('linux') and os.path.exists(lsb_release):
    with open(lsb_release, 'r') as f:
      res = f.read()
      if res.count('CHROMEOS_RELEASE_NAME'):
        return True
  return False


def _ExecutableExtensions():
  # pathext is, e.g. '.com;.exe;.bat;.cmd'
  exts = os.getenv('PATHEXT').split(';') #e.g. ['.com','.exe','.bat','.cmd']
  return [x[1:].upper() for x in exts] #e.g. ['COM','EXE','BAT','CMD']


def IsExecutable(path):
  if os.path.isfile(path):
    if hasattr(os, 'name') and os.name == 'nt':
      return path.split('.')[-1].upper() in _ExecutableExtensions()
    else:
      return os.access(path, os.X_OK)
  else:
    return False


def _AddDirToPythonPath(*path_parts):
  path = os.path.abspath(os.path.join(*path_parts))
  if os.path.isdir(path) and path not in sys.path:
    # Some callsite that use telemetry assumes that sys.path[0] is the directory
    # containing the script, so we add these extra paths to right after it.
    sys.path.insert(1, path)

_AddDirToPythonPath(os.path.join(GetCatapultDir(), 'devil'))
_AddDirToPythonPath(os.path.join(GetCatapultDir(), 'dependency_manager'))
_AddDirToPythonPath(os.path.join(GetCatapultDir(), 'third_party', 'mock'))
# mox3 is needed for pyfakefs usage, but not for pylint.
_AddDirToPythonPath(os.path.join(GetCatapultDir(), 'third_party', 'mox3'))
_AddDirToPythonPath(
    os.path.join(GetCatapultDir(), 'third_party', 'pyfakefs'))

from devil.utils import timeout_retry
from devil.utils import reraiser_thread


# Decorator that adds timeout functionality to a function.
def Timeout(default_timeout):
  return lambda func: TimeoutDeco(func, default_timeout)

# Note: Even though the "timeout" keyword argument is the only
# keyword argument that will need to be given to the decorated function,
# we still have to use the **kwargs syntax, because we have to use
# the *args syntax here before (since the decorator decorates functions
# with different numbers of positional arguments) and Python doesn't allow
# a single named keyword argument after *args.
# (e.g., 'def foo(*args, bar=42):' is a syntax error)

def TimeoutDeco(func, default_timeout):
  @functools.wraps(func)
  def RunWithTimeout(*args, **kwargs):
    if 'timeout' in kwargs:
      timeout = kwargs['timeout']
    else:
      timeout = default_timeout
    try:
      return timeout_retry.Run(func, timeout, 0, args=args)
    except reraiser_thread.TimeoutError:
      print '%s timed out.' % func.__name__
      return False
  return RunWithTimeout


MIN_POLL_INTERVAL_IN_SECONDS = 0.1
MAX_POLL_INTERVAL_IN_SECONDS = 5
OUTPUT_INTERVAL_IN_SECONDS = 300

def WaitFor(condition, timeout):
  """Waits for up to |timeout| secs for the function |condition| to return True.

  Polling frequency is (elapsed_time / 10), with a min of .1s and max of 5s.

  Returns:
    Result of |condition| function (if present).
  """
  def GetConditionString():
    if condition.__name__ == '<lambda>':
      try:
        return inspect.getsource(condition).strip()
      except IOError:
        pass
    return condition.__name__

  # Do an initial check to see if its true.
  res = condition()
  if res:
    return res
  start_time = time.time()
  last_output_time = start_time
  elapsed_time = time.time() - start_time
  while elapsed_time < timeout:
    res = condition()
    if res:
      return res
    now = time.time()
    elapsed_time = now - start_time
    last_output_elapsed_time = now - last_output_time
    if last_output_elapsed_time > OUTPUT_INTERVAL_IN_SECONDS:
      last_output_time = time.time()
    poll_interval = min(max(elapsed_time / 10., MIN_POLL_INTERVAL_IN_SECONDS),
                        MAX_POLL_INTERVAL_IN_SECONDS)
    time.sleep(poll_interval)
  raise TimeoutException('Timed out while waiting %ds for %s.' %
                         (timeout, GetConditionString()))

class TimeoutException(Exception):
  """The operation failed to complete because of a timeout.

  It is possible that waiting for a longer period of time would result in a
  successful operation.
  """
  pass
