# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Thread and ThreadGroup that reraise exceptions on the main thread."""
# pylint: disable=W0212

import logging
import sys
import threading
import time
import traceback

from devil.utils import watchdog_timer


class TimeoutError(Exception):
  """Module-specific timeout exception."""
  pass


def LogThreadStack(thread, error_log_func=logging.critical):
  """Log the stack for the given thread.

  Args:
    thread: a threading.Thread instance.
    error_log_func: Logging function when logging errors.
  """
  stack = sys._current_frames()[thread.ident]
  error_log_func('*' * 80)
  error_log_func('Stack dump for thread %r', thread.name)
  error_log_func('*' * 80)
  for filename, lineno, name, line in traceback.extract_stack(stack):
    error_log_func('File: "%s", line %d, in %s', filename, lineno, name)
    if line:
      error_log_func('  %s', line.strip())
  error_log_func('*' * 80)


class ReraiserThread(threading.Thread):
  """Thread class that can reraise exceptions."""

  def __init__(self, func, args=None, kwargs=None, name=None):
    """Initialize thread.

    Args:
      func: callable to call on a new thread.
      args: list of positional arguments for callable, defaults to empty.
      kwargs: dictionary of keyword arguments for callable, defaults to empty.
      name: thread name, defaults to Thread-N.
    """
    if not name and func.__name__ != '<lambda>':
      name = func.__name__
    super(ReraiserThread, self).__init__(name=name)
    if not args:
      args = []
    if not kwargs:
      kwargs = {}
    self.daemon = True
    self._func = func
    self._args = args
    self._kwargs = kwargs
    self._ret = None
    self._exc_info = None
    self._thread_group = None

  def ReraiseIfException(self):
    """Reraise exception if an exception was raised in the thread."""
    if self._exc_info:
      raise self._exc_info[0], self._exc_info[1], self._exc_info[2]

  def GetReturnValue(self):
    """Reraise exception if present, otherwise get the return value."""
    self.ReraiseIfException()
    return self._ret

  # override
  def run(self):
    """Overrides Thread.run() to add support for reraising exceptions."""
    try:
      self._ret = self._func(*self._args, **self._kwargs)
    except:  # pylint: disable=W0702
      self._exc_info = sys.exc_info()


class ReraiserThreadGroup(object):
  """A group of ReraiserThread objects."""

  def __init__(self, threads=None):
    """Initialize thread group.

    Args:
      threads: a list of ReraiserThread objects; defaults to empty.
    """
    self._threads = []
    # Set when a thread from one group has called JoinAll on another. It is used
    # to detect when a there is a TimeoutRetryThread active that links to the
    # current thread.
    self.blocked_parent_thread_group = None
    if threads:
      for thread in threads:
        self.Add(thread)

  def Add(self, thread):
    """Add a thread to the group.

    Args:
      thread: a ReraiserThread object.
    """
    assert thread._thread_group is None
    thread._thread_group = self
    self._threads.append(thread)

  def StartAll(self, will_block=False):
    """Start all threads.

    Args:
      will_block: Whether the calling thread will subsequently block on this
        thread group. Causes the active ReraiserThreadGroup (if there is one)
        to be marked as blocking on this thread group.
    """
    if will_block:
      # Multiple threads blocking on the same outer thread should not happen in
      # practice.
      assert not self.blocked_parent_thread_group
      self.blocked_parent_thread_group = CurrentThreadGroup()
    for thread in self._threads:
      thread.start()

  def _JoinAll(self, watcher=None, timeout=None):
    """Join all threads without stack dumps.

    Reraises exceptions raised by the child threads and supports breaking
    immediately on exceptions raised on the main thread.

    Args:
      watcher: Watchdog object providing the thread timeout. If none is
          provided, the thread will never be timed out.
      timeout: An optional number of seconds to wait before timing out the join
          operation. This will not time out the threads.
    """
    if watcher is None:
      watcher = watchdog_timer.WatchdogTimer(None)
    alive_threads = self._threads[:]
    end_time = (time.time() + timeout) if timeout else None
    try:
      while alive_threads and (end_time is None or end_time > time.time()):
        for thread in alive_threads[:]:
          if watcher.IsTimedOut():
            raise TimeoutError('Timed out waiting for %d of %d threads.' %
                               (len(alive_threads), len(self._threads)))
          # Allow the main thread to periodically check for interrupts.
          thread.join(0.1)
          if not thread.isAlive():
            alive_threads.remove(thread)
      # All threads are allowed to complete before reraising exceptions.
      for thread in self._threads:
        thread.ReraiseIfException()
    finally:
      self.blocked_parent_thread_group = None

  def IsAlive(self):
    """Check whether any of the threads are still alive.

    Returns:
      Whether any of the threads are still alive.
    """
    return any(t.isAlive() for t in self._threads)

  def JoinAll(self, watcher=None, timeout=None,
              error_log_func=logging.critical):
    """Join all threads.

    Reraises exceptions raised by the child threads and supports breaking
    immediately on exceptions raised on the main thread. Unfinished threads'
    stacks will be logged on watchdog timeout.

    Args:
      watcher: Watchdog object providing the thread timeout. If none is
          provided, the thread will never be timed out.
      timeout: An optional number of seconds to wait before timing out the join
          operation. This will not time out the threads.
      error_log_func: Logging function when logging errors.
    """
    try:
      self._JoinAll(watcher, timeout)
    except TimeoutError:
      error_log_func('Timed out. Dumping threads.')
      for thread in (t for t in self._threads if t.isAlive()):
        LogThreadStack(thread, error_log_func=error_log_func)
      raise

  def GetAllReturnValues(self, watcher=None):
    """Get all return values, joining all threads if necessary.

    Args:
      watcher: same as in |JoinAll|. Only used if threads are alive.
    """
    if any([t.isAlive() for t in self._threads]):
      self.JoinAll(watcher)
    return [t.GetReturnValue() for t in self._threads]


def CurrentThreadGroup():
  """Returns the ReraiserThreadGroup that owns the running thread.

  Returns:
    The current thread group, otherwise None.
  """
  current_thread = threading.current_thread()
  if isinstance(current_thread, ReraiserThread):
    return current_thread._thread_group  # pylint: disable=no-member
  return None


def RunAsync(funcs, watcher=None):
  """Executes the given functions in parallel and returns their results.

  Args:
    funcs: List of functions to perform on their own threads.
    watcher: Watchdog object providing timeout, by default waits forever.

  Returns:
    A list of return values in the order of the given functions.
  """
  thread_group = ReraiserThreadGroup(ReraiserThread(f) for f in funcs)
  thread_group.StartAll(will_block=True)
  return thread_group.GetAllReturnValues(watcher=watcher)
