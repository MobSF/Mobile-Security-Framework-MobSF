# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A utility to run functions with timeouts and retries."""
# pylint: disable=W0702

import logging
import threading
import time

from devil.utils import reraiser_thread
from devil.utils import watchdog_timer

logger = logging.getLogger(__name__)


class TimeoutRetryThreadGroup(reraiser_thread.ReraiserThreadGroup):

  def __init__(self, timeout, threads=None):
    super(TimeoutRetryThreadGroup, self).__init__(threads)
    self._watcher = watchdog_timer.WatchdogTimer(timeout)

  def GetWatcher(self):
    """Returns the watchdog keeping track of this thread's time."""
    return self._watcher

  def GetElapsedTime(self):
    return self._watcher.GetElapsed()

  def GetRemainingTime(self, required=0, msg=None):
    """Get the remaining time before the thread times out.

    Useful to send as the |timeout| parameter of async IO operations.

    Args:
      required: minimum amount of time that will be required to complete, e.g.,
        some sleep or IO operation.
      msg: error message to show if timing out.

    Returns:
      The number of seconds remaining before the thread times out, or None
      if the thread never times out.

    Raises:
      reraiser_thread.TimeoutError if the remaining time is less than the
        required time.
    """
    remaining = self._watcher.GetRemaining()
    if remaining is not None and remaining < required:
      if msg is None:
        msg = 'Timeout expired'
      if remaining > 0:
        msg += (', wait of %.1f secs required but only %.1f secs left'
                % (required, remaining))
      raise reraiser_thread.TimeoutError(msg)
    return remaining


def CurrentTimeoutThreadGroup():
  """Returns the thread group that owns or is blocked on the active thread.

  Returns:
    Returns None if no TimeoutRetryThreadGroup is tracking the current thread.
  """
  thread_group = reraiser_thread.CurrentThreadGroup()
  while thread_group:
    if isinstance(thread_group, TimeoutRetryThreadGroup):
      return thread_group
    thread_group = thread_group.blocked_parent_thread_group
  return None


def WaitFor(condition, wait_period=5, max_tries=None):
  """Wait for a condition to become true.

  Repeatedly call the function condition(), with no arguments, until it returns
  a true value.

  If called within a TimeoutRetryThreadGroup, it cooperates nicely with it.

  Args:
    condition: function with the condition to check
    wait_period: number of seconds to wait before retrying to check the
      condition
    max_tries: maximum number of checks to make, the default tries forever
      or until the TimeoutRetryThreadGroup expires.

  Returns:
    The true value returned by the condition, or None if the condition was
    not met after max_tries.

  Raises:
    reraiser_thread.TimeoutError: if the current thread is a
      TimeoutRetryThreadGroup and the timeout expires.
  """
  condition_name = condition.__name__
  timeout_thread_group = CurrentTimeoutThreadGroup()
  while max_tries is None or max_tries > 0:
    result = condition()
    if max_tries is not None:
      max_tries -= 1
    msg = ['condition', repr(condition_name), 'met' if result else 'not met']
    if timeout_thread_group:
      # pylint: disable=no-member
      msg.append('(%.1fs)' % timeout_thread_group.GetElapsedTime())
    logger.info(' '.join(msg))
    if result:
      return result
    if timeout_thread_group:
      # pylint: disable=no-member
      timeout_thread_group.GetRemainingTime(wait_period,
          msg='Timed out waiting for %r' % condition_name)
    time.sleep(wait_period)
  return None


def AlwaysRetry(_exception):
  return True


def Run(func, timeout, retries, args=None, kwargs=None, desc=None,
        error_log_func=logging.critical, retry_if_func=AlwaysRetry):
  """Runs the passed function in a separate thread with timeouts and retries.

  Args:
    func: the function to be wrapped.
    timeout: the timeout in seconds for each try.
    retries: the number of retries.
    args: list of positional args to pass to |func|.
    kwargs: dictionary of keyword args to pass to |func|.
    desc: An optional description of |func| used in logging. If omitted,
      |func.__name__| will be used.
    error_log_func: Logging function when logging errors.
    retry_if_func: Unary callable that takes an exception and returns
      whether |func| should be retried. Defaults to always retrying.

  Returns:
    The return value of func(*args, **kwargs).
  """
  if not args:
    args = []
  if not kwargs:
    kwargs = {}
  if not desc:
    desc = func.__name__

  num_try = 1
  while True:
    thread_name = 'TimeoutThread-%d-for-%s' % (num_try,
                                               threading.current_thread().name)
    child_thread = reraiser_thread.ReraiserThread(lambda: func(*args, **kwargs),
                                                  name=thread_name)
    try:
      thread_group = TimeoutRetryThreadGroup(timeout, threads=[child_thread])
      thread_group.StartAll(will_block=True)
      while True:
        thread_group.JoinAll(watcher=thread_group.GetWatcher(), timeout=60,
                             error_log_func=error_log_func)
        if thread_group.IsAlive():
          logger.info('Still working on %s', desc)
        else:
          return thread_group.GetAllReturnValues()[0]
    except reraiser_thread.TimeoutError as e:
      # Timeouts already get their stacks logged.
      if num_try > retries or not retry_if_func(e):
        raise
      # Do not catch KeyboardInterrupt.
    except Exception as e:  # pylint: disable=broad-except
      if num_try > retries or not retry_if_func(e):
        raise
      error_log_func(
          '(%s) Exception on %s, attempt %d of %d: %r',
          thread_name, desc, num_try, retries + 1, e)
    num_try += 1
