# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Function/method decorators that provide timeout and retry logic.
"""

import functools
import itertools
import sys

from devil.android import device_errors
from devil.utils import cmd_helper
from devil.utils import reraiser_thread
from devil.utils import timeout_retry

DEFAULT_TIMEOUT_ATTR = '_default_timeout'
DEFAULT_RETRIES_ATTR = '_default_retries'


def _TimeoutRetryWrapper(
    f, timeout_func, retries_func, retry_if_func=timeout_retry.AlwaysRetry,
    pass_values=False):
  """ Wraps a funcion with timeout and retry handling logic.

  Args:
    f: The function to wrap.
    timeout_func: A callable that returns the timeout value.
    retries_func: A callable that returns the retries value.
    pass_values: If True, passes the values returned by |timeout_func| and
                 |retries_func| to the wrapped function as 'timeout' and
                 'retries' kwargs, respectively.
  Returns:
    The wrapped function.
  """
  @functools.wraps(f)
  def timeout_retry_wrapper(*args, **kwargs):
    timeout = timeout_func(*args, **kwargs)
    retries = retries_func(*args, **kwargs)
    if pass_values:
      kwargs['timeout'] = timeout
      kwargs['retries'] = retries

    @functools.wraps(f)
    def impl():
      return f(*args, **kwargs)
    try:
      if timeout_retry.CurrentTimeoutThreadGroup():
        # Don't wrap if there's already an outer timeout thread.
        return impl()
      else:
        desc = '%s(%s)' % (f.__name__, ', '.join(itertools.chain(
            (str(a) for a in args),
            ('%s=%s' % (k, str(v)) for k, v in kwargs.iteritems()))))
        return timeout_retry.Run(impl, timeout, retries, desc=desc,
                                 retry_if_func=retry_if_func)
    except reraiser_thread.TimeoutError as e:
      raise device_errors.CommandTimeoutError(str(e)), None, (
          sys.exc_info()[2])
    except cmd_helper.TimeoutError as e:
      raise device_errors.CommandTimeoutError(str(e)), None, (
          sys.exc_info()[2])
  return timeout_retry_wrapper


def WithTimeoutAndRetries(f):
  """A decorator that handles timeouts and retries.

  'timeout' and 'retries' kwargs must be passed to the function.

  Args:
    f: The function to decorate.
  Returns:
    The decorated function.
  """
  get_timeout = lambda *a, **kw: kw['timeout']
  get_retries = lambda *a, **kw: kw['retries']
  return _TimeoutRetryWrapper(f, get_timeout, get_retries)


def WithTimeoutAndConditionalRetries(retry_if_func):
  """Returns a decorator that handles timeouts and, in some cases, retries.

  'timeout' and 'retries' kwargs must be passed to the function.

  Args:
    retry_if_func: A unary callable that takes an exception and returns
      whether failures should be retried.
  Returns:
    The actual decorator.
  """
  def decorator(f):
    get_timeout = lambda *a, **kw: kw['timeout']
    get_retries = lambda *a, **kw: kw['retries']
    return _TimeoutRetryWrapper(
        f, get_timeout, get_retries, retry_if_func=retry_if_func)
  return decorator


def WithExplicitTimeoutAndRetries(timeout, retries):
  """Returns a decorator that handles timeouts and retries.

  The provided |timeout| and |retries| values are always used.

  Args:
    timeout: The number of seconds to wait for the decorated function to
             return. Always used.
    retries: The number of times the decorated function should be retried on
             failure. Always used.
  Returns:
    The actual decorator.
  """
  def decorator(f):
    get_timeout = lambda *a, **kw: timeout
    get_retries = lambda *a, **kw: retries
    return _TimeoutRetryWrapper(f, get_timeout, get_retries)
  return decorator


def WithTimeoutAndRetriesDefaults(default_timeout, default_retries):
  """Returns a decorator that handles timeouts and retries.

  The provided |default_timeout| and |default_retries| values are used only
  if timeout and retries values are not provided.

  Args:
    default_timeout: The number of seconds to wait for the decorated function
                     to return. Only used if a 'timeout' kwarg is not passed
                     to the decorated function.
    default_retries: The number of times the decorated function should be
                     retried on failure. Only used if a 'retries' kwarg is not
                     passed to the decorated function.
  Returns:
    The actual decorator.
  """
  def decorator(f):
    get_timeout = lambda *a, **kw: kw.get('timeout', default_timeout)
    get_retries = lambda *a, **kw: kw.get('retries', default_retries)
    return _TimeoutRetryWrapper(f, get_timeout, get_retries, pass_values=True)
  return decorator


def WithTimeoutAndRetriesFromInstance(
    default_timeout_name=DEFAULT_TIMEOUT_ATTR,
    default_retries_name=DEFAULT_RETRIES_ATTR,
    min_default_timeout=None):
  """Returns a decorator that handles timeouts and retries.

  The provided |default_timeout_name| and |default_retries_name| are used to
  get the default timeout value and the default retries value from the object
  instance if timeout and retries values are not provided.

  Note that this should only be used to decorate methods, not functions.

  Args:
    default_timeout_name: The name of the default timeout attribute of the
                          instance.
    default_retries_name: The name of the default retries attribute of the
                          instance.
    min_timeout: Miniumum timeout to be used when using instance timeout.
  Returns:
    The actual decorator.
  """
  def decorator(f):
    def get_timeout(inst, *_args, **kwargs):
      ret = getattr(inst, default_timeout_name)
      if min_default_timeout is not None:
        ret = max(min_default_timeout, ret)
      return kwargs.get('timeout', ret)

    def get_retries(inst, *_args, **kwargs):
      return kwargs.get('retries', getattr(inst, default_retries_name))
    return _TimeoutRetryWrapper(f, get_timeout, get_retries, pass_values=True)
  return decorator

