#!/usr/bin/env python
# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Miscellaneous utility functions."""

import inspect
import logging
import time

try:
  # pkg_resources (part of setuptools) is needed when WPR is
  # distributed as a package. (Resources may need to be extracted from
  # the package.)

  import pkg_resources

  def resource_exists(resource_name):
    return pkg_resources.resource_exists(__name__, resource_name)

  def resource_string(resource_name):
    return pkg_resources.resource_string(__name__, resource_name)

except ImportError:
  # Import of pkg_resources failed, so fall back to getting resources
  # from the file system.

  import os

  def _resource_path(resource_name):
    _replay_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(_replay_dir, resource_name)

  def resource_exists(resource_name):
    return os.path.exists(_resource_path(resource_name))

  def resource_string(resource_name):
    return open(_resource_path(resource_name)).read()


class TimeoutException(Exception):
  pass


def WaitFor(condition, timeout):
  """Waits for up to |timeout| secs for the function |condition| to return True.

  Polling frequency is (elapsed_time / 10), with a min of .1s and max of 5s.

  Returns:
    Result of |condition| function (if present).
  """
  min_poll_interval = 0.1
  max_poll_interval = 5
  output_interval = 300

  def GetConditionString():
    if condition.__name__ == '<lambda>':
      try:
        return inspect.getsource(condition).strip()
      except IOError:
        pass
    return condition.__name__

  start_time = time.time()
  last_output_time = start_time
  while True:
    res = condition()
    if res:
      return res
    now = time.time()
    elapsed_time = now - start_time
    last_output_elapsed_time = now - last_output_time
    if elapsed_time > timeout:
      raise TimeoutException('Timed out while waiting %ds for %s.' %
                                        (timeout, GetConditionString()))
    if last_output_elapsed_time > output_interval:
      logging.info('Continuing to wait %ds for %s. Elapsed: %ds.',
                   timeout, GetConditionString(), elapsed_time)
      last_output_time = time.time()
    poll_interval = min(max(elapsed_time / 10., min_poll_interval),
                        max_poll_interval)
    time.sleep(poll_interval)
