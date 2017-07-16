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

"""Simulate network characteristics directly in Python.

Allows running replay without dummynet.
"""

import logging
import platformsettings
import re
import time


TIMER = platformsettings.timer


class ProxyShaperError(Exception):
  """Module catch-all error."""
  pass

class BandwidthValueError(ProxyShaperError):
  """Raised for unexpected dummynet-style bandwidth value."""
  pass


class RateLimitedFile(object):
  """Wrap a file like object with rate limiting.

  TODO(slamm): Simulate slow-start.
      Each RateLimitedFile corresponds to one-direction of a
      bidirectional socket. Slow-start can be added here (algorithm needed).
      Will consider changing this class to take read and write files and
      corresponding bit rates for each.
  """
  BYTES_PER_WRITE = 1460

  def __init__(self, request_counter, f, bps):
    """Initialize a RateLimiter.

    Args:
      request_counter: callable to see how many requests share the limit.
      f: file-like object to wrap.
      bps: an integer of bits per second.
    """
    self.request_counter = request_counter
    self.original_file = f
    self.bps = bps

  def transfer_seconds(self, num_bytes):
    """Seconds to read/write |num_bytes| with |self.bps|."""
    return 8.0 * num_bytes / self.bps

  def write(self, data):
    num_bytes = len(data)
    num_sent_bytes = 0
    while num_sent_bytes < num_bytes:
      num_write_bytes = min(self.BYTES_PER_WRITE, num_bytes - num_sent_bytes)
      num_requests = self.request_counter()
      wait = self.transfer_seconds(num_write_bytes) * num_requests
      logging.debug('write sleep: %0.4fs (%d requests)', wait, num_requests)
      time.sleep(wait)

      self.original_file.write(
          data[num_sent_bytes:num_sent_bytes + num_write_bytes])
      num_sent_bytes += num_write_bytes

  def _read(self, read_func, size):
    start = TIMER()
    data = read_func(size)
    read_seconds = TIMER() - start
    num_bytes = len(data)
    num_requests = self.request_counter()
    wait = self.transfer_seconds(num_bytes) * num_requests - read_seconds
    if wait > 0:
      logging.debug('read sleep: %0.4fs %d requests)', wait, num_requests)
      time.sleep(wait)
    return data

  def readline(self, size=-1):
    return self._read(self.original_file.readline, size)

  def read(self, size=-1):
    return self._read(self.original_file.read, size)

  def __getattr__(self, name):
    """Forward any non-overriden calls."""
    return getattr(self.original_file, name)


def GetBitsPerSecond(bandwidth):
  """Return bits per second represented by dummynet bandwidth option.

  See ipfw/dummynet.c:read_bandwidth for how it is really done.

  Args:
    bandwidth: a dummynet-style bandwidth specification (e.g. "10Kbit/s")
  """
  if bandwidth == '0':
    return 0
  bw_re = r'^(\d+)(?:([KM])?(bit|Byte)/s)?$'
  match = re.match(bw_re, str(bandwidth))
  if not match:
    raise BandwidthValueError('Value, "%s", does not match regex: %s' % (
        bandwidth, bw_re))
  bw = int(match.group(1))
  if match.group(2) == 'K':
    bw *= 1000
  if match.group(2) == 'M':
    bw *= 1000000
  if match.group(3) == 'Byte':
    bw *= 8
  return bw
