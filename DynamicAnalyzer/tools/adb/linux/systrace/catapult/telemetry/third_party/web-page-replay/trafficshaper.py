#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
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

import logging
import platformsettings
import re


# Mac has broken bandwitdh parsing, so double check the values.
# On Mac OS X 10.6, "KBit/s" actually uses "KByte/s".
BANDWIDTH_PATTERN = r'0|\d+[KM]?(bit|Byte)/s'


class TrafficShaperException(Exception):
  pass


class BandwidthValueError(TrafficShaperException):
  def __init__(self, value):  # pylint: disable=super-init-not-called
    self.value = value

  def __str__(self):
    return 'Value, "%s", does not match regex: %s' % (
        self.value, BANDWIDTH_PATTERN)


class TrafficShaper(object):
  """Manages network traffic shaping."""

  # Pick webpagetest-compatible values (details: http://goo.gl/oghTg).
  _UPLOAD_PIPE = '10'      # Enforces overall upload bandwidth.
  _UPLOAD_QUEUE = '10'     # Shares upload bandwidth among source ports.
  _UPLOAD_RULE = '5000'    # Specifies when the upload queue is used.
  _DOWNLOAD_PIPE = '11'    # Enforces overall download bandwidth.
  _DOWNLOAD_QUEUE = '11'   # Shares download bandwidth among destination ports.
  _DOWNLOAD_RULE = '5100'  # Specifies when the download queue is used.
  _QUEUE_SLOTS = 100       # Number of packets to queue.

  _BANDWIDTH_RE = re.compile(BANDWIDTH_PATTERN)

  def __init__(self,
               dont_use=None,
               host='127.0.0.1',
               ports=None,
               up_bandwidth='0',
               down_bandwidth='0',
               delay_ms='0',
               packet_loss_rate='0',
               init_cwnd='0',
               use_loopback=True):
    """Start shaping traffic.

    Args:
      host: a host string (name or IP) for the web proxy.
      ports: a list of ports to shape traffic on.
      up_bandwidth: Upload bandwidth
      down_bandwidth: Download bandwidth
           Bandwidths measured in [K|M]{bit/s|Byte/s}. '0' means unlimited.
      delay_ms: Propagation delay in milliseconds. '0' means no delay.
      packet_loss_rate: Packet loss rate in range [0..1]. '0' means no loss.
      init_cwnd: the initial cwnd setting. '0' means no change.
      use_loopback: True iff shaping is done on the loopback (or equiv) adapter.
    """
    assert dont_use is None  # Force args to be named.
    self.host = host
    self.ports = ports
    self.up_bandwidth = up_bandwidth
    self.down_bandwidth = down_bandwidth
    self.delay_ms = delay_ms
    self.packet_loss_rate = packet_loss_rate
    self.init_cwnd = init_cwnd
    self.use_loopback = use_loopback
    if not self._BANDWIDTH_RE.match(self.up_bandwidth):
      raise BandwidthValueError(self.up_bandwidth)
    if not self._BANDWIDTH_RE.match(self.down_bandwidth):
      raise BandwidthValueError(self.down_bandwidth)
    self.is_shaping = False

  def __enter__(self):
    if self.use_loopback:
      platformsettings.setup_temporary_loopback_config()
    if self.init_cwnd != '0':
      platformsettings.set_temporary_tcp_init_cwnd(self.init_cwnd)
    try:
      ipfw_list = platformsettings.ipfw('list')
      if not ipfw_list.startswith('65535 '):
        logging.warn('ipfw has existing rules:\n%s', ipfw_list)
        self._delete_rules(ipfw_list)
    except Exception:
      pass
    if (self.up_bandwidth == '0' and self.down_bandwidth == '0' and
        self.delay_ms == '0' and self.packet_loss_rate == '0'):
      logging.info('Skipped shaping traffic.')
      return
    if not self.ports:
      raise TrafficShaperException('No ports on which to shape traffic.')

    ports = ','.join(str(p) for p in self.ports)
    half_delay_ms = int(self.delay_ms) / 2  # split over up/down links

    try:
      # Configure upload shaping.
      platformsettings.ipfw(
          'pipe', self._UPLOAD_PIPE,
          'config',
          'bw', self.up_bandwidth,
          'delay', half_delay_ms,
          )
      platformsettings.ipfw(
          'queue', self._UPLOAD_QUEUE,
          'config',
          'pipe', self._UPLOAD_PIPE,
          'plr', self.packet_loss_rate,
          'queue', self._QUEUE_SLOTS,
          'mask', 'src-port', '0xffff',
          )
      platformsettings.ipfw(
          'add', self._UPLOAD_RULE,
          'queue', self._UPLOAD_QUEUE,
          'ip',
          'from', 'any',
          'to', self.host,
          self.use_loopback and 'out' or 'in',
          'dst-port', ports,
          )
      self.is_shaping = True

      # Configure download shaping.
      platformsettings.ipfw(
          'pipe', self._DOWNLOAD_PIPE,
          'config',
          'bw', self.down_bandwidth,
          'delay', half_delay_ms,
          )
      platformsettings.ipfw(
          'queue', self._DOWNLOAD_QUEUE,
          'config',
          'pipe', self._DOWNLOAD_PIPE,
          'plr', self.packet_loss_rate,
          'queue', self._QUEUE_SLOTS,
          'mask', 'dst-port', '0xffff',
          )
      platformsettings.ipfw(
          'add', self._DOWNLOAD_RULE,
          'queue', self._DOWNLOAD_QUEUE,
          'ip',
          'from', self.host,
          'to', 'any',
          'out',
          'src-port', ports,
          )
      logging.info('Started shaping traffic')
    except Exception:
      logging.error('Unable to shape traffic.')
      raise

  def __exit__(self, unused_exc_type, unused_exc_val, unused_exc_tb):
    if self.is_shaping:
      try:
        self._delete_rules()
        logging.info('Stopped shaping traffic')
      except Exception:
        logging.error('Unable to stop shaping traffic.')
        raise

  def _delete_rules(self, ipfw_list=None):
    if ipfw_list is None:
      ipfw_list = platformsettings.ipfw('list')
    existing_rules = set(
        r.split()[0].lstrip('0') for r in ipfw_list.splitlines())
    delete_rules = [r for r in (self._DOWNLOAD_RULE, self._UPLOAD_RULE)
                    if r in existing_rules]
    if delete_rules:
      platformsettings.ipfw('delete', *delete_rules)
