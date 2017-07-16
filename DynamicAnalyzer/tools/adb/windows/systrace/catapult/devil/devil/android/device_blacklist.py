# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)


class Blacklist(object):

  def __init__(self, path):
    self._blacklist_lock = threading.RLock()
    self._path = path

  def Read(self):
    """Reads the blacklist from the blacklist file.

    Returns:
      A dict containing bad devices.
    """
    with self._blacklist_lock:
      blacklist = dict()
      if not os.path.exists(self._path):
        return blacklist

      try:
        with open(self._path, 'r') as f:
          blacklist = json.load(f)
      except (IOError, ValueError) as e:
        logger.warning('Unable to read blacklist: %s', str(e))
        os.remove(self._path)

      if not isinstance(blacklist, dict):
        logger.warning('Ignoring %s: %s (a dict was expected instead)',
                        self._path, blacklist)
        blacklist = dict()

      return blacklist

  def Write(self, blacklist):
    """Writes the provided blacklist to the blacklist file.

    Args:
      blacklist: list of bad devices to write to the blacklist file.
    """
    with self._blacklist_lock:
      with open(self._path, 'w') as f:
        json.dump(blacklist, f)

  def Extend(self, devices, reason='unknown'):
    """Adds devices to blacklist file.

    Args:
      devices: list of bad devices to be added to the blacklist file.
      reason: string specifying the reason for blacklist (eg: 'unauthorized')
    """
    timestamp = time.time()
    event_info = {
        'timestamp': timestamp,
        'reason': reason,
    }
    device_dicts = {device: event_info for device in devices}
    logger.info('Adding %s to blacklist %s for reason: %s',
                 ','.join(devices), self._path, reason)
    with self._blacklist_lock:
      blacklist = self.Read()
      blacklist.update(device_dicts)
      self.Write(blacklist)

  def Reset(self):
    """Erases the blacklist file if it exists."""
    logger.info('Resetting blacklist %s', self._path)
    with self._blacklist_lock:
      if os.path.exists(self._path):
        os.remove(self._path)
