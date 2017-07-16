# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A module to keep track of devices across builds."""

import json
import logging
import os

logger = logging.getLogger(__name__)


def GetPersistentDeviceList(file_name):
  """Returns a list of devices.

  Args:
    file_name: the file name containing a list of devices.

  Returns: List of device serial numbers that were on the bot.
  """
  if not os.path.isfile(file_name):
    logger.warning("Device file %s doesn't exist.", file_name)
    return []

  try:
    with open(file_name) as f:
      devices = json.load(f)
    if not isinstance(devices, list) or not all(isinstance(d, basestring)
                                                for d in devices):
      logger.warning('Unrecognized device file format: %s', devices)
      return []
    return [d for d in devices if d != '(error)']
  except ValueError:
    logger.exception(
        'Error reading device file %s. Falling back to old format.', file_name)

  # TODO(bpastene) Remove support for old unstructured file format.
  with open(file_name) as f:
    return [d for d in f.read().splitlines() if d != '(error)']


def WritePersistentDeviceList(file_name, device_list):
  path = os.path.dirname(file_name)
  assert isinstance(device_list, list)
  # If there is a problem with ADB "(error)" can be added to the device list.
  # These should be removed before saving.
  device_list = [d for d in device_list if d != '(error)']
  if not os.path.exists(path):
    os.makedirs(path)
  with open(file_name, 'w') as f:
    json.dump(device_list, f)
