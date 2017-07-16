# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from devil.android import device_blacklist
from devil.android import device_errors
from devil.android import device_utils


def GetDevices(requested_devices, blacklist_file):
  if not isinstance(blacklist_file, device_blacklist.Blacklist):
    blacklist_file = (device_blacklist.Blacklist(blacklist_file)
                      if blacklist_file
                      else None)

  devices = device_utils.DeviceUtils.HealthyDevices(blacklist_file)
  if not devices:
    raise device_errors.NoDevicesError()
  elif requested_devices:
    requested = set(requested_devices)
    available = set(str(d) for d in devices)
    missing = requested.difference(available)
    if missing:
      raise device_errors.DeviceUnreachableError(next(iter(missing)))
    return sorted(device_utils.DeviceUtils(d)
                  for d in available.intersection(requested))
  else:
    return devices

