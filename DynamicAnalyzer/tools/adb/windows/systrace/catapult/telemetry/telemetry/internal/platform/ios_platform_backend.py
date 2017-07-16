# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry.internal.platform import posix_platform_backend

#TODO(baxley): Put in real values.
class IosPlatformBackend(posix_platform_backend.PosixPlatformBackend):
  def __init__(self):
    super(IosPlatformBackend, self).__init__()

  def GetOSName(self):
    # TODO(baxley): Get value from ideviceinfo.
    logging.warn('Not implemented')
    return 'ios'

  def GetOSVersionName(self):
    # TODO(baxley): Get value from ideviceinfo.
    logging.warn('Not implemented')
    return '7.1'

  def SetFullPerformanceModeEnabled(self, enabled):
    logging.warn('Not implemented')
    return

  def FlushDnsCache(self):
    logging.warn('Not implemented')
    return

  def CanMonitorThermalThrottling(self):
    logging.warn('Not implemented')
    return False

  def CanMonitorPower(self):
    logging.warn('Not implemented')
    return False

  def StartMonitoringPower(self, browser):
    raise NotImplementedError()

  def StopMonitoringPower(self):
    raise NotImplementedError()

  def FlushEntireSystemCache(self):
    raise NotImplementedError()

  def HasBeenThermallyThrottled(self):
    raise NotImplementedError()

  def StopVideoCapture(self):
    raise NotImplementedError()

  def IsThermallyThrottled(self):
    raise NotImplementedError()

  def GetSystemTotalPhysicalMemory(self):
    raise NotImplementedError()

  def InstallApplication(self, application):
    raise NotImplementedError()
