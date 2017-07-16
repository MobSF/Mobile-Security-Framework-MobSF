# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

class MockBrowserBackend(object):
  def __init__(self, package):
    self.package = package

class MockBrowser(object):
  def __init__(self, package):
    self._browser_backend = MockBrowserBackend(package)

class MockBattery(object):
  def __init__(self,
               power_results,
               starts_charging=True,
               voltage=4.0,
               fuelgauge=None):
    # voltage in millivolts
    self._power_results = power_results
    self._charging = starts_charging
    self._voltage = voltage
    self._fuelgauge = fuelgauge if fuelgauge else []
    self._fuel_idx = 0

  def SupportsFuelGauge(self):
    return len(self._fuelgauge) >= 0

  def GetFuelGaugeChargeCounter(self):
    try:
      x = self._fuelgauge[self._fuel_idx]
      self._fuel_idx += 1
      return x
    except IndexError:
      assert False, "Too many GetFuelGaugeChargeCounter() calls."

  def GetCharging(self):
    return self._charging

  def SetCharging(self, charging):
    if charging:
      assert not self._charging, "Mock battery already charging."
      self._charging = True
    else:
      assert self._charging, "Mock battery already not charging."
      self._charging = False

  def GetPowerData(self):
    return self._power_results

  def GetBatteryInfo(self):
    # the voltage returned by GetBatteryInfo() is in millivolts
    return {'voltage': int(self._voltage*1000)}

class MockPlatformBackend(object):
  def __init__(self, command_dict=None):
    self._cdict = (command_dict if command_dict else {})

  def RunCommand(self, command):
    assert command in self._cdict, "Mock platform error: Unexpected command."
    return self._cdict[command]
