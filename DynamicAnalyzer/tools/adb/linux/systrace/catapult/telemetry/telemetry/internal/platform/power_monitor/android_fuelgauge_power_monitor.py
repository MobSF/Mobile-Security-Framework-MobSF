# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.platform.power_monitor import android_power_monitor_base


class FuelGaugePowerMonitor(android_power_monitor_base.AndroidPowerMonitorBase):
  """PowerMonitor that relies on the fuel gauge chips to monitor the power
  consumption of a android device.
  """
  def __init__(self, battery):
    """Constructor.

    Args:
        battery: A BatteryUtil instance.
        platform_backend: A LinuxBasedPlatformBackend instance.
    """
    super(FuelGaugePowerMonitor, self).__init__()
    self._battery = battery
    self._starting_fuel_gauge = None

  def CanMonitorPower(self):
    return self._battery.SupportsFuelGauge()

  def StartMonitoringPower(self, browser):
    self._CheckStart()
    self._starting_fuel_gauge = self._battery.GetFuelGaugeChargeCounter()

  def StopMonitoringPower(self):
    self._CheckStop()
    # Convert from nAh to mAh.
    fuel_gauge_delta = (
        float((self._starting_fuel_gauge) -
        self._battery.GetFuelGaugeChargeCounter()) / 1000000)
    voltage = self._ParseVoltage(self._battery.GetBatteryInfo().get('voltage'))
    return self.ProcessPowerData(voltage, fuel_gauge_delta)

  @staticmethod
  def ProcessPowerData(voltage, fuel_gauge_delta):
    return {'identifier': 'fuel_gauge',
            'fuel_gauge_energy_consumption_mwh': fuel_gauge_delta * voltage}
