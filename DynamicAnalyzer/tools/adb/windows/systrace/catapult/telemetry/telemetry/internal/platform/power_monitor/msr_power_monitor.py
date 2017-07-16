# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import platform
import re

from telemetry import decorators
from telemetry.internal.platform import power_monitor


MSR_RAPL_POWER_UNIT = 0x606
MSR_PKG_ENERGY_STATUS = 0x611  # Whole package
MSR_PP0_ENERGY_STATUS = 0x639  # Core
MSR_PP1_ENERGY_STATUS = 0x641  # Uncore
MSR_DRAM_ENERGY_STATUS = 0x619
IA32_PACKAGE_THERM_STATUS = 0x1b1
IA32_TEMPERATURE_TARGET = 0x1a2


def _JoulesToMilliwattHours(value_joules):
  return value_joules * 1000 / 3600.


def _IsSandyBridgeOrLater(vendor, family, model):
  # Model numbers from:
  # https://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers
  # http://www.speedtraq.com
  return ('Intel' in vendor and family == 6 and
          (model in (0x2A, 0x2D) or model >= 0x30))


class MsrPowerMonitor(power_monitor.PowerMonitor):
  def __init__(self, backend):
    super(MsrPowerMonitor, self).__init__()
    self._backend = backend
    self._start_energy_j = None
    self._start_temp_c = None

  def CanMonitorPower(self):
    raise NotImplementedError()

  def StartMonitoringPower(self, browser):
    self._CheckStart()
    self._start_energy_j = self._PackageEnergyJoules()
    self._start_temp_c = self._TemperatureCelsius()

  def StopMonitoringPower(self):
    self._CheckStop()
    energy_consumption_j = self._PackageEnergyJoules() - self._start_energy_j
    average_temp_c = (self._TemperatureCelsius() + self._start_temp_c) / 2.
    if energy_consumption_j < 0:  # Correct overflow.
      # The energy portion of the MSR is 4 bytes.
      energy_consumption_j += 2 ** 32 * self._EnergyMultiplier()

    self._start_energy_j = None
    self._start_temp_c = None

    return {
        'identifier': 'msr',
        'energy_consumption_mwh': _JoulesToMilliwattHours(energy_consumption_j),
        'platform_info': {
            'average_temperature_c': average_temp_c,
        },
    }

  @decorators.Cache
  def _EnergyMultiplier(self):
    return 0.5 ** self._backend.ReadMsr(MSR_RAPL_POWER_UNIT, 8, 5)

  def _PackageEnergyJoules(self):
    return (self._backend.ReadMsr(MSR_PKG_ENERGY_STATUS, 0, 32) *
            self._EnergyMultiplier())

  def _TemperatureCelsius(self):
    tcc_activation_temp = self._backend.ReadMsr(IA32_TEMPERATURE_TARGET, 16, 7)
    if tcc_activation_temp <= 0:
      tcc_activation_temp = 105
    package_temp_headroom = self._backend.ReadMsr(
        IA32_PACKAGE_THERM_STATUS, 16, 7)
    return tcc_activation_temp - package_temp_headroom

  def _CheckMSRs(self):
    try:
      if self._PackageEnergyJoules() <= 0:
        logging.info('Cannot monitor power: no energy readings.')
        return False

      if self._TemperatureCelsius() <= 0:
        logging.info('Cannot monitor power: no temperature readings.')
        return False
    except OSError as e:
      logging.info('Cannot monitor power: %s' % e)
      return False
    return True


class MsrPowerMonitorLinux(MsrPowerMonitor):
  def CanMonitorPower(self):
    vendor = None
    family = None
    model = None
    cpuinfo = open('/proc/cpuinfo').read().splitlines()
    for line in cpuinfo:
      if vendor and family and model:
        break
      if line.startswith('vendor_id'):
        vendor = line.split('\t')[1]
      elif line.startswith('cpu family'):
        family = int(line.split(' ')[2])
      elif line.startswith('model\t\t'):
        model = int(line.split(' ')[1])
    if not _IsSandyBridgeOrLater(vendor, family, model):
      logging.info('Cannot monitor power: pre-Sandy Bridge CPU.')
      return False

    if not self._CheckMSRs():
      logging.info('Try running tools/telemetry/build/linux_setup_msr.py.')
      return False

    return True


class MsrPowerMonitorWin(MsrPowerMonitor):
  def CanMonitorPower(self):
    family, model = map(int, re.match('.+ Family ([0-9]+) Model ([0-9]+)',
                        platform.processor()).groups())
    if not _IsSandyBridgeOrLater(platform.processor(), family, model):
      logging.info('Cannot monitor power: pre-Sandy Bridge CPU.')
      return False

    try:
      return self._CheckMSRs()
    finally:
      # Since _CheckMSRs() starts the MSR server on win platform, we must close
      # it after checking to avoid leaking msr server process.
      self._backend.CloseMsrServer()

  def StopMonitoringPower(self):
    power_statistics = super(MsrPowerMonitorWin, self).StopMonitoringPower()
    self._backend.CloseMsrServer()
    return power_statistics
