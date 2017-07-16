# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry.internal.platform import power_monitor


class AndroidPowerMonitorBase(power_monitor.PowerMonitor):

  # Abstract class.
  # pylint: disable=abstract-method

  def _ParseVoltage(self, millivolts):
    # Parse voltage information.
    # If voltage is None, use 4.0 as default.
    # Otherwise, convert millivolts to volts.
    if millivolts is None:
      # Converting at a nominal voltage of 4.0V, as those values are obtained by
      # a heuristic, and 4.0V is the voltage we set when using a monsoon device.
      voltage = 4.0
      logging.warning('Unable to get device voltage. Using %s.', voltage)
    else:
      voltage = float(millivolts) / 1000
      logging.info('Device voltage at %s', voltage)
      return voltage

  def _LogPowerAnomalies(self, power_data, package):
    # Log anomalies in power data.
    if power_data['energy_consumption_mwh'] == 0:
      logging.warning('Power data is returning 0 for system total usage. %s'
                      % (power_data))
      if power_data['application_energy_consumption_mwh'] == 0:
        logging.warning('Power data is returning 0 usage for %s. %s'
                        % (package, power_data))
