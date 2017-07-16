# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import os
import py_utils
import re

from profile_chrome import util
from systrace import trace_result
from systrace import tracing_agents


_DDMS_SAMPLING_FREQUENCY_US = 100


class DdmsAgent(tracing_agents.TracingAgent):
  def __init__(self, device, package_info):
    tracing_agents.TracingAgent.__init__(self)
    self._device = device
    self._package = package_info.package
    self._output_file = None
    self._supports_sampling = self._SupportsSampling()

  def __repr__(self):
    return 'ddms profile'

  def _SupportsSampling(self):
    for line in self._device.RunShellCommand(
        ['am', '--help'], check_return=True):
      if re.match(r'.*am profile start.*--sampling', line):
        return True
    return False

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StartAgentTracing(self, config, timeout=None):
    self._output_file = (
        '/data/local/tmp/ddms-profile-%s' % util.GetTraceTimestamp())
    cmd = ['am', 'profile', 'start']
    if self._supports_sampling:
      cmd.extend(['--sampling', str(_DDMS_SAMPLING_FREQUENCY_US)])
    cmd.extend([self._package, self._output_file])
    self._device.RunShellCommand(cmd, check_return=True)
    return True

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StopAgentTracing(self, timeout=None):
    self._device.RunShellCommand(
        ['am', 'profile', 'stop', self._package], check_return=True)
    return True

  @py_utils.Timeout(tracing_agents.GET_RESULTS_TIMEOUT)
  def GetResults(self, timeout=None):
    with open(self._PullTrace(), 'r') as f:
      trace_data = f.read()
    return trace_result.TraceResult('ddms', trace_data)

  def _PullTrace(self):
    if not self._output_file:
      return None

    host_file = os.path.join(
        os.path.curdir, os.path.basename(self._output_file))
    self._device.PullFile(self._output_file, host_file)
    return host_file

  def SupportsExplicitClockSync(self):
    return False

  def RecordClockSyncMarker(self, sync_id, did_record_sync_marker_callback):
    # pylint: disable=unused-argument
    assert self.SupportsExplicitClockSync(), ('Clock sync marker cannot be '
        'recorded since explicit clock sync is not supported.')


class DdmsConfig(tracing_agents.TracingConfig):
  def __init__(self, device, package_info, ddms):
    tracing_agents.TracingConfig.__init__(self)
    self.device = device
    self.package_info = package_info
    self.ddms = ddms


def try_create_agent(config):
  if config.ddms:
    return DdmsAgent(config.device, config.package_info)
  return None

def add_options(parser):
  options = optparse.OptionGroup(parser, 'Java tracing')
  options.add_option('--ddms', help='Trace Java execution using DDMS '
                     'sampling.', action='store_true')
  return options

def get_config(options):
  return DdmsConfig(options.device, options.package_info, options.ddms)
