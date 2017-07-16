# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import signal
import sys

from telemetry.core import exceptions
from telemetry.internal.platform import profiler

import py_utils

try:
  import pexpect  # pylint: disable=import-error
except ImportError:
  pass


class _SingleProcessIprofilerProfiler(object):
  """An internal class for using iprofiler for a given process."""
  def __init__(self, pid, output_path):
    self._output_path = output_path
    output_dir = os.path.dirname(self._output_path)
    output_file = os.path.basename(self._output_path)
    self._proc = pexpect.spawn(
        'iprofiler', ['-timeprofiler', '-T', '300', '-a', str(pid),
                      '-d', output_dir, '-o', output_file],
        timeout=300)
    while True:
      if self._proc.getecho():
        output = self._proc.readline().strip()
        if not output:
          continue
        if 'iprofiler: Profiling process' in output:
          break
        print output
      self._proc.interact(escape_character='\x0d')
      if 'Failed to authorize rights' in output:
        raise exceptions.ProfilingException(
            'Failed to authorize rights for iprofiler\n')
      if 'iprofiler error' in output:
        raise exceptions.ProfilingException(
            'Failed to start iprofiler for process %s\n' %
            self._output_path.split('.')[1])
      self._proc.write('\x0d')
      print
      def Echo():
        return self._proc.getecho()
      py_utils.WaitFor(Echo, timeout=5)

  def CollectProfile(self):
    self._proc.kill(signal.SIGINT)
    try:
      self._proc.wait()
    except pexpect.ExceptionPexpect:
      pass
    finally:
      self._proc = None

    print 'To view the profile, run:'
    print '  open -a Instruments %s.dtps' % self._output_path
    return self._output_path


class IprofilerProfiler(profiler.Profiler):

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(IprofilerProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    process_output_file_map = self._GetProcessOutputFileMap()
    self._process_profilers = []
    for pid, output_file in process_output_file_map.iteritems():
      if '.utility' in output_file:
        # The utility process may not have been started by Telemetry.
        # So we won't have permissing to profile it
        continue
      self._process_profilers.append(
          _SingleProcessIprofilerProfiler(pid, output_file))

  @classmethod
  def name(cls):
    return 'iprofiler'

  @classmethod
  def is_supported(cls, browser_type):
    if sys.platform != 'darwin':
      return False
    if browser_type == 'any':
      return True
    return (not browser_type.startswith('android') and
            not browser_type.startswith('cros'))

  def CollectProfile(self):
    output_files = []
    for single_process in self._process_profilers:
      output_files.append(single_process.CollectProfile())
    return output_files
