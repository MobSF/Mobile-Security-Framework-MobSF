# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from telemetry.internal.backends.chrome import android_browser_finder
from telemetry.internal.platform import profiler

import py_utils

try:
  from devil.android import device_errors  # pylint: disable=import-error
except ImportError:
  device_errors = None


class AndroidTraceviewProfiler(profiler.Profiler):
  """Collects a Traceview on Android."""

  _DEFAULT_DEVICE_DIR = '/data/local/tmp/traceview'

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(AndroidTraceviewProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)

    if self._browser_backend.device.FileExists(self._DEFAULT_DEVICE_DIR):
      # Note: command must be passed as a string to expand wildcards.
      self._browser_backend.device.RunShellCommand(
          'rm ' + os.path.join(self._DEFAULT_DEVICE_DIR, '*'),
          check_return=True, shell=True)
    else:
      self._browser_backend.device.RunShellCommand(
          ['mkdir', '-p', self._DEFAULT_DEVICE_DIR], check_return=True)
      self._browser_backend.device.RunShellCommand(
          ['chmod', '777', self._DEFAULT_DEVICE_DIR], check_return=True)

    self._trace_files = []
    for pid in self._GetProcessOutputFileMap().iterkeys():
      device_dump_file = '%s/%s.trace' % (self._DEFAULT_DEVICE_DIR, pid)
      self._trace_files.append((pid, device_dump_file))
      self._browser_backend.device.RunShellCommand(
          ['am', 'profile', str(pid), 'start', device_dump_file],
          check_return=True)

  @classmethod
  def name(cls):
    return 'android-traceview'

  @classmethod
  def is_supported(cls, browser_type):
    if browser_type == 'any':
      return android_browser_finder.CanFindAvailableBrowsers()
    return browser_type.startswith('android')

  def CollectProfile(self):
    output_files = []
    for pid, trace_file in self._trace_files:
      self._browser_backend.device.RunShellCommand(
          ['am', 'profile', str(pid), 'stop'], check_return=True)
      # pylint: disable=cell-var-from-loop
      py_utils.WaitFor(lambda: self._FileSize(trace_file) > 0, timeout=10)
      output_files.append(trace_file)
    self._browser_backend.device.PullFile(
        self._DEFAULT_DEVICE_DIR, self._output_path)
    # Note: command must be passed as a string to expand wildcards.
    self._browser_backend.device.RunShellCommand(
        'rm ' + os.path.join(self._DEFAULT_DEVICE_DIR, '*'),
        check_return=True, shell=True)
    print 'Traceview profiles available in ', self._output_path
    print 'Use third_party/android_tools/sdk/tools/monitor '
    print 'then use "File->Open File" to visualize them.'
    return output_files

  def _FileSize(self, file_name):
    try:
      return self._browser_backend.device.FileSize(file_name)
    except device_errors.CommandFailedError:
      return 0
