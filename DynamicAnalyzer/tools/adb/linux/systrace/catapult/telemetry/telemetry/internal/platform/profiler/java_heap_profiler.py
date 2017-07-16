# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import subprocess
import threading

from telemetry.core import platform
from telemetry.internal.backends.chrome import android_browser_finder
from telemetry.internal.platform import profiler
from telemetry.internal.util import binary_manager

import py_utils

try:
  from devil.android import device_errors  # pylint: disable=import-error
except ImportError:
  device_errors = None


class JavaHeapProfiler(profiler.Profiler):
  """Android-specific, trigger and fetch java heap dumps."""

  _DEFAULT_DEVICE_DIR = '/data/local/tmp/javaheap'
  # TODO(bulach): expose this as a command line option somehow.
  _DEFAULT_INTERVAL = 20
  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(JavaHeapProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    self._run_count = 1

    self._DumpJavaHeap(False)

    self._timer = threading.Timer(self._DEFAULT_INTERVAL, self._OnTimer)
    self._timer.start()

  @classmethod
  def name(cls):
    return 'java-heap'

  @classmethod
  def is_supported(cls, browser_type):
    if browser_type == 'any':
      return android_browser_finder.CanFindAvailableBrowsers()
    return browser_type.startswith('android')

  def CollectProfile(self):
    self._timer.cancel()
    self._DumpJavaHeap(True)
    self._browser_backend.device.PullFile(
        self._DEFAULT_DEVICE_DIR, self._output_path)
    # Note: command must be passed as a string to expand wildcards.
    self._browser_backend.device.RunShellCommand(
        'rm -f ' + os.path.join(self._DEFAULT_DEVICE_DIR, '*'),
        check_return=True, shell=True)
    output_files = []
    for f in os.listdir(self._output_path):
      if os.path.splitext(f)[1] == '.aprof':
        input_file = os.path.join(self._output_path, f)
        output_file = input_file.replace('.aprof', '.hprof')
        hprof_conv = binary_manager.FetchPath(
            'hprof-conv',
            platform.GetHostPlatform().GetArchName(),
            platform.GetHostPlatform().GetOSName())
        subprocess.call([hprof_conv, input_file, output_file])
        output_files.append(output_file)
    return output_files

  def _OnTimer(self):
    self._DumpJavaHeap(False)

  def _DumpJavaHeap(self, wait_for_completion):
    if not self._browser_backend.device.FileExists(
        self._DEFAULT_DEVICE_DIR):
      self._browser_backend.device.RunShellCommand(
          ['mkdir', '-p', self._DEFAULT_DEVICE_DIR], check_return=True)
      self._browser_backend.device.RunShellCommand(
          ['chmod', '777', self._DEFAULT_DEVICE_DIR], check_return=True)

    device_dump_file = None
    for pid in self._GetProcessOutputFileMap().iterkeys():
      device_dump_file = '%s/%s.%s.aprof' % (self._DEFAULT_DEVICE_DIR, pid,
                                             self._run_count)
      self._browser_backend.device.RunShellCommand(
          ['am', 'dumpheap', str(pid), device_dump_file], check_return=True)
    if device_dump_file and wait_for_completion:
      py_utils.WaitFor(lambda: self._FileSize(device_dump_file) > 0, timeout=2)
    self._run_count += 1

  def _FileSize(self, file_name):
    try:
      return self._browser_backend.device.FileSize(file_name)
    except device_errors.CommandFailedError:
      return 0
