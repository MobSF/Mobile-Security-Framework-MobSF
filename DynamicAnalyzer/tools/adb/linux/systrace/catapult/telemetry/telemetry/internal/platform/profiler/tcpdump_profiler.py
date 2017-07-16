# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import signal
import subprocess
import sys
import tempfile

from telemetry.internal.platform import profiler
from telemetry.internal.platform.profiler import android_prebuilt_profiler_helper

_TCP_DUMP_BASE_OPTS = ['-i', 'any', '-p', '-s', '0', '-w']


class _TCPDumpProfilerAndroid(object):
  """An internal class to collect TCP dumps on android.

  This profiler uses pre-built binaries from AOSP.
  See more details in prebuilt/android/README.txt.
  """

  _DEVICE_DUMP_FILE = '/sdcard/tcpdump_profiles/capture.pcap'

  def __init__(self, device, output_path):
    self._device = device
    self._output_path = output_path
    self._device.RunShellCommand(
        ['mkdir', '-p', os.path.dirname(self._DEVICE_DUMP_FILE)],
        check_return=True)
    self._proc = subprocess.Popen(
        [self._device.adb.GetAdbPath(),
         '-s', self._device.adb.GetDeviceSerial(),
         'shell', android_prebuilt_profiler_helper.GetDevicePath('tcpdump')] +
         _TCP_DUMP_BASE_OPTS +
         [self._DEVICE_DUMP_FILE])

  def CollectProfile(self):
    tcpdump_pid = self._device.GetPids('tcpdump')
    if not tcpdump_pid or not 'tcpdump' in tcpdump_pid:
      raise Exception('Unable to find TCPDump. Check your device is rooted '
          'and tcpdump is installed at ' +
          android_prebuilt_profiler_helper.GetDevicePath('tcpdump'))
    if len(tcpdump_pid['tcpdump']) > 1:
      raise Exception(
          'At most one instance of process tcpdump expected but found pids: '
          '%s' % tcpdump_pid)
    tcpdump_pid = int(tcpdump_pid['tcpdump'][0])
    self._device.RunShellCommand(
        ['kill', '-term', str(tcpdump_pid)], check_return=True)
    self._proc.terminate()
    host_dump = os.path.join(self._output_path,
                             os.path.basename(self._DEVICE_DUMP_FILE))
    self._device.PullFile(self._DEVICE_DUMP_FILE, host_dump)
    print 'TCP dump available at: %s ' % host_dump
    print 'Use Wireshark to open it.'
    return host_dump


class _TCPDumpProfilerLinux(object):
  """An internal class to collect TCP dumps on linux desktop."""

  _DUMP_FILE = 'capture.pcap'

  def __init__(self, output_path):
    if not os.path.exists(output_path):
      os.makedirs(output_path)
    self._dump_file = os.path.join(output_path, self._DUMP_FILE)
    self._tmp_output_file = tempfile.NamedTemporaryFile('w', 0)
    try:
      self._proc = subprocess.Popen(
          ['tcpdump'] + _TCP_DUMP_BASE_OPTS + [self._dump_file],
          stdout=self._tmp_output_file, stderr=subprocess.STDOUT)
    except OSError as e:
      raise Exception('Unable to execute TCPDump, please check your '
          'installation. ' + str(e))

  def CollectProfile(self):
    self._proc.send_signal(signal.SIGINT)
    exit_code = self._proc.wait()
    try:
      if exit_code:
        raise Exception(
            'tcpdump failed with exit code %d. Output:\n%s' %
            (exit_code, self._GetStdOut()))
    finally:
      self._tmp_output_file.close()
    print 'TCP dump available at: ', self._dump_file
    print 'Use Wireshark to open it.'
    return self._dump_file

  def _GetStdOut(self):
    self._tmp_output_file.flush()
    try:
      with open(self._tmp_output_file.name) as f:
        return f.read()
    except IOError:
      return ''


class TCPDumpProfiler(profiler.Profiler):
  """A Factory to instantiate the platform-specific profiler."""
  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(TCPDumpProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    if platform_backend.GetOSName() == 'android':
      android_prebuilt_profiler_helper.InstallOnDevice(
          browser_backend.device, 'tcpdump')
      self._platform_profiler = _TCPDumpProfilerAndroid(
          browser_backend.device, output_path)
    else:
      self._platform_profiler = _TCPDumpProfilerLinux(output_path)

  @classmethod
  def name(cls):
    return 'tcpdump'

  @classmethod
  def is_supported(cls, browser_type):
    if browser_type.startswith('cros'):
      return False
    if sys.platform.startswith('linux'):
      return True
    return browser_type.startswith('android')

  def CollectProfile(self):
    return self._platform_profiler.CollectProfile()
