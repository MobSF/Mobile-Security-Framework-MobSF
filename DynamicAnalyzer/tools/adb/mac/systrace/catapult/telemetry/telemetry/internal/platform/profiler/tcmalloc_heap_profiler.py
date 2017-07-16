# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import sys

from telemetry.internal.backends.chrome import android_browser_finder
from telemetry.internal.platform import profiler

# Environment variables to (android properties, default value) mapping.
_ENV_VARIABLES = {
  'HEAP_PROFILE_TIME_INTERVAL': ('heapprof.time_interval', 20),
  'HEAP_PROFILE_MMAP': ('heapprof.mmap', 1),
  'DEEP_HEAP_PROFILE': ('heapprof.deep_heap_profile', 1),
}


class _TCMallocHeapProfilerAndroid(object):
  """An internal class to set android properties and fetch dumps from device."""

  _DEFAULT_DEVICE_DIR = '/data/local/tmp/heap'

  def __init__(self, browser_backend, output_path):
    self._browser_backend = browser_backend
    self._output_path = output_path

    _ENV_VARIABLES['HEAPPROFILE'] = ('heapprof',
        os.path.join(self._DEFAULT_DEVICE_DIR, 'dmprof'))

    self._SetDeviceProperties(_ENV_VARIABLES)

  def _SetDeviceProperties(self, properties):
    device_configured = False
    # This profiler requires adb root to set properties.
    self._browser_backend.device.EnableRoot()
    for values in properties.itervalues():
      device_property = self._browser_backend.device.GetProp(values[0])
      if not device_property or not device_property.strip():
        self._browser_backend.device.SetProp(values[0], values[1])
        device_configured = True
    if not self._browser_backend.device.FileExists(
        self._DEFAULT_DEVICE_DIR):
      self._browser_backend.device.RunShellCommand(
          ['mkdir', '-p', self._DEFAULT_DEVICE_DIR], check_return=True)
      self._browser_backend.device.RunShellCommand(
          ['chmod', '777', self._DEFAULT_DEVICE_DIR], check_return=True)
      device_configured = True
    if device_configured:
      raise Exception('Device required special config, run again.')

  def CollectProfile(self):
    try:
      self._browser_backend.device.PullFile(
          self._DEFAULT_DEVICE_DIR, self._output_path)
    except:
      logging.exception('New exception caused by DeviceUtils conversion')
      raise
    # Note: command must be passed as a string to expand wildcards.
    self._browser_backend.device.RunShellCommand(
        'rm -f ' + os.path.join(self._DEFAULT_DEVICE_DIR, '*'),
        check_return=True, shell=True)
    if os.path.exists(self._output_path):
      logging.info('TCMalloc dumps pulled to %s', self._output_path)
      with file(os.path.join(self._output_path,
                             'browser.pid'), 'w') as pid_file:
        pid_file.write(str(self._browser_backend.pid).rjust(5, '0'))
    return [self._output_path]


class _TCMallocHeapProfilerLinux(object):
  """An internal class to set environment variables and fetch dumps."""

  _DEFAULT_DIR = '/tmp/tcmalloc/'

  def __init__(self, browser_backend):
    self._browser_backend = browser_backend
    _ENV_VARIABLES['HEAPPROFILE'] = ('heapprof', self._DEFAULT_DIR + 'dmprof')
    self._CheckEnvironmentVariables(_ENV_VARIABLES)

  def _CheckEnvironmentVariables(self, env_vars):
    msg = ''
    for key, values in env_vars.iteritems():
      if key not in os.environ:
        msg += '%s=%s ' % (key, str(values[1]))
    if msg:
      raise Exception('Need environment variables, try again with:\n %s' % msg)
    if not os.path.exists(os.environ['HEAPPROFILE']):
      os.makedirs(os.environ['HEAPPROFILE'])
    assert os.path.isdir(os.environ['HEAPPROFILE']), 'HEAPPROFILE is not a dir'

  def CollectProfile(self):
    with file(os.path.join(os.path.dirname(os.environ['HEAPPROFILE']),
                           'browser.pid'), 'w') as pid_file:
      pid_file.write(str(self._browser_backend.pid))
    print 'TCMalloc dumps available ', os.environ['HEAPPROFILE']
    return [os.environ['HEAPPROFILE']]


class TCMallocHeapProfiler(profiler.Profiler):
  """A Factory to instantiate the platform-specific profiler."""
  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(TCMallocHeapProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    if platform_backend.GetOSName() == 'android':
      self._platform_profiler = _TCMallocHeapProfilerAndroid(
          browser_backend, output_path)
    else:
      self._platform_profiler = _TCMallocHeapProfilerLinux(browser_backend)

  @classmethod
  def name(cls):
    return 'tcmalloc-heap'

  @classmethod
  def is_supported(cls, browser_type):
    if browser_type.startswith('cros'):
      return False
    if sys.platform.startswith('linux'):
      return True
    if browser_type == 'any':
      return android_browser_finder.CanFindAvailableBrowsers()
    return browser_type.startswith('android')

  @classmethod
  def CustomizeBrowserOptions(cls, browser_type, options):
    options.AppendExtraBrowserArgs('--no-sandbox')
    options.AppendExtraBrowserArgs('--enable-memory-benchmarking')

  @classmethod
  def WillCloseBrowser(cls, browser_backend, platform_backend):
    # The tcmalloc_heap_profiler dumps files at regular
    # intervals (~20 secs).
    # This is a minor optimization to ensure it'll dump the last file when
    # the test completes.
    for i in xrange(len(browser_backend.browser.tabs)):
      browser_backend.browser.tabs[i].ExecuteJavaScript("""
        if (chrome && chrome.memoryBenchmarking) {
          chrome.memoryBenchmarking.heapProfilerDump('renderer', 'final');
          chrome.memoryBenchmarking.heapProfilerDump('browser', 'final');
        }
      """)

  def CollectProfile(self):
    return self._platform_profiler.CollectProfile()
