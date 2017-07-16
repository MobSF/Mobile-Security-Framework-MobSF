# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import sys

from py_utils import cloud_storage  # pylint: disable=import-error

from telemetry.core import exceptions
from telemetry.core import profiling_controller
from telemetry import decorators
from telemetry.internal import app
from telemetry.internal.backends import browser_backend
from telemetry.internal.browser import browser_credentials
from telemetry.internal.browser import extension_dict
from telemetry.internal.browser import tab_list
from telemetry.internal.browser import web_contents
from telemetry.internal.util import exception_formatter


class Browser(app.App):
  """A running browser instance that can be controlled in a limited way.

  To create a browser instance, use browser_finder.FindBrowser.

  Be sure to clean up after yourself by calling Close() when you are done with
  the browser. Or better yet:
    browser_to_create = FindBrowser(options)
    with browser_to_create.Create(options) as browser:
      ... do all your operations on browser here
  """
  def __init__(self, backend, platform_backend, credentials_path):
    super(Browser, self).__init__(app_backend=backend,
                                  platform_backend=platform_backend)
    try:
      self._browser_backend = backend
      self._platform_backend = platform_backend
      self._tabs = tab_list.TabList(backend.tab_list_backend)
      self.credentials = browser_credentials.BrowserCredentials()
      self.credentials.credentials_path = credentials_path
      self._platform_backend.DidCreateBrowser(self, self._browser_backend)
      browser_options = self._browser_backend.browser_options
      self.platform.FlushDnsCache()
      if browser_options.clear_sytem_cache_for_browser_and_profile_on_start:
        if self.platform.CanFlushIndividualFilesFromSystemCache():
          self.platform.FlushSystemCacheForDirectory(
              self._browser_backend.profile_directory)
          self.platform.FlushSystemCacheForDirectory(
              self._browser_backend.browser_directory)
        elif self.platform.SupportFlushEntireSystemCache():
          self.platform.FlushEntireSystemCache()
        else:
          logging.warning('Flush system cache is not supported. ' +
              'Did not flush system cache.')

      self._browser_backend.SetBrowser(self)
      self._browser_backend.Start()
      self._LogBrowserInfo()
      self._platform_backend.DidStartBrowser(self, self._browser_backend)
      self._profiling_controller = profiling_controller.ProfilingController(
          self._browser_backend.profiling_controller_backend)
    except Exception:
      exc_info = sys.exc_info()
      logging.exception('Failure while starting browser backend.')
      try:
        self._platform_backend.WillCloseBrowser(self, self._browser_backend)
      except Exception:
        exception_formatter.PrintFormattedException(
            msg='Exception raised while closing platform backend')
      raise exc_info[0], exc_info[1], exc_info[2]

  @property
  def profiling_controller(self):
    return self._profiling_controller

  @property
  def browser_type(self):
    return self.app_type

  @property
  def supports_extensions(self):
    return self._browser_backend.supports_extensions

  @property
  def supports_tab_control(self):
    return self._browser_backend.supports_tab_control

  @property
  def tabs(self):
    return self._tabs

  @property
  def foreground_tab(self):
    for i in xrange(len(self._tabs)):
      # The foreground tab is the first (only) one that isn't hidden.
      # This only works through luck on Android, due to crbug.com/322544
      # which means that tabs that have never been in the foreground return
      # document.hidden as false; however in current code the Android foreground
      # tab is always tab 0, which will be the first one that isn't hidden
      if self._tabs[i].EvaluateJavaScript('!document.hidden'):
        return self._tabs[i]
    raise Exception("No foreground tab found")

  @property
  @decorators.Cache
  def extensions(self):
    if not self.supports_extensions:
      raise browser_backend.ExtensionsNotSupportedException(
          'Extensions not supported')
    return extension_dict.ExtensionDict(self._browser_backend.extension_backend)

  def _LogBrowserInfo(self):
    logging.info('OS: %s %s',
                 self._platform_backend.platform.GetOSName(),
                 self._platform_backend.platform.GetOSVersionName())
    if self.supports_system_info:
      system_info = self.GetSystemInfo()
      if system_info.model_name:
        logging.info('Model: %s', system_info.model_name)
      if system_info.gpu:
        for i, device in enumerate(system_info.gpu.devices):
          logging.info('GPU device %d: %s', i, device)
        if system_info.gpu.aux_attributes:
          logging.info('GPU Attributes:')
          for k, v in sorted(system_info.gpu.aux_attributes.iteritems()):
            logging.info('  %-20s: %s', k, v)
        if system_info.gpu.feature_status:
          logging.info('Feature Status:')
          for k, v in sorted(system_info.gpu.feature_status.iteritems()):
            logging.info('  %-20s: %s', k, v)
        if system_info.gpu.driver_bug_workarounds:
          logging.info('Driver Bug Workarounds:')
          for workaround in system_info.gpu.driver_bug_workarounds:
            logging.info('  %s', workaround)
      else:
        logging.info('No GPU devices')
    else:
      logging.warning('System info not supported')

  def _GetStatsCommon(self, pid_stats_function):
    browser_pid = self._browser_backend.pid
    result = {
        'Browser': dict(pid_stats_function(browser_pid), **{'ProcessCount': 1}),
        'Renderer': {'ProcessCount': 0},
        'Gpu': {'ProcessCount': 0},
        'Other': {'ProcessCount': 0}
    }
    process_count = 1
    for child_pid in self._platform_backend.GetChildPids(browser_pid):
      try:
        child_cmd_line = self._platform_backend.GetCommandLine(child_pid)
        child_stats = pid_stats_function(child_pid)
      except exceptions.ProcessGoneException:
        # It is perfectly fine for a process to have gone away between calling
        # GetChildPids() and then further examining it.
        continue
      child_process_name = self._browser_backend.GetProcessName(child_cmd_line)
      process_name_type_key_map = {'gpu-process': 'Gpu', 'renderer': 'Renderer'}
      if child_process_name in process_name_type_key_map:
        child_process_type_key = process_name_type_key_map[child_process_name]
      else:
        # TODO: identify other process types (zygote, plugin, etc), instead of
        # lumping them in a single category.
        child_process_type_key = 'Other'
      result[child_process_type_key]['ProcessCount'] += 1
      for k, v in child_stats.iteritems():
        if k in result[child_process_type_key]:
          result[child_process_type_key][k] += v
        else:
          result[child_process_type_key][k] = v
      process_count += 1
    for v in result.itervalues():
      if v['ProcessCount'] > 1:
        for k in v.keys():
          if k.endswith('Peak'):
            del v[k]
      del v['ProcessCount']
    result['ProcessCount'] = process_count
    return result

  @property
  def memory_stats(self):
    """Returns a dict of memory statistics for the browser:
    { 'Browser': {
        'VM': R,
        'VMPeak': S,
        'WorkingSetSize': T,
        'WorkingSetSizePeak': U,
        'ProportionalSetSize': V,
        'PrivateDirty': W
      },
      'Gpu': {
        'VM': R,
        'VMPeak': S,
        'WorkingSetSize': T,
        'WorkingSetSizePeak': U,
        'ProportionalSetSize': V,
        'PrivateDirty': W
      },
      'Renderer': {
        'VM': R,
        'VMPeak': S,
        'WorkingSetSize': T,
        'WorkingSetSizePeak': U,
        'ProportionalSetSize': V,
        'PrivateDirty': W
      },
      'SystemCommitCharge': X,
      'SystemTotalPhysicalMemory': Y,
      'ProcessCount': Z,
    }
    Any of the above keys may be missing on a per-platform basis.
    """
    self._platform_backend.PurgeUnpinnedMemory()
    result = self._GetStatsCommon(self._platform_backend.GetMemoryStats)
    commit_charge = self._platform_backend.GetSystemCommitCharge()
    if commit_charge:
      result['SystemCommitCharge'] = commit_charge
    total = self._platform_backend.GetSystemTotalPhysicalMemory()
    if total:
      result['SystemTotalPhysicalMemory'] = total
    return result

  @property
  def cpu_stats(self):
    """Returns a dict of cpu statistics for the system.
    { 'Browser': {
        'CpuProcessTime': S,
        'TotalTime': T
      },
      'Gpu': {
        'CpuProcessTime': S,
        'TotalTime': T
      },
      'Renderer': {
        'CpuProcessTime': S,
        'TotalTime': T
      }
    }
    Any of the above keys may be missing on a per-platform basis.
    """
    result = self._GetStatsCommon(self._platform_backend.GetCpuStats)
    del result['ProcessCount']

    # We want a single time value, not the sum for all processes.
    cpu_timestamp = self._platform_backend.GetCpuTimestamp()
    for process_type in result:
      # Skip any process_types that are empty
      if not len(result[process_type]):
        continue
      result[process_type].update(cpu_timestamp)
    return result

  def Close(self):
    """Closes this browser."""
    try:
      if self._browser_backend.IsBrowserRunning():
        self._platform_backend.WillCloseBrowser(self, self._browser_backend)

      self._browser_backend.profiling_controller_backend.WillCloseBrowser()
      if self._browser_backend.supports_uploading_logs:
        try:
          self._browser_backend.UploadLogsToCloudStorage()
        except cloud_storage.CloudStorageError as e:
          logging.error('Cannot upload browser log: %s' % str(e))
    finally:
      self._browser_backend.Close()
      self.credentials = None

  def Foreground(self):
    """Ensure the browser application is moved to the foreground."""
    return self._browser_backend.Foreground()

  def Background(self):
    """Ensure the browser application is moved to the background."""
    return self._browser_backend.Background()

  def GetStandardOutput(self):
    return self._browser_backend.GetStandardOutput()

  def GetLogFileContents(self):
    return self._browser_backend.GetLogFileContents()

  def GetStackTrace(self):
    return self._browser_backend.GetStackTrace()

  def GetMostRecentMinidumpPath(self):
    """Returns the path to the most recent minidump."""
    return self._browser_backend.GetMostRecentMinidumpPath()

  def GetAllMinidumpPaths(self):
    """Returns all minidump paths available in the backend."""
    return self._browser_backend.GetAllMinidumpPaths()

  def GetAllUnsymbolizedMinidumpPaths(self):
    """Returns paths to all minidumps that have not already been
    symbolized."""
    return self._browser_backend.GetAllUnsymbolizedMinidumpPaths()

  def SymbolizeMinidump(self, minidump_path):
    """Given a minidump path, this method returns a tuple with the
    first value being whether or not the minidump was able to be
    symbolized and the second being that symbolized dump when true
    and error message when false."""
    return self._browser_backend.SymbolizeMinidump(minidump_path)

  @property
  def supports_system_info(self):
    return self._browser_backend.supports_system_info

  def GetSystemInfo(self):
    """Returns low-level information about the system, if available.

       See the documentation of the SystemInfo class for more details."""
    return self._browser_backend.GetSystemInfo()

  @property
  def supports_memory_dumping(self):
    return self._browser_backend.supports_memory_dumping

  def DumpMemory(self, timeout=web_contents.DEFAULT_WEB_CONTENTS_TIMEOUT):
    return self._browser_backend.DumpMemory(timeout)

  @property
  def supports_overriding_memory_pressure_notifications(self):
    return (
        self._browser_backend.supports_overriding_memory_pressure_notifications)

  def SetMemoryPressureNotificationsSuppressed(
      self, suppressed, timeout=web_contents.DEFAULT_WEB_CONTENTS_TIMEOUT):
    self._browser_backend.SetMemoryPressureNotificationsSuppressed(
        suppressed, timeout)

  def SimulateMemoryPressureNotification(
      self, pressure_level, timeout=web_contents.DEFAULT_WEB_CONTENTS_TIMEOUT):
    self._browser_backend.SimulateMemoryPressureNotification(
        pressure_level, timeout)

  @property
  def supports_cpu_metrics(self):
    return self._browser_backend.supports_cpu_metrics

  @property
  def supports_memory_metrics(self):
    return self._browser_backend.supports_memory_metrics

  @property
  def supports_power_metrics(self):
    return self._browser_backend.supports_power_metrics

  def DumpStateUponFailure(self):
    logging.info('*************** BROWSER STANDARD OUTPUT ***************')
    try:  # pylint: disable=broad-except
      logging.info(self.GetStandardOutput())
    except Exception:
      logging.exception('Failed to get browser standard output:')
    logging.info('*********** END OF BROWSER STANDARD OUTPUT ************')

    logging.info('********************* BROWSER LOG *********************')
    try:  # pylint: disable=broad-except
      logging.info(self.GetLogFileContents())
    except Exception:
      logging.exception('Failed to get browser log:')
    logging.info('***************** END OF BROWSER LOG ******************')
