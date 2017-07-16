# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.util import atexit_with_log
import json
import logging
import os
import shutil
import stat
import sys
import tempfile
import traceback

from py_trace_event import trace_time
from telemetry.internal.platform import tracing_agent
from telemetry.internal.platform.tracing_agent import (
    chrome_tracing_devtools_manager)

_DESKTOP_OS_NAMES = ['linux', 'mac', 'win']
_STARTUP_TRACING_OS_NAMES = _DESKTOP_OS_NAMES + ['android', 'chromeos']

# The trace config file path should be the same as specified in
# src/components/tracing/trace_config_file.[h|cc]
_CHROME_TRACE_CONFIG_DIR_ANDROID = '/data/local/'
_CHROME_TRACE_CONFIG_DIR_CROS = '/tmp/'
_CHROME_TRACE_CONFIG_FILE_NAME = 'chrome-trace-config.json'


def ClearStarupTracingStateIfNeeded(platform_backend):
  # Trace config file has fixed path on Android and temporary path on desktop.
  if platform_backend.GetOSName() == 'android':
    trace_config_file = os.path.join(_CHROME_TRACE_CONFIG_DIR_ANDROID,
                                     _CHROME_TRACE_CONFIG_FILE_NAME)
    platform_backend.device.RunShellCommand(
        ['rm', '-f', trace_config_file], check_return=True, as_root=True)


class ChromeTracingStartedError(Exception):
  pass


class ChromeTracingStoppedError(Exception):
  pass


class ChromeClockSyncError(Exception):
  pass


class ChromeTracingAgent(tracing_agent.TracingAgent):
  def __init__(self, platform_backend):
    super(ChromeTracingAgent, self).__init__(platform_backend)
    self._trace_config = None
    self._trace_config_file = None
    self._previously_responsive_devtools = []

  @property
  def trace_config(self):
    # Trace config is also used to check if Chrome tracing is running or not.
    return self._trace_config

  @property
  def trace_config_file(self):
    return self._trace_config_file

  @classmethod
  def IsStartupTracingSupported(cls, platform_backend):
    if platform_backend.GetOSName() in _STARTUP_TRACING_OS_NAMES:
      return True
    else:
      return False

  @classmethod
  def IsSupported(cls, platform_backend):
    if cls.IsStartupTracingSupported(platform_backend):
      return True
    else:
      return chrome_tracing_devtools_manager.IsSupported(platform_backend)

  def _StartStartupTracing(self, config):
    if not self.IsStartupTracingSupported(self._platform_backend):
      return False
    self._CreateTraceConfigFile(config)
    return True

  def _StartDevToolsTracing(self, config, timeout):
    if not chrome_tracing_devtools_manager.IsSupported(self._platform_backend):
      return False
    devtools_clients = (chrome_tracing_devtools_manager
        .GetActiveDevToolsClients(self._platform_backend))
    if not devtools_clients:
      return False
    for client in devtools_clients:
      if client.is_tracing_running:
        raise ChromeTracingStartedError(
            'Tracing is already running on devtools at port %s on platform'
            'backend %s.' % (client.remote_port, self._platform_backend))
      client.StartChromeTracing(config, timeout)
    return True

  def StartAgentTracing(self, config, timeout):
    if not config.enable_chrome_trace:
      return False

    if self._trace_config:
      raise ChromeTracingStartedError(
          'Tracing is already running on platform backend %s.'
          % self._platform_backend)

    if (config.enable_android_graphics_memtrack and
        self._platform_backend.GetOSName() == 'android'):
      self._platform_backend.SetGraphicsMemoryTrackingEnabled(True)

    # Chrome tracing Agent needs to start tracing for chrome browsers that are
    # not yet started, and for the ones that already are. For the former, we
    # first setup the trace_config_file, which allows browsers that starts after
    # this point to use it for enabling tracing upon browser startup. For the
    # latter, we invoke start tracing command through devtools for browsers that
    # are already started and tracked by chrome_tracing_devtools_manager.
    started_startup_tracing = self._StartStartupTracing(config)
    started_devtools_tracing = self._StartDevToolsTracing(config, timeout)
    if started_startup_tracing or started_devtools_tracing:
      self._trace_config = config
      return True
    return False

  def SupportsExplicitClockSync(self):
    return True

  def _RecordClockSyncMarkerDevTools(
      self, sync_id, record_controller_clock_sync_marker_callback,
      devtools_clients):
    has_clock_synced = False
    for client in devtools_clients:
      try:
        timestamp = trace_time.Now()
        client.RecordChromeClockSyncMarker(sync_id)
        # We only need one successful clock sync.
        has_clock_synced = True
        break
      except Exception:
        logging.exception('Failed to record clock sync marker with sync_id=%r '
                          'via DevTools client %r:' % (sync_id, client))
    if not has_clock_synced:
      raise ChromeClockSyncError(
          'Failed to issue clock sync to devtools client')
    record_controller_clock_sync_marker_callback(sync_id, timestamp)

  def _RecordClockSyncMarkerAsyncEvent(
      self, sync_id, record_controller_clock_sync_marker_callback):
    has_clock_synced = False
    for backend in self._IterInspectorBackends():
      try:
        timestamp = trace_time.Now()
        event = 'ClockSyncEvent.%s' % sync_id
        backend.EvaluateJavaScript(
            "console.time({{ event }});", event=event)
        backend.EvaluateJavaScript(
            "console.timeEnd({{ event }});", event=event)
        has_clock_synced = True
        break
      except Exception:
        logging.exception('Failed to record clock sync marker with sync_id=%r '
                          'via inspector backend %r:' % (sync_id, backend))
    if not has_clock_synced:
      raise ChromeClockSyncError(
          'Failed to issue clock sync to devtools client')
    record_controller_clock_sync_marker_callback(sync_id, timestamp)

  def RecordClockSyncMarker(self, sync_id,
                            record_controller_clock_sync_marker_callback):
    devtools_clients = (chrome_tracing_devtools_manager
        .GetActiveDevToolsClients(self._platform_backend))
    if not devtools_clients:
      raise ChromeClockSyncError('Cannot issue clock sync. No devtools clients')
    version = None
    for client in devtools_clients:
      version = client.GetChromeBranchNumber()
      break
    logging.info('Chrome version: %s', version)
    # Note, we aren't sure whether 2744 is the correct cut-off point which
    # Chrome will support clock sync marker, however we verified that 2743 does
    # not support clock sync (catapult/issues/2804) hence we use it here.
    # On the next update of Chrome ref build, if testTBM2ForSmoke still fails,
    # the cut-off branch number will need to be bumped up again.
    if version and int(version) > 2743:
      self._RecordClockSyncMarkerDevTools(
          sync_id, record_controller_clock_sync_marker_callback,
          devtools_clients)
    else:  # TODO(rnephew): Remove once chrome stable is past branch 2743.
      self._RecordClockSyncMarkerAsyncEvent(
          sync_id, record_controller_clock_sync_marker_callback)

  def StopAgentTracing(self):
    if not self._trace_config:
      raise ChromeTracingStoppedError(
          'Tracing is not running on platform backend %s.'
          % self._platform_backend)

    if self.IsStartupTracingSupported(self._platform_backend):
      self._RemoveTraceConfigFile()

    # We get all DevTools clients including the stale ones, so that we get an
    # exception if there is a stale client. This is because we will potentially
    # lose data if there is a stale client.
    devtools_clients = (chrome_tracing_devtools_manager
        .GetDevToolsClients(self._platform_backend))
    raised_exception_messages = []
    assert len(self._previously_responsive_devtools) == 0
    for client in devtools_clients:
      try:
        client.StopChromeTracing()
        self._previously_responsive_devtools.append(client)

      except Exception:
        raised_exception_messages.append(
          'Error when trying to stop Chrome tracing on devtools at port %s:\n%s'
          % (client.remote_port,
             ''.join(traceback.format_exception(*sys.exc_info()))))

    if (self._trace_config.enable_android_graphics_memtrack and
        self._platform_backend.GetOSName() == 'android'):
      self._platform_backend.SetGraphicsMemoryTrackingEnabled(False)

    self._trace_config = None
    if raised_exception_messages:
      raise ChromeTracingStoppedError(
          'Exceptions raised when trying to stop Chrome devtool tracing:\n' +
          '\n'.join(raised_exception_messages))

  def CollectAgentTraceData(self, trace_data_builder, timeout=None):
    raised_exception_messages = []
    for client in self._previously_responsive_devtools:
      try:
        client.CollectChromeTracingData(trace_data_builder)
      except Exception:
        raised_exception_messages.append(
          'Error when collecting Chrome tracing on devtools at port %s:\n%s'
          % (client.remote_port,
             ''.join(traceback.format_exception(*sys.exc_info()))))
    self._previously_responsive_devtools = []

    if raised_exception_messages:
      raise ChromeTracingStoppedError(
          'Exceptions raised when trying to collect Chrome devtool tracing:\n' +
          '\n'.join(raised_exception_messages))

  def _CreateTraceConfigFileString(self, config):
    # See src/components/tracing/trace_config_file.h for the format
    result = {
      'trace_config':
        config.chrome_trace_config.GetChromeTraceConfigForStartupTracing()
    }
    return json.dumps(result, sort_keys=True)

  def _CreateTraceConfigFile(self, config):
    assert not self._trace_config_file
    if self._platform_backend.GetOSName() == 'android':
      self._trace_config_file = os.path.join(_CHROME_TRACE_CONFIG_DIR_ANDROID,
                                             _CHROME_TRACE_CONFIG_FILE_NAME)
      self._platform_backend.device.WriteFile(self._trace_config_file,
          self._CreateTraceConfigFileString(config), as_root=True)
      # The config file has fixed path on Android. We need to ensure it is
      # always cleaned up.
      atexit_with_log.Register(self._RemoveTraceConfigFile)
    elif self._platform_backend.GetOSName() == 'chromeos':
      self._trace_config_file = os.path.join(_CHROME_TRACE_CONFIG_DIR_CROS,
                                             _CHROME_TRACE_CONFIG_FILE_NAME)
      cri = self._platform_backend.cri
      cri.PushContents(self._CreateTraceConfigFileString(config),
                       self._trace_config_file)
      cri.Chown(self._trace_config_file)
      # The config file has fixed path on CrOS. We need to ensure it is
      # always cleaned up.
      atexit_with_log.Register(self._RemoveTraceConfigFile)
    elif self._platform_backend.GetOSName() in _DESKTOP_OS_NAMES:
      self._trace_config_file = os.path.join(tempfile.mkdtemp(),
                                             _CHROME_TRACE_CONFIG_FILE_NAME)
      with open(self._trace_config_file, 'w') as f:
        trace_config_string = self._CreateTraceConfigFileString(config)
        logging.info('Trace config file string: %s', trace_config_string)
        f.write(trace_config_string)
      os.chmod(self._trace_config_file,
               os.stat(self._trace_config_file).st_mode | stat.S_IROTH)
    else:
      raise NotImplementedError

  def _RemoveTraceConfigFile(self):
    if not self._trace_config_file:
      return
    if self._platform_backend.GetOSName() == 'android':
      self._platform_backend.device.RunShellCommand(
          ['rm', '-f', self._trace_config_file], check_return=True,
          as_root=True)
    elif self._platform_backend.GetOSName() == 'chromeos':
      self._platform_backend.cri.RmRF(self._trace_config_file)
    elif self._platform_backend.GetOSName() in _DESKTOP_OS_NAMES:
      if os.path.exists(self._trace_config_file):
        os.remove(self._trace_config_file)
      shutil.rmtree(os.path.dirname(self._trace_config_file))
    else:
      raise NotImplementedError
    self._trace_config_file = None

  def SupportsFlushingAgentTracing(self):
    return True

  def FlushAgentTracing(self, config, timeout, trace_data_builder):
    if not self._trace_config:
      raise ChromeTracingStoppedError(
          'Tracing is not running on platform backend %s.'
          % self._platform_backend)

    for backend in self._IterInspectorBackends():
      backend.EvaluateJavaScript("console.time('flush-tracing');")

    self.StopAgentTracing()
    self.CollectAgentTraceData(trace_data_builder)
    self.StartAgentTracing(config, timeout)

    for backend in self._IterInspectorBackends():
      backend.EvaluateJavaScript("console.timeEnd('flush-tracing');")

  def _IterInspectorBackends(self):
    for client in chrome_tracing_devtools_manager.GetDevToolsClients(
        self._platform_backend):
      context_map = client.GetUpdatedInspectableContexts()
      for context in context_map.contexts:
        if context['type'] in ['iframe', 'page', 'webview']:
          yield context_map.GetInspectorBackend(context['id'])
