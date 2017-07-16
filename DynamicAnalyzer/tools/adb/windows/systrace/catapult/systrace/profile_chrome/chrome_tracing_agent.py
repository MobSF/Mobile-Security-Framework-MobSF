# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import optparse
import os
import py_utils
import re

from devil.android import device_errors
from devil.android.sdk import intent
from systrace import trace_result
from systrace import tracing_agents


DEFAULT_CHROME_CATEGORIES = '_DEFAULT_CHROME_CATEGORIES'
_HEAP_PROFILE_MMAP_PROPERTY = 'heapprof.mmap'


class ChromeTracingAgent(tracing_agents.TracingAgent):
  def __init__(self, device, package_info, ring_buffer, trace_memory=False):
    tracing_agents.TracingAgent.__init__(self)
    self._device = device
    self._package_info = package_info
    self._ring_buffer = ring_buffer
    self._logcat_monitor = self._device.GetLogcatMonitor()
    self._trace_file = None
    self._trace_memory = trace_memory
    self._is_tracing = False
    self._trace_start_re = \
       re.compile(r'Logging performance trace to file')
    self._trace_finish_re = \
       re.compile(r'Profiler finished[.] Results are in (.*)[.]')
    self._categories = None

  def __repr__(self):
    return 'chrome trace'

  @staticmethod
  def GetCategories(device, package_info):
    with device.GetLogcatMonitor() as logmon:
      device.BroadcastIntent(intent.Intent(
          action='%s.GPU_PROFILER_LIST_CATEGORIES' % package_info.package))
      try:
        json_category_list = logmon.WaitFor(
            re.compile(r'{"traceCategoriesList(.*)'), timeout=5).group(0)
      except device_errors.CommandTimeoutError:
        raise RuntimeError('Performance trace category list marker not found. '
                           'Is the correct version of the browser running?')

    record_categories = set()
    disabled_by_default_categories = set()
    json_data = json.loads(json_category_list)['traceCategoriesList']
    for item in json_data:
      for category in item.split(','):
        if category.startswith('disabled-by-default'):
          disabled_by_default_categories.add(category)
        else:
          record_categories.add(category)

    return list(record_categories), list(disabled_by_default_categories)

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StartAgentTracing(self, config, timeout=None):
    self._categories = _ComputeChromeCategories(config)
    self._logcat_monitor.Start()
    start_extras = {'categories': ','.join(self._categories)}
    if self._ring_buffer:
      start_extras['continuous'] = None
    self._device.BroadcastIntent(intent.Intent(
        action='%s.GPU_PROFILER_START' % self._package_info.package,
        extras=start_extras))

    if self._trace_memory:
      self._device.EnableRoot()
      self._device.SetProp(_HEAP_PROFILE_MMAP_PROPERTY, 1)

    # Chrome logs two different messages related to tracing:
    #
    # 1. "Logging performance trace to file"
    # 2. "Profiler finished. Results are in [...]"
    #
    # The first one is printed when tracing starts and the second one indicates
    # that the trace file is ready to be pulled.
    try:
      self._logcat_monitor.WaitFor(self._trace_start_re, timeout=5)
      self._is_tracing = True
    except device_errors.CommandTimeoutError:
      raise RuntimeError(
          'Trace start marker not found. Possible causes: 1) Is the correct '
          'version of the browser running? 2) Is the browser already launched?')
    return True

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StopAgentTracing(self, timeout=None):
    if self._is_tracing:
      self._device.BroadcastIntent(intent.Intent(
          action='%s.GPU_PROFILER_STOP' % self._package_info.package))
      self._trace_file = self._logcat_monitor.WaitFor(
          self._trace_finish_re, timeout=120).group(1)
      self._is_tracing = False
    if self._trace_memory:
      self._device.SetProp(_HEAP_PROFILE_MMAP_PROPERTY, 0)
    return True

  @py_utils.Timeout(tracing_agents.GET_RESULTS_TIMEOUT)
  def GetResults(self, timeout=None):
    with open(self._PullTrace(), 'r') as f:
      trace_data = f.read()
    return trace_result.TraceResult('traceEvents', trace_data)

  def _PullTrace(self):
    trace_file = self._trace_file.replace('/storage/emulated/0/', '/sdcard/')
    host_file = os.path.join(os.path.curdir, os.path.basename(trace_file))
    try:
      self._device.PullFile(trace_file, host_file)
    except device_errors.AdbCommandFailedError:
      raise RuntimeError(
          'Cannot pull the trace file. Have you granted Storage permission to '
          'the browser? (Android Settings -> Apps -> [the browser app] -> '
          'Permissions -> Storage)')
    return host_file

  def SupportsExplicitClockSync(self):
    return False

  def RecordClockSyncMarker(self, sync_id, did_record_sync_marker_callback):
    # pylint: disable=unused-argument
    assert self.SupportsExplicitClockSync(), ('Clock sync marker cannot be '
        'recorded since explicit clock sync is not supported.')


class ChromeConfig(tracing_agents.TracingConfig):
  def __init__(self, chrome_categories, trace_cc, trace_frame_viewer,
               trace_ubercompositor, trace_gpu, trace_flow, trace_memory,
               trace_scheduler, ring_buffer, device, package_info):
    tracing_agents.TracingConfig.__init__(self)
    self.chrome_categories = chrome_categories
    self.trace_cc = trace_cc
    self.trace_frame_viewer = trace_frame_viewer
    self.trace_ubercompositor = trace_ubercompositor
    self.trace_gpu = trace_gpu
    self.trace_flow = trace_flow
    self.trace_memory = trace_memory
    self.trace_scheduler = trace_scheduler
    self.ring_buffer = ring_buffer
    self.device = device
    self.package_info = package_info


def try_create_agent(config):
  if config.chrome_categories:
    return ChromeTracingAgent(config.device, config.package_info,
                              config.ring_buffer, config.trace_memory)
  return None

def add_options(parser):
  chrome_opts = optparse.OptionGroup(parser, 'Chrome tracing options')
  chrome_opts.add_option('-c', '--categories', help='Select Chrome tracing '
                         'categories with comma-delimited wildcards, '
                         'e.g., "*", "cat1*,-cat1a". Omit this option to trace '
                         'Chrome\'s default categories. Chrome tracing can be '
                         'disabled with "--categories=\'\'". Use "list" to '
                         'see the available categories.',
                         metavar='CHROME_CATEGORIES', dest='chrome_categories')
  chrome_opts.add_option('--trace-cc',
                         help='Deprecated, use --trace-frame-viewer.',
                         action='store_true')
  chrome_opts.add_option('--trace-frame-viewer',
                         help='Enable enough trace categories for '
                         'compositor frame viewing.', action='store_true')
  chrome_opts.add_option('--trace-ubercompositor',
                         help='Enable enough trace categories for '
                         'ubercompositor frame data.', action='store_true')
  chrome_opts.add_option('--trace-gpu', help='Enable extra trace categories '
                         'for GPU data.', action='store_true')
  chrome_opts.add_option('--trace-flow', help='Enable extra trace categories '
                         'for IPC message flows.', action='store_true')
  chrome_opts.add_option('--trace-memory', help='Enable extra trace categories '
                         'for memory profile. (tcmalloc required)',
                         action='store_true')
  chrome_opts.add_option('--trace-scheduler', help='Enable extra trace '
                         'categories for scheduler state',
                         action='store_true')
  return chrome_opts

def get_config(options):
  return ChromeConfig(options.chrome_categories, options.trace_cc,
                      options.trace_frame_viewer, options.trace_ubercompositor,
                      options.trace_gpu, options.trace_flow,
                      options.trace_memory, options.trace_scheduler,
                      options.ring_buffer, options.device,
                      options.package_info)

def _ComputeChromeCategories(config):
  categories = []
  if config.trace_frame_viewer:
    categories.append('disabled-by-default-cc.debug')
  if config.trace_ubercompositor:
    categories.append('disabled-by-default-cc.debug*')
  if config.trace_gpu:
    categories.append('disabled-by-default-gpu.debug*')
  if config.trace_flow:
    categories.append('disabled-by-default-toplevel.flow')
  if config.trace_memory:
    categories.append('disabled-by-default-memory')
  if config.trace_scheduler:
    categories.append('disabled-by-default-blink.scheduler')
    categories.append('disabled-by-default-cc.debug.scheduler')
    categories.append('disabled-by-default-renderer.scheduler')
  if config.chrome_categories:
    categories += config.chrome_categories.split(',')
  return categories
