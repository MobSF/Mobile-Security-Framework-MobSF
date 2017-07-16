# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import os
import py_utils

from systrace import trace_result
from systrace import tracing_agents


class FtraceAgentIo(object):
  @staticmethod
  def writeFile(path, data):
    if FtraceAgentIo.haveWritePermissions(path):
      with open(path, 'w') as f:
        f.write(data)
    else:
      raise IOError('Cannot write to %s; did you forget sudo/root?' % path)

  @staticmethod
  def readFile(path):
    with open(path, 'r') as f:
      return f.read()

  @staticmethod
  def haveWritePermissions(path):
    return os.access(path, os.W_OK)


FT_DIR = "/sys/kernel/debug/tracing/"
FT_CLOCK = FT_DIR + "trace_clock"
FT_BUFFER_SIZE = FT_DIR + "buffer_size_kb"
FT_TRACER = FT_DIR + "current_tracer"
FT_PRINT_TGID = FT_DIR + "options/print-tgid"
FT_TRACE_ON = FT_DIR + "tracing_on"
FT_TRACE = FT_DIR + "trace"
FT_TRACE_MARKER = FT_DIR + "trace_marker"
FT_OVERWRITE = FT_DIR + "options/overwrite"

all_categories = {
    "sched": {
          "desc": "CPU Scheduling",
          "req": ["sched/sched_switch/", "sched/sched_wakeup/"]
    },
    "freq": {
          "desc": "CPU Frequency",
          "req": ["power/cpu_frequency/", "power/clock_set_rate/"]
    },
    "irq": {
          "desc": "CPU IRQS and IPIS",
          "req": ["irq/"],
          "opt": ["ipi/"]
    },
    "workq": {
          "desc": "Kernel workqueues",
          "req": ["workqueue/"]
    },
    "memreclaim": {
          "desc": "Kernel Memory Reclaim",
          "req": ["vmscan/mm_vmscan_direct_reclaim_begin/",
                  "vmscan/mm_vmscan_direct_reclaim_end/",
                  "vmscan/mm_vmscan_kswapd_wake/",
                  "vmscan/mm_vmscan_kswapd_sleep/"]
    },
    "idle": {
          "desc": "CPU Idle",
          "req": ["power/cpu_idle/"]
    },
    "regulators": {
          "desc": "Voltage and Current Regulators",
          "req": ["regulator/"]
    },
    "disk": {
          "desc": "Disk I/O",
          "req": ["block/block_rq_issue/",
                  "block/block_rq_complete/"],
          "opt": ["f2fs/f2fs_sync_file_enter/",
                  "f2fs/f2fs_sync_file_exit/",
                  "f2fs/f2fs_write_begin/",
                  "f2fs/f2fs_write_end/",
                  "ext4/ext4_da_write_begin/",
                  "ext4/ext4_da_write_end/",
                  "ext4/ext4_sync_file_enter/",
                  "ext4/ext4_sync_file_exit/"]
    }
}


def try_create_agent(config):
  if config.target != 'linux':
    return None
  return FtraceAgent(FtraceAgentIo)


def list_categories(_):
  agent = FtraceAgent(FtraceAgentIo)
  agent._print_avail_categories()


class FtraceConfig(tracing_agents.TracingConfig):
  def __init__(self, ftrace_categories, target, trace_buf_size):
    tracing_agents.TracingConfig.__init__(self)
    self.ftrace_categories = ftrace_categories
    self.target = target
    self.trace_buf_size = trace_buf_size


def add_options(parser):
  options = optparse.OptionGroup(parser, 'Ftrace options')
  options.add_option('--ftrace-categories', dest='ftrace_categories',
                     help='Select ftrace categories with a comma-delimited '
                     'list, e.g. --ftrace-categories=cat1,cat2,cat3')
  return options


def get_config(options):
  return FtraceConfig(options.ftrace_categories, options.target,
                      options.trace_buf_size)


class FtraceAgent(tracing_agents.TracingAgent):

  def __init__(self, fio=FtraceAgentIo):
    """Initialize a systrace agent.

    Args:
      config: The command-line config.
      categories: The trace categories to capture.
    """
    super(FtraceAgent, self).__init__()
    self._fio = fio
    self._config = None
    self._categories = None

  def _get_trace_buffer_size(self):
    buffer_size = 4096
    if ((self._config.trace_buf_size is not None)
        and (self._config.trace_buf_size > 0)):
      buffer_size = self._config.trace_buf_size
    return buffer_size

  def _fix_categories(self, categories):
    """
    Applies the default category (sched) if there are no categories
    in the list and removes unavailable categories from the list.
    Args:
        categories: List of categories.
    """
    if not categories:
      categories = ["sched"]
    return [x for x in categories
            if self._is_category_available(x)]

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StartAgentTracing(self, config, timeout=None):
    """Start tracing.
    """
    self._config = config
    categories = self._fix_categories(config.ftrace_categories)
    self._fio.writeFile(FT_BUFFER_SIZE,
                        str(self._get_trace_buffer_size()))
    self._fio.writeFile(FT_CLOCK, 'global')
    self._fio.writeFile(FT_TRACER, 'nop')
    self._fio.writeFile(FT_OVERWRITE, "0")

    # TODO: riandrews to push necessary patches for TGID option to upstream
    # linux kernel
    # self._fio.writeFile(FT_PRINT_TGID, '1')

    for category in categories:
      self._category_enable(category)

    self._categories = categories # need to store list of categories to disable
    print 'starting tracing.'

    self._fio.writeFile(FT_TRACE, '')
    self._fio.writeFile(FT_TRACE_ON, '1')
    return True

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StopAgentTracing(self, timeout=None):
    """Collect the result of tracing.

    This function will block while collecting the result. For sync mode, it
    reads the data, e.g., from stdout, until it finishes. For async mode, it
    blocks until the agent is stopped and the data is ready.
    """
    self._fio.writeFile(FT_TRACE_ON, '0')
    for category in self._categories:
      self._category_disable(category)
    return True

  @py_utils.Timeout(tracing_agents.GET_RESULTS_TIMEOUT)
  def GetResults(self, timeout=None):
    # get the output
    d = self._fio.readFile(FT_TRACE)
    self._fio.writeFile(FT_BUFFER_SIZE, "1")
    return trace_result.TraceResult('trace-data', d)

  def SupportsExplicitClockSync(self):
    return False

  def RecordClockSyncMarker(self, sync_id, did_record_sync_marker_callback):
    # No implementation, but need to have this to support the API
    # pylint: disable=unused-argument
    return False

  def _is_category_available(self, category):
    if category not in all_categories:
      return False
    events_dir = FT_DIR + "events/"
    req_events = all_categories[category]["req"]
    for event in req_events:
      event_full_path = events_dir + event + "enable"
      if not self._fio.haveWritePermissions(event_full_path):
        return False
    return True

  def _avail_categories(self):
    ret = []
    for event in all_categories:
      if self._is_category_available(event):
        ret.append(event)
    return ret

  def _print_avail_categories(self):
    avail = self._avail_categories()
    if len(avail):
      print "tracing config:"
      for category in self._avail_categories():
        desc = all_categories[category]["desc"]
        print "{0: <16}".format(category), ": ", desc
    else:
      print "No tracing categories available - perhaps you need root?"

  def _category_enable_paths(self, category):
    events_dir = FT_DIR + "events/"
    req_events = all_categories[category]["req"]
    for event in req_events:
      event_full_path = events_dir + event + "enable"
      yield event_full_path
    if "opt" in all_categories[category]:
      opt_events = all_categories[category]["opt"]
      for event in opt_events:
        event_full_path = events_dir + event + "enable"
        if self._fio.haveWritePermissions(event_full_path):
          yield event_full_path

  def _category_enable(self, category):
    for path in self._category_enable_paths(category):
      self._fio.writeFile(path, "1")

  def _category_disable(self, category):
    for path in self._category_enable_paths(category):
      self._fio.writeFile(path, "0")
