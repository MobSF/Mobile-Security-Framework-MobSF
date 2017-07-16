# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import py_utils
import re
import sys
import threading
import zlib

from devil.android import device_utils
from devil.android.sdk import version_codes
from py_trace_event import trace_time as trace_time_module
from systrace import trace_result
from systrace import tracing_agents
from systrace import util

# Text that ADB sends, but does not need to be displayed to the user.
ADB_IGNORE_REGEXP = r'^capturing trace\.\.\. done|^capturing trace\.\.\.'
# The number of seconds to wait on output from ADB.
ADB_STDOUT_READ_TIMEOUT = 0.2
# The adb shell command to initiate a trace.
ATRACE_BASE_ARGS = ['atrace']
# If a custom list of categories is not specified, traces will include
# these categories (if available on the device).
DEFAULT_CATEGORIES = 'sched,freq,gfx,view,dalvik,webview,'\
                     'input,disk,am,wm,rs,binder_driver'
# The command to list trace categories.
LIST_CATEGORIES_ARGS = ATRACE_BASE_ARGS + ['--list_categories']
# Minimum number of seconds between displaying status updates.
MIN_TIME_BETWEEN_STATUS_UPDATES = 0.2
# ADB sends this text to indicate the beginning of the trace data.
TRACE_START_REGEXP = r'TRACE\:'
# Plain-text trace data should always start with this string.
TRACE_TEXT_HEADER = '# tracer'
_FIX_THREAD_IDS = True
_FIX_MISSING_TGIDS = True
_FIX_CIRCULAR_TRACES = True


def list_categories(config):
  """List the possible trace event categories.

  This function needs the tracing config since it needs to get the serial
  number of the device to send a command to.

  Args:
      config: Tracing config.
  """
  devutils = device_utils.DeviceUtils(config.device_serial_number)
  categories = devutils.RunShellCommand(
      LIST_CATEGORIES_ARGS, check_return=True)

  device_sdk_version = util.get_device_sdk_version()
  if device_sdk_version < version_codes.MARSHMALLOW:
    # work around platform bug where rs tag would corrupt trace until M(Api23)
    categories = [c for c in categories if not re.match(r'^\s*rs\s*-', c)]

  print '\n'.join(categories)
  if not devutils.HasRoot():
    print '\nNOTE: more categories may be available with adb root\n'


def get_available_categories(config, device_sdk_version):
  """Gets the list of atrace categories available for tracing.
  Args:
      config: Tracing config.
      device_sdk_version: Sdk version int of device to be queried.
  """
  devutils = device_utils.DeviceUtils(config.device_serial_number)
  categories_output = devutils.RunShellCommand(
      LIST_CATEGORIES_ARGS, check_return=True)
  categories = [c.split('-')[0].strip() for c in categories_output]

  if device_sdk_version < version_codes.MARSHMALLOW:
    # work around platform bug where rs tag would corrupt trace until M(Api23)
    categories = [c for c in categories if c != 'rs']
  return categories


def try_create_agent(config):
  """Create an Atrace agent.

  Args:
      config: Command line config.
  """
  if config.target != 'android':
    return None
  if config.from_file is not None:
    return None

  if not config.atrace_categories:
    return None

  # Check device SDK version.
  device_sdk_version = util.get_device_sdk_version()
  if device_sdk_version < version_codes.JELLY_BEAN_MR2:
    print ('Device SDK versions < 18 (Jellybean MR2) not supported.\n'
           'Your device SDK version is %d.' % device_sdk_version)
    return None

  return AtraceAgent(device_sdk_version)

def _construct_extra_atrace_args(config, categories):
  """Construct extra arguments (-a, -k, categories) for atrace command.

  Args:
      config: Tracing config.
  """
  extra_args = []

  if config.app_name is not None:
    extra_args.extend(['-a', config.app_name])

  if config.kfuncs is not None:
    extra_args.extend(['-k', config.kfuncs])

  extra_args.extend(categories)
  return extra_args

def _construct_atrace_args(config, categories):
  """Builds the command used to invoke a trace process.
  Returns:
    A tuple where the first element is an array of command arguments, and
    the second element is a boolean which will be true if the command will
    stream trace data.
  """
  atrace_args = ATRACE_BASE_ARGS[:]

  if config.compress_trace_data:
    atrace_args.extend(['-z'])

  if (config.trace_time is not None) and (config.trace_time > 0):
    atrace_args.extend(['-t', str(config.trace_time)])

  if (config.trace_buf_size is not None) and (config.trace_buf_size > 0):
    atrace_args.extend(['-b', str(config.trace_buf_size)])

  elif 'sched' in categories:
    # 'sched' is a high-volume tag, double the default buffer size
    # to accommodate that
    atrace_args.extend(['-b', '4096'])
  extra_args = _construct_extra_atrace_args(config, categories)

  atrace_args.extend(extra_args)
  return atrace_args


class AtraceAgent(tracing_agents.TracingAgent):

  def __init__(self, device_sdk_version):
    super(AtraceAgent, self).__init__()
    self._device_sdk_version = device_sdk_version
    self._adb = None
    self._trace_data = None
    self._tracer_args = None
    self._collection_thread = None
    self._device_utils = None
    self._device_serial_number = None
    self._config = None
    self._categories = None

  def __repr__(self):
    return 'atrace'

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StartAgentTracing(self, config, timeout=None):
    assert config.atrace_categories, 'Atrace categories are missing!'
    self._config = config
    self._categories = config.atrace_categories
    if isinstance(self._categories, list):
      self._categories = ','.join(self._categories)
    avail_cats = get_available_categories(config, self._device_sdk_version)
    unavailable = [x for x in self._categories.split(',') if
        x not in avail_cats]
    self._categories = [x for x in self._categories.split(',') if
        x in avail_cats]
    if unavailable:
      print 'These categories are unavailable: ' + ' '.join(unavailable)
    self._device_utils = device_utils.DeviceUtils(config.device_serial_number)
    self._device_serial_number = config.device_serial_number
    self._tracer_args = _construct_atrace_args(config,
                                               self._categories)
    self._device_utils.RunShellCommand(
        self._tracer_args + ['--async_start'], check_return=True)
    return True

  def _collect_and_preprocess(self):
    """Collects and preprocesses trace data.

    Stores results in self._trace_data.
    """
    trace_data = self._collect_trace_data()
    self._trace_data = self._preprocess_trace_data(trace_data)

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StopAgentTracing(self, timeout=None):
    """Stops tracing and starts collecting results.

    To synchronously retrieve the results after calling this function,
    call GetResults().
    """
    self._collection_thread = threading.Thread(
        target=self._collect_and_preprocess)
    self._collection_thread.start()
    return True

  @py_utils.Timeout(tracing_agents.GET_RESULTS_TIMEOUT)
  def GetResults(self, timeout=None):
    """Waits for collection thread to finish and returns trace results."""
    self._collection_thread.join()
    self._collection_thread = None
    return trace_result.TraceResult('systemTraceEvents', self._trace_data)

  def SupportsExplicitClockSync(self):
    return True

  def RecordClockSyncMarker(self, sync_id, did_record_sync_marker_callback):
    """Records a clock sync marker.

    Args:
        sync_id: ID string for clock sync marker.
    """
    cmd = 'echo trace_event_clock_sync: name=%s >' \
        ' /sys/kernel/debug/tracing/trace_marker' % sync_id
    with self._device_utils.adb.PersistentShell(
        self._device_serial_number) as shell:
      t1 = trace_time_module.Now()
      shell.RunCommand(cmd, close=True)
      did_record_sync_marker_callback(t1, sync_id)

  def _stop_trace(self):
    """Stops atrace.

    Note that prior to Api 23, --async-stop may not actually stop tracing.
    Thus, this uses a fallback method of running a zero-length synchronous
    trace if tracing is still on."""
    self._device_utils.RunShellCommand(
        self._tracer_args + ['--async_stop'], check_return=True)
    is_trace_enabled_file = '/sys/kernel/debug/tracing/tracing_on'

    if self._device_sdk_version < version_codes.MARSHMALLOW:
      if int(self._device_utils.ReadFile(is_trace_enabled_file)):
        # tracing was incorrectly left on, disable it
        self._device_utils.RunShellCommand(
            self._tracer_args + ['-t 0'], check_return=True)

  def _collect_trace_data(self):
    """Reads the output from atrace and stops the trace."""
    dump_cmd = self._tracer_args + ['--async_dump']
    result = self._device_utils.RunShellCommand(
        dump_cmd, raw_output=True, check_return=True)

    data_start = re.search(TRACE_START_REGEXP, result)
    if data_start:
      data_start = data_start.end(0)
    else:
      raise IOError('Unable to get atrace data. Did you forget adb root?')
    output = re.sub(ADB_IGNORE_REGEXP, '', result[data_start:])
    self._stop_trace()
    return output

  def _preprocess_trace_data(self, trace_data):
    """Performs various processing on atrace data.

    Args:
      trace_data: The raw trace data.
    Returns:
      The processed trace data.
    """
    if trace_data:
      trace_data = strip_and_decompress_trace(trace_data)

    if not trace_data:
      print >> sys.stderr, ('No data was captured.  Output file was not '
                            'written.')
      sys.exit(1)

    if _FIX_THREAD_IDS:
      # Issue ps command to device and patch thread names
      # TODO(catapult:#3215): Migrate to device.GetPids()
      ps_dump = self._device_utils.RunShellCommand(
          'ps -T -o USER,TID,PPID,VSIZE,RSS,WCHAN,ADDR=PC,S,CMD || ps -t',
          shell=True, check_return=True)
      thread_names = extract_thread_list(ps_dump)
      trace_data = fix_thread_names(trace_data, thread_names)

    if _FIX_MISSING_TGIDS:
      # Issue printf command to device and patch tgids
      procfs_dump = self._device_utils.RunShellCommand(
          'printf "%s\n" /proc/[0-9]*/task/[0-9]*',
          shell=True, check_return=True)
      pid2_tgid = extract_tgids(procfs_dump)
      trace_data = fix_missing_tgids(trace_data, pid2_tgid)

    if _FIX_CIRCULAR_TRACES:
      trace_data = fix_circular_traces(trace_data)

    return trace_data


def extract_thread_list(trace_lines):
  """Removes the thread list from the given trace data.

  Args:
    trace_lines: The text portion of the trace

  Returns:
    a map of thread ids to thread names
  """

  threads = {}
  # Assume any line that starts with USER is the header
  header = -1
  for i, line in enumerate(trace_lines):
    cols = line.split()
    if len(cols) >= 8 and cols[0] == 'USER':
      header = i
      break
  if header == -1:
    return threads
  for line in trace_lines[header + 1:]:
    cols = line.split(None, 8)
    if len(cols) == 9:
      tid = int(cols[1])
      name = cols[8]
      threads[tid] = name

  return threads


def extract_tgids(trace_lines):
  """Removes the procfs dump from the given trace text

  Args:
    trace_lines: The text portion of the trace

  Returns:
    a map of pids to their tgid.
  """
  tgid_2pid = {}
  for line in trace_lines:
    result = re.match('^/proc/([0-9]+)/task/([0-9]+)', line)
    if result:
      parent_pid, tgid = result.group(1, 2)
      tgid_2pid[tgid] = parent_pid

  return tgid_2pid


def strip_and_decompress_trace(trace_data):
  """Fixes new-lines and decompresses trace data.

  Args:
    trace_data: The trace data returned by atrace.
  Returns:
    The decompressed trace data.
  """
  # Collapse CRLFs that are added by adb shell.
  if trace_data.startswith('\r\n'):
    trace_data = trace_data.replace('\r\n', '\n')
  elif trace_data.startswith('\r\r\n'):
    # On windows, adb adds an extra '\r' character for each line.
    trace_data = trace_data.replace('\r\r\n', '\n')

  # Skip the initial newline.
  if trace_data[0] == '\n':
    trace_data = trace_data[1:]

  if not trace_data.startswith(TRACE_TEXT_HEADER):
    # No header found, so assume the data is compressed.
    trace_data = zlib.decompress(trace_data)

  # Enforce Unix line-endings.
  trace_data = trace_data.replace('\r', '')

  # Skip any initial newlines.
  while trace_data and trace_data[0] == '\n':
    trace_data = trace_data[1:]

  return trace_data


def fix_thread_names(trace_data, thread_names):
  """Replaces thread ids with their names.

  Args:
    trace_data: The atrace data.
    thread_names: A mapping of thread ids to thread names.
  Returns:
    The updated trace data.
  """

  def repl(m):
    tid = int(m.group(2))
    if tid > 0:
      name = thread_names.get(tid)
      if name is None:
        name = m.group(1)
        if name == '<...>':
          name = '<' + str(tid) + '>'
        thread_names[tid] = name
      return name + '-' + m.group(2)
    else:
      return m.group(0)

  # matches something like:
  # Binder_2-895, or com.google.android.inputmethod.latin-1078 etc...
  trace_data = re.sub(r'^\s*(\S+)-(\d+)', repl, trace_data,
                      flags=re.MULTILINE)
  return trace_data


def fix_missing_tgids(trace_data, pid2_tgid):
  """Replaces missing TGIDs from the trace data with those found in procfs

  Args:
    trace_data: the atrace data

  Returns:
    The updated trace data with missing TGIDs replaced with the correct TGID
  """

  def repl(m):
    tid = m.group(2)
    if (int(tid) > 0 and m.group(1) != '<idle>' and m.group(3) == '(-----)'
        and tid in pid2_tgid):
      # returns Proc_name-PID (TGID)
      # Binder_2-381 (-----) becomes Binder_2-381 (128)
      return m.group(1) + '-' + m.group(2) + ' ( ' + pid2_tgid[tid] + ')'

    return m.group(0)

  # matches something like:
  # Binder_2-895 (-----)
  trace_data = re.sub(r'^\s*(\S+)-(\d+)\s+(\(\S+\))', repl, trace_data,
                      flags=re.MULTILINE)
  return trace_data


def fix_circular_traces(out):
  """Fix inconsistentcies in traces due to circular buffering.

  The circular buffers are kept per CPU, so it is not guaranteed that the
  beginning of a slice is overwritten before the end. To work around this, we
  throw away the prefix of the trace where not all CPUs have events yet.

  Args:
    out: The data to fix.
  Returns:
    The updated trace data.
  """
  # If any of the CPU's buffers have filled up and
  # older events have been dropped, the kernel
  # emits markers of the form '##### CPU 2 buffer started ####' on
  # the line before the first event in the trace on that CPU.
  #
  # No such headers are emitted if there were no overflows or the trace
  # was captured with non-circular buffers.
  buffer_start_re = re.compile(r'^#+ CPU \d+ buffer started', re.MULTILINE)

  start_of_full_trace = 0

  while True:
    result = buffer_start_re.search(out, start_of_full_trace + 1)
    if result:
      start_of_full_trace = result.start()
    else:
      break

  if start_of_full_trace > 0:
    # Need to keep the header intact to make the importer happy.
    end_of_header = re.search(r'^[^#]', out, re.MULTILINE).start()
    out = out[:end_of_header] + out[start_of_full_trace:]
  return out


class AtraceConfig(tracing_agents.TracingConfig):
  def __init__(self, atrace_categories, trace_buf_size, kfuncs,
               app_name, compress_trace_data, from_file,
               device_serial_number, trace_time, target):
    tracing_agents.TracingConfig.__init__(self)
    self.atrace_categories = atrace_categories
    self.trace_buf_size = trace_buf_size
    self.kfuncs = kfuncs
    self.app_name = app_name
    self.compress_trace_data = compress_trace_data
    self.from_file = from_file
    self.device_serial_number = device_serial_number
    self.trace_time = trace_time
    self.target = target


def add_options(parser):
  options = optparse.OptionGroup(parser, 'Atrace options')
  options.add_option('--atrace-categories', dest='atrace_categories',
                     help='Select atrace categories with a comma-delimited '
                     'list, e.g. --atrace-categories=cat1,cat2,cat3')
  options.add_option('-k', '--ktrace', dest='kfuncs', action='store',
                     help='specify a comma-separated list of kernel functions '
                     'to trace')
  options.add_option('--no-compress', dest='compress_trace_data',
                     default=True, action='store_false',
                     help='Tell the device not to send the trace data in '
                     'compressed form.')
  options.add_option('-a', '--app', dest='app_name', default=None,
                     type='string', action='store',
                     help='enable application-level tracing for '
                     'comma-separated list of app cmdlines')
  options.add_option('--from-file', dest='from_file',
                     action='store', help='read the trace from a '
                     'file (compressed) rather than running a '
                     'live trace')
  return options

def get_config(options):
  return AtraceConfig(options.atrace_categories,
                      options.trace_buf_size, options.kfuncs,
                      options.app_name, options.compress_trace_data,
                      options.from_file, options.device_serial_number,
                      options.trace_time, options.target)
