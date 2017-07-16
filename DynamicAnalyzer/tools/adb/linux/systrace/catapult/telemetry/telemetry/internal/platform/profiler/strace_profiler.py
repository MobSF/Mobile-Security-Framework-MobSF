# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import logging
import re
import signal
import subprocess
import sys
import tempfile

from telemetry.internal.platform import profiler
from telemetry.timeline import model
from tracing.trace_data import trace_data as trace_data_module


# Parses one line of strace output, for example:
# 6052  1311456063.159722 read(8, "\1\0\0\0\0\0\0\0", 8) = 8 <0.000022>
_STRACE_LINE_RE = re.compile(
    r'^(?P<tid>\d+)\s+'
    r'(?P<ts>\d+)'
    r'(?P<micro>.\d+)\s+'
    r'(?P<func>.*?)'
    r'[(](?P<args>.*?)[)]\s+=\s+'
    r'(?P<ret>.*?)\s+'
    r'<(?P<dur>[\d.]+)>$')

_UNFINISHED_LINE_RE = re.compile(
    r'^(?P<tid>\d+)\s+'
    r'(?P<line>.*?)'
    r'<unfinished ...>$')

_RESUMED_LINE_RE = re.compile(
    r'^(?P<tid>\d+)\s+'
    r'(?P<ts>\d+)'
    r'(?P<micro>.\d+)\s+'
    r'<[.][.][.]\s(?P<func>.*?)\sresumed>'
    r'(?P<line>.*?)$')

_KILLED_LINE_RE = re.compile(
    r'^(?P<tid>\d+)\s+'
    r'(?P<ts>\d+)'
    r'(?P<micro>.\d+)\s+'
    r'[+][+][+] killed by SIGKILL [+][+][+]$')


def _StraceToChromeTrace(pid, infile):
  """Returns chrometrace json format for |infile| strace output."""
  # Map of fd:file_name for open file descriptors. Useful for displaying
  # file name instead of the descriptor number.
  fd_map = {}

  # Map of tid:interrupted_call for the interrupted call on each thread. It is
  # possible to context switch during a system call. In this case we must
  # match up the lines.
  interrupted_call_map = {}

  out = []
  with open(infile, 'r') as f:
    for line in f.readlines():
      # Ignore kill lines for now.
      m = _KILLED_LINE_RE.match(line)
      if m:
        continue

      # If this line is interrupted, then remember it and continue.
      m = _UNFINISHED_LINE_RE.match(line)
      if m:
        assert m.group('tid') not in interrupted_call_map
        interrupted_call_map[m.group('tid')] = line
        continue

      # If this is a resume of a previous line, stitch it together.
      interrupted = False
      m = _RESUMED_LINE_RE.match(line)
      if m:
        interrupted = True
        assert m.group('tid') in interrupted_call_map
        line = interrupted_call_map[m.group('tid')].replace(
            '<unfinished ...>', m.group('line'))
        del interrupted_call_map[m.group('tid')]

      # At this point we can do a normal match.
      m = _STRACE_LINE_RE.match(line)
      if not m:
        if ('exit' not in line and
            'Profiling timer expired' not in line and
            '<unavailable>' not in line):
          logging.warn('Failed to parse line: %s' % line)
        continue

      ts_begin = int(1000000 * (int(m.group('ts')) + float(m.group('micro'))))
      ts_end = ts_begin + int(1000000 * float(m.group('dur')))
      tid = int(m.group('tid'))
      function_name = unicode(m.group('func'), errors='ignore')
      function_args = unicode(m.group('args'), errors='ignore')
      ret = unicode(m.group('ret'), errors='ignore')
      cat = 'strace'

      possible_fd_arg = None
      first_arg = function_args.split(',')[0]
      if first_arg and first_arg.strip().isdigit():
        possible_fd_arg = first_arg.strip()

      if function_name == 'open' and ret.isdigit():
        # 1918  1311606151.649379 open("/foo/bar.so", O_RDONLY) = 7 <0.000088>
        fd_map[ret] = first_arg

      args = {
          'args': function_args,
          'ret': ret,
          }
      if interrupted:
        args['interrupted'] = True
      if possible_fd_arg and possible_fd_arg in fd_map:
        args['fd%s' % first_arg] = fd_map[possible_fd_arg]

      out.append({
          'cat': cat,
          'pid': pid,
          'tid': tid,
          'ts': ts_begin,
          'ph': 'B',  # Begin
          'name': function_name,
          })
      out.append({
          'cat': cat,
          'pid': pid,
          'tid': tid,
          'ts': ts_end,
          'ph': 'E',  # End
          'name': function_name,
          'args': args,
          })

  return out


def _GenerateTraceMetadata(timeline_model):
  out = []
  for process in timeline_model.processes:
    out.append({
        'name': 'process_name',
        'ph': 'M',  # Metadata
        'pid': process,
        'args': {
          'name': timeline_model.processes[process].name
          }
        })
    for thread in timeline_model.processes[process].threads:
      out.append({
          'name': 'thread_name',
          'ph': 'M',  # Metadata
          'pid': process,
          'tid': thread,
          'args': {
            'name': timeline_model.processes[process].threads[thread].name
            }
          })
  return out


class _SingleProcessStraceProfiler(object):
  """An internal class for using perf for a given process."""
  def __init__(self, pid, output_file, platform_backend):
    self._pid = pid
    self._platform_backend = platform_backend
    self._output_file = output_file
    self._tmp_output_file = tempfile.NamedTemporaryFile('w', 0)
    self._proc = subprocess.Popen(
        ['strace', '-ttt', '-f', '-T', '-p', str(pid), '-o', output_file],
        stdout=self._tmp_output_file, stderr=subprocess.STDOUT)

  def CollectProfile(self):
    if ('renderer' in self._output_file and
        not self._platform_backend.GetCommandLine(self._pid)):
      logging.warning('Renderer was swapped out during profiling. '
                      'To collect a full profile rerun with '
                      '"--extra-browser-args=--single-process"')
    self._proc.send_signal(signal.SIGINT)
    exit_code = self._proc.wait()
    try:
      if exit_code:
        raise Exception('strace failed with exit code %d. Output:\n%s' % (
                        exit_code, self._GetStdOut()))
    finally:
      self._tmp_output_file.close()

    return _StraceToChromeTrace(self._pid, self._output_file)

  def _GetStdOut(self):
    self._tmp_output_file.flush()
    try:
      with open(self._tmp_output_file.name) as f:
        return f.read()
    except IOError:
      return ''


class StraceProfiler(profiler.Profiler):

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(StraceProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    assert self._browser_backend.supports_tracing
    self._browser_backend.browser.StartTracing(None, timeout=10)
    process_output_file_map = self._GetProcessOutputFileMap()
    self._process_profilers = []
    self._output_file = output_path + '.json'
    for pid, output_file in process_output_file_map.iteritems():
      if 'zygote' in output_file:
        continue
      self._process_profilers.append(
          _SingleProcessStraceProfiler(pid, output_file, platform_backend))

  @classmethod
  def name(cls):
    return 'strace'

  @classmethod
  def is_supported(cls, browser_type):
    if sys.platform != 'linux2':
      return False
    # TODO(tonyg): This should be supported on android and cros.
    if (browser_type.startswith('android') or
       browser_type.startswith('cros')):
      return False
    return True

  @classmethod
  def CustomizeBrowserOptions(cls, browser_type, options):
    options.AppendExtraBrowserArgs([
        '--no-sandbox',
        '--allow-sandbox-debugging'
    ])

  def CollectProfile(self):
    print 'Processing trace...'

    out_json = []

    for single_process in self._process_profilers:
      out_json.extend(single_process.CollectProfile())

    trace_data_builder = trace_data_module.TraceDataBuilder()
    self._browser_backend.browser.StopTracing(trace_data_builder)
    timeline_model = model.TimelineModel(trace_data_builder.AsData())
    out_json.extend(_GenerateTraceMetadata(timeline_model))

    with open(self._output_file, 'w') as f:
      f.write(json.dumps(out_json, separators=(',', ':')))

    print 'Trace saved as %s' % self._output_file
    print 'To view, open in chrome://tracing'
    return [self._output_file]
