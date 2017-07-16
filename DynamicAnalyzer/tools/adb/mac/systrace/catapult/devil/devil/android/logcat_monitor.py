# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=unused-argument

import errno
import logging
import os
import re
import shutil
import tempfile
import threading
import time

from devil.android import decorators
from devil.android import device_errors
from devil.android.sdk import adb_wrapper
from devil.utils import reraiser_thread

logger = logging.getLogger(__name__)


class LogcatMonitor(object):

  _RECORD_ITER_TIMEOUT = 2.0
  _RECORD_THREAD_JOIN_WAIT = 5.0
  _WAIT_TIME = 0.2
  _THREADTIME_RE_FORMAT = (
      r'(?P<date>\S*) +(?P<time>\S*) +(?P<proc_id>%s) +(?P<thread_id>%s) +'
      r'(?P<log_level>%s) +(?P<component>%s) *: +(?P<message>%s)$')

  def __init__(self, adb, clear=True, filter_specs=None, output_file=None):
    """Create a LogcatMonitor instance.

    Args:
      adb: An instance of adb_wrapper.AdbWrapper.
      clear: If True, clear the logcat when monitoring starts.
      filter_specs: An optional list of '<tag>[:priority]' strings.
      output_file: File path to save recorded logcat.
    """
    if isinstance(adb, adb_wrapper.AdbWrapper):
      self._adb = adb
    else:
      raise ValueError('Unsupported type passed for argument "device"')
    self._clear = clear
    self._filter_specs = filter_specs
    self._output_file = output_file
    self._record_file = None
    self._record_file_lock = threading.Lock()
    self._record_thread = None
    self._stop_recording_event = threading.Event()

  @property
  def output_file(self):
    return self._output_file

  @decorators.WithTimeoutAndRetriesDefaults(10, 0)
  def WaitFor(self, success_regex, failure_regex=None, timeout=None,
              retries=None):
    """Wait for a matching logcat line or until a timeout occurs.

    This will attempt to match lines in the logcat against both |success_regex|
    and |failure_regex| (if provided). Note that this calls re.search on each
    logcat line, not re.match, so the provided regular expressions don't have
    to match an entire line.

    Args:
      success_regex: The regular expression to search for.
      failure_regex: An optional regular expression that, if hit, causes this
        to stop looking for a match. Can be None.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      A match object if |success_regex| matches a part of a logcat line, or
      None if |failure_regex| matches a part of a logcat line.
    Raises:
      CommandFailedError on logcat failure (NOT on a |failure_regex| match).
      CommandTimeoutError if no logcat line matching either |success_regex| or
        |failure_regex| is found in |timeout| seconds.
      DeviceUnreachableError if the device becomes unreachable.
      LogcatMonitorCommandError when calling |WaitFor| while not recording
        logcat.
    """
    if self._record_thread is None:
      raise LogcatMonitorCommandError(
          'Must be recording logcat when calling |WaitFor|',
          device_serial=str(self._adb))
    if isinstance(success_regex, basestring):
      success_regex = re.compile(success_regex)
    if isinstance(failure_regex, basestring):
      failure_regex = re.compile(failure_regex)

    logger.debug('Waiting %d seconds for "%s"', timeout, success_regex.pattern)

    # NOTE This will continue looping until:
    #  - success_regex matches a line, in which case the match object is
    #    returned.
    #  - failure_regex matches a line, in which case None is returned
    #  - the timeout is hit, in which case a CommandTimeoutError is raised.
    with open(self._record_file.name, 'r') as f:
      while True:
        line = f.readline()
        if line:
          m = success_regex.search(line)
          if m:
            return m
          if failure_regex and failure_regex.search(line):
            return None
        else:
          time.sleep(self._WAIT_TIME)

  def FindAll(self, message_regex, proc_id=None, thread_id=None, log_level=None,
              component=None):
    """Finds all lines in the logcat that match the provided constraints.

    Args:
      message_regex: The regular expression that the <message> section must
        match.
      proc_id: The process ID to match. If None, matches any process ID.
      thread_id: The thread ID to match. If None, matches any thread ID.
      log_level: The log level to match. If None, matches any log level.
      component: The component to match. If None, matches any component.

    Raises:
      LogcatMonitorCommandError when calling |FindAll| before recording logcat.

    Yields:
      A match object for each matching line in the logcat. The match object
      will always contain, in addition to groups defined in |message_regex|,
      the following named groups: 'date', 'time', 'proc_id', 'thread_id',
      'log_level', 'component', and 'message'.
    """
    if self._record_file is None:
      raise LogcatMonitorCommandError(
          'Must have recorded or be recording a logcat to call |FindAll|',
          device_serial=str(self._adb))
    if proc_id is None:
      proc_id = r'\d+'
    if thread_id is None:
      thread_id = r'\d+'
    if log_level is None:
      log_level = r'[VDIWEF]'
    if component is None:
      component = r'[^\s:]+'
    # pylint: disable=protected-access
    threadtime_re = re.compile(
        type(self)._THREADTIME_RE_FORMAT % (
            proc_id, thread_id, log_level, component, message_regex))

    with open(self._record_file.name, 'r') as f:
      for line in f:
        m = re.match(threadtime_re, line)
        if m:
          yield m

  def _StartRecording(self):
    """Starts recording logcat to file.

    Function spawns a thread that records logcat to file and will not die
    until |StopRecording| is called.
    """
    def record_to_file():
      # Write the log with line buffering so the consumer sees each individual
      # line.
      for data in self._adb.Logcat(filter_specs=self._filter_specs,
                                   logcat_format='threadtime',
                                   iter_timeout=self._RECORD_ITER_TIMEOUT):
        if self._stop_recording_event.isSet():
          return

        if data is None:
          # Logcat can yield None if the iter_timeout is hit.
          continue

        with self._record_file_lock:
          if self._record_file and not self._record_file.closed:
            self._record_file.write(data + '\n')

    self._stop_recording_event.clear()
    if not self._record_thread:
      self._record_thread = reraiser_thread.ReraiserThread(record_to_file)
      self._record_thread.start()

  def _StopRecording(self):
    """Finish recording logcat."""
    if self._record_thread:
      self._stop_recording_event.set()
      self._record_thread.join(timeout=self._RECORD_THREAD_JOIN_WAIT)
      self._record_thread.ReraiseIfException()
      self._record_thread = None

  def Start(self):
    """Starts the logcat monitor.

    Clears the logcat if |clear| was set in |__init__|.
    """
    if self._clear:
      self._adb.Logcat(clear=True)
    if not self._record_file:
      self._record_file = tempfile.NamedTemporaryFile(mode='a', bufsize=1)
    self._StartRecording()

  def Stop(self):
    """Stops the logcat monitor.

    Stops recording the logcat. Copies currently recorded logcat to
    |self._output_file|.
    """
    self._StopRecording()
    with self._record_file_lock:
      if self._record_file and self._output_file:
        try:
          os.makedirs(os.path.dirname(self._output_file))
        except OSError as e:
          if e.errno != errno.EEXIST:
            raise
        shutil.copy(self._record_file.name, self._output_file)

  def Close(self):
    """Closes logcat recording file.

    Should be called when finished using the logcat monitor.
    """
    with self._record_file_lock:
      if self._record_file:
        self._record_file.close()
        self._record_file = None

  def __enter__(self):
    """Starts the logcat monitor."""
    self.Start()
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    """Stops the logcat monitor."""
    self.Stop()

  def __del__(self):
    """Closes logcat recording file in case |Close| was never called."""
    with self._record_file_lock:
      if self._record_file:
        logger.warning(
            'Need to call |Close| on the logcat monitor when done!')
        self._record_file.close()

  @property
  def adb(self):
    return self._adb


class LogcatMonitorCommandError(device_errors.CommandFailedError):
  """Exception for errors with logcat monitor commands."""
  pass
