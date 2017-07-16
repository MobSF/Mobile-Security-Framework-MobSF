# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections

from telemetry.core import exceptions

class Profiler(object):
  """A sampling profiler provided by the platform.

  A profiler is started on its constructor, and should
  gather data until CollectProfile().
  The life cycle is normally tied to a single page,
  i.e., multiple profilers will be created for a page set.
  WillCloseBrowser() is called right before the browser
  is closed to allow any further cleanup.
  """

  def __init__(self, browser_backend, platform_backend, output_path, state):
    self._browser_backend = browser_backend
    self._platform_backend = platform_backend
    self._output_path = output_path
    self._state = state

  @classmethod
  def name(cls):
    """User-friendly name of this profiler."""
    raise NotImplementedError()

  @classmethod
  def is_supported(cls, browser_type):
    """True iff this profiler is currently supported by the platform."""
    raise NotImplementedError()

  @classmethod
  def CustomizeBrowserOptions(cls, browser_type, options):
    """Override to customize the Browser's options before it is created."""
    pass

  @classmethod
  def WillCloseBrowser(cls, browser_backend, platform_backend):
    """Called before the browser is stopped."""
    pass

  def _GetProcessOutputFileMap(self):
    """Returns a dict with pid: output_file."""
    all_pids = ([self._browser_backend.pid] +
                self._platform_backend.GetChildPids(self._browser_backend.pid))

    process_name_counts = collections.defaultdict(int)
    process_output_file_map = {}
    for pid in all_pids:
      try:
        cmd_line = self._platform_backend.GetCommandLine(pid)
        process_name = self._browser_backend.GetProcessName(cmd_line)
        output_file = '%s.%s%s' % (self._output_path, process_name,
                                   process_name_counts[process_name])
        process_name_counts[process_name] += 1
        process_output_file_map[pid] = output_file
      except exceptions.ProcessGoneException:
        # Ignore processes that disappeared since calling GetChildPids().
        continue
    return process_output_file_map

  def CollectProfile(self):
    """Collect the profile from the profiler."""
    raise NotImplementedError()
