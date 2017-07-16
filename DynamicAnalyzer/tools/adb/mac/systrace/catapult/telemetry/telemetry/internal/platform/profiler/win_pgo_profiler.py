# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import glob
import os
import subprocess
import sys

from telemetry.internal.platform import profiler

_PGOSWEEP_EXECUTABLE = 'pgosweep.exe'


class WinPGOProfiler(profiler.Profiler):
  """A profiler that run the Visual Studio PGO utility 'pgosweep.exe' before
  terminating a browser or a renderer process.
  """

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(WinPGOProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)

    self._pgosweep_path = None

    if os.path.exists(os.path.join(browser_backend.browser_directory,
                                   _PGOSWEEP_EXECUTABLE)):
      self._pgosweep_path = os.path.join(browser_backend.browser_directory,
                                         _PGOSWEEP_EXECUTABLE)

    if not self._pgosweep_path:
      for entry in os.environ['PATH'].split(os.pathsep):
        if os.path.exists(os.path.join(entry, _PGOSWEEP_EXECUTABLE)):
          self._pgosweep_path = os.path.join(entry, _PGOSWEEP_EXECUTABLE)
          break
    if not self._pgosweep_path:
      raise IOError(2, 'Can\'t find %s, run vcvarsall.bat to fix this.' %
                    _PGOSWEEP_EXECUTABLE)

    self._browser_dir = browser_backend.browser_directory
    self._chrome_child_pgc_counter = self._GetNextProfileIndex('chrome_child')

  def _GetNextProfileIndex(self, dll_name):
    """Scan the directory containing the DLL |dll_name| to find the next index
    to use for the profile data files.

    Args:
      dll_name: The name of the DLL for which we want to get the next index to
          to use.
    """
    max_index = 0
    pgc_files = glob.glob(os.path.join(self._browser_dir,
                                       '%s!*.pgc' % dll_name))
    for pgc_file in pgc_files:
      max_index = max(max_index,
          int(os.path.splitext(os.path.split(pgc_file)[1])[0].split('!')[1]))
    return max_index + 1

  def _RunPGOSweep(self, pid, dll_name, index):
    """Run the pgosweep utility to gather the profile data of a given process.

    Args:
      pid: The PID of the process we're interested in.
      dll_name: The name of the DLL for which we want the profile data.
      index: The index to use for the profile data file.

    Returns the name of the profile data file.
    """
    pgc_filename = '%s\\%s!%d.pgc' % (self._browser_dir, dll_name, index)
    subprocess.Popen([self._pgosweep_path,
                      '/pid:%d' % pid,
                      '%s.dll' % dll_name,
                      pgc_filename]
                    ).wait()
    return pgc_filename

  @classmethod
  def name(cls):
    return 'win_pgo_profiler'

  @classmethod
  def is_supported(cls, browser_type):
    # This profiler only make sense when doing a Windows build with Visual
    # Studio (minimal supported version is 2013 Update 2).
    return sys.platform.startswith('win')

  @classmethod
  def CustomizeBrowserOptions(cls, browser_type, options):
    # The sandbox need to be disabled if we want to be able to gather the
    # profile data.
    options.AppendExtraBrowserArgs('--no-sandbox')

  def CollectProfile(self):
    """Collect the profile data for the current processes."""
    output_files = []
    for pid, output_file in self._GetProcessOutputFileMap().iteritems():
      if 'renderer' in output_file:
        output_files.append(self._RunPGOSweep(pid,
                                              'chrome_child',
                                              self._chrome_child_pgc_counter))
        self._chrome_child_pgc_counter += 1
    return output_files
