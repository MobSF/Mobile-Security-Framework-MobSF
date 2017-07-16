# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import subprocess
import sys
import tempfile

from telemetry.core import exceptions
from telemetry.internal.platform import profiler
from telemetry.internal.platform.profiler import android_profiling_helper

from devil.android.sdk import adb_wrapper


class _SingleProcessVTuneProfiler(object):
  """An internal class for using vtune for a given process."""
  def __init__(self, pid, output_file, browser_backend, platform_backend):
    self._pid = pid
    self._browser_backend = browser_backend
    self._platform_backend = platform_backend
    self._output_file = output_file
    self._tmp_output_file = tempfile.NamedTemporaryFile('w', 0)
    cmd = ['amplxe-cl', '-collect', 'hotspots',
           '-target-pid', str(pid), '-r', self._output_file]
    self._is_android = platform_backend.GetOSName() == 'android'
    if self._is_android:
      cmd += ['-target-system', 'android']

    self._proc = subprocess.Popen(
        cmd, stdout=self._tmp_output_file, stderr=subprocess.STDOUT)

  def CollectProfile(self):
    if 'renderer' in self._output_file:
      try:
        self._platform_backend.GetCommandLine(self._pid)
      except exceptions.ProcessGoneException:
        logging.warning('Renderer was swapped out during profiling. '
                        'To collect a full profile rerun with '
                        '"--extra-browser-args=--single-process"')
    subprocess.call(['amplxe-cl', '-command', 'stop', '-r', self._output_file])

    exit_code = self._proc.wait()
    try:
      # 1: amplxe: Error: Cannot find a running process with the specified ID.
      #    Provide a valid PID.
      if exit_code not in (0, 1):
        raise Exception(
            'amplxe-cl failed with exit code %d. Output:\n%s' % (exit_code,
            self._GetStdOut()))
    finally:
      self._tmp_output_file.close()

    if exit_code:
      # The renderer process was swapped out. Now that we made sure VTune has
      # stopped, return without further processing the invalid profile.
      return self._output_file

    if self._is_android:
      required_libs = \
          android_profiling_helper.GetRequiredLibrariesForVTuneProfile(
              self._output_file)

      device = self._browser_backend.device
      symfs_root = os.path.join(os.path.dirname(self._output_file), 'symfs')
      if not os.path.exists(symfs_root):
        os.makedirs(symfs_root)
      android_profiling_helper.CreateSymFs(device,
                                           symfs_root,
                                           required_libs,
                                           use_symlinks=True)
      logging.info('Resolving symbols in profile.')
      subprocess.call(['amplxe-cl', '-finalize', '-r', self._output_file,
                       '-search-dir', symfs_root])

    print 'To view the profile, run:'
    print '  amplxe-gui %s' % self._output_file

    return self._output_file

  def _GetStdOut(self):
    self._tmp_output_file.flush()
    try:
      with open(self._tmp_output_file.name) as f:
        return f.read()
    except IOError:
      return ''


class VTuneProfiler(profiler.Profiler):

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(VTuneProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    process_output_file_map = self._GetProcessOutputFileMap()
    self._process_profilers = []

    has_renderer = False
    for pid, output_file in process_output_file_map.iteritems():
      if 'renderer' in output_file:
        has_renderer = True
        break

    for pid, output_file in process_output_file_map.iteritems():
      if has_renderer:
        if not 'renderer' in output_file:
          continue
      elif not 'browser0' in output_file:
        continue

      self._process_profilers.append(
          _SingleProcessVTuneProfiler(pid, output_file, browser_backend,
                                      platform_backend))

  @classmethod
  def name(cls):
    return 'vtune'

  @classmethod
  def is_supported(cls, browser_type):
    if sys.platform != 'linux2':
      return False
    if browser_type.startswith('cros'):
      return False
    try:
      proc = subprocess.Popen(['amplxe-cl', '-version'],
                              stderr=subprocess.STDOUT,
                              stdout=subprocess.PIPE)
      proc.communicate()
      if proc.returncode != 0:
        return False

      if browser_type.startswith('android'):
        # VTune checks if 'su' is available on the device.
        proc = subprocess.Popen(
            [adb_wrapper.AdbWrapper.GetAdbPath(),
             'shell', 'su', '-c', 'id'],
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE)
        return 'not found' not in proc.communicate()[0]

      return True
    except OSError:
      return False

  @classmethod
  def CustomizeBrowserOptions(cls, browser_type, options):
    options.AppendExtraBrowserArgs([
        '--no-sandbox',
        '--allow-sandbox-debugging',
    ])

  def CollectProfile(self):
    print 'Processing profile, this will take a few minutes...'

    output_files = []
    for single_process in self._process_profilers:
      output_files.append(single_process.CollectProfile())
    return output_files
