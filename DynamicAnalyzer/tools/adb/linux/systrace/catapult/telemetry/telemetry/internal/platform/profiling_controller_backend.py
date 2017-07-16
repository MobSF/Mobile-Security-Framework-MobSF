# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.internal.platform.profiler import profiler_finder


class ProfilingControllerBackend(object):
  def __init__(self, platform_backend, browser_backend):
    self._platform_backend = platform_backend
    self._browser_backend = browser_backend
    self._active_profilers = []
    self._profilers_states = {}

  def Start(self, profiler_name, base_output_file):
    """Starts profiling using |profiler_name|. Results are saved to
    |base_output_file|.<process_name>."""
    assert not self._active_profilers, 'Already profiling. Must stop first.'

    profiler_class = profiler_finder.FindProfiler(profiler_name)

    if not profiler_class.is_supported(self._browser_backend.browser_type):
      raise Exception('The %s profiler is not '
                      'supported on this platform.' % profiler_name)

    if not profiler_class in self._profilers_states:
      self._profilers_states[profiler_class] = {}

    self._active_profilers.append(
        profiler_class(self._browser_backend, self._platform_backend,
            base_output_file, self._profilers_states[profiler_class]))

  def Stop(self):
    """Stops all active profilers and saves their results.

    Returns:
      A list of filenames produced by the profiler.
    """
    output_files = []
    for profiler in self._active_profilers:
      output_files.extend(profiler.CollectProfile())
    self._active_profilers = []
    return output_files

  def WillCloseBrowser(self):
    for profiler_class in self._profilers_states:
      profiler_class.WillCloseBrowser(
        self._browser_backend, self._platform_backend)
