# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class ProfilingController(object):

  def __init__(self, profiling_controller_backend):
    self._profiling_controller_backend = profiling_controller_backend

  def Start(self, profiler_name, base_output_file):
    self._profiling_controller_backend.Start(profiler_name, base_output_file)

  def Stop(self):
    return self._profiling_controller_backend.Stop()
