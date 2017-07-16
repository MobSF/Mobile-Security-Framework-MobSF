# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import tempfile

from telemetry.internal.platform import profiler


class NetLogProfiler(profiler.Profiler):

  _NET_LOG_ARG = '--log-net-log='

  @classmethod
  def name(cls):
    return 'netlog'

  @classmethod
  def is_supported(cls, browser_type):
    return not browser_type.startswith('cros')

  @classmethod
  def CustomizeBrowserOptions(cls, browser_type, options):
    if browser_type.startswith('android'):
      dump_file = '/sdcard/net-internals-profile.json'
    else:
      dump_file = tempfile.mkstemp()[1]
    options.AppendExtraBrowserArgs([cls._NET_LOG_ARG + dump_file])

  def CollectProfile(self):
    # Find output filename from browser argument.
    for i in self._browser_backend.browser_options.extra_browser_args:
      if i.startswith(self._NET_LOG_ARG):
        output_file = i[len(self._NET_LOG_ARG):]
    assert output_file
    # On Android pull the output file to the host.
    if self._platform_backend.GetOSName() == 'android':
      host_output_file = '%s.json' % self._output_path
      self._browser_backend.device.PullFile(output_file, host_output_file)
      # Clean the device
      self._browser_backend.device.RemovePath(output_file)
      output_file = host_output_file
    print 'Net-internals log saved as %s' % output_file
    print 'To view, open in chrome://net-internals'
    return [output_file]
