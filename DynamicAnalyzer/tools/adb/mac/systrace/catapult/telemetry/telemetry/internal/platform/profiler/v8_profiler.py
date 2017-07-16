# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re
import tempfile

from telemetry.internal.platform import profiler


class V8Profiler(profiler.Profiler):

  _V8_ARG = '--js-flags=--logfile=%s --prof --log-timer-events'

  @classmethod
  def name(cls):
    return 'v8'

  @classmethod
  def is_supported(cls, browser_type):
    return not browser_type.startswith('cros')

  @classmethod
  def CustomizeBrowserOptions(cls, browser_type, options):
    if browser_type.startswith('android'):
      dump_file = '/data/local/tmp/v8-profile.log'
    else:
      dump_file = tempfile.mkstemp()[1]
    options.AppendExtraBrowserArgs([cls._V8_ARG % dump_file, '--no-sandbox'])

  def CollectProfile(self):
    # Find output filename from browser argument.
    for i in self._browser_backend.browser_options.extra_browser_args:
      match = re.match(self._V8_ARG % r'(\S+)', i)
      if match:
        output_file = match.groups(0)[0]
    assert output_file
    # On Android pull the output file to the host.
    if self._platform_backend.GetOSName() == 'android':
      host_output_file = '%s.log' % self._output_path
      self._browser_backend.device.PullFile(output_file, host_output_file)
      # Clean the device
      self._browser_backend.device.RemovePath(output_file)
      output_file = host_output_file
    print 'V8 profile saved as %s' % output_file
    print 'To view, open in ' \
          'http://v8.googlecode.com/svn/trunk/tools/tick-processor.html'
    return [output_file]
