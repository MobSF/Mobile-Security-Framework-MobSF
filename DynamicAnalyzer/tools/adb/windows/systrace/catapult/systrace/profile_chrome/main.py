#!/usr/bin/env python
#
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import optparse
import os
import sys
import webbrowser

from profile_chrome import chrome_tracing_agent
from profile_chrome import ddms_tracing_agent
from profile_chrome import flags
from profile_chrome import perf_tracing_agent
from profile_chrome import profiler
from profile_chrome import ui
from systrace import util
from systrace.tracing_agents import atrace_agent

from devil.android import device_utils
from devil.android.sdk import adb_wrapper


_PROFILE_CHROME_AGENT_MODULES = [chrome_tracing_agent, ddms_tracing_agent,
                                 perf_tracing_agent, atrace_agent]


def _CreateOptionParser():
  parser = optparse.OptionParser(description='Record about://tracing profiles '
                                 'from Android browsers. See http://dev.'
                                 'chromium.org/developers/how-tos/trace-event-'
                                 'profiling-tool for detailed instructions for '
                                 'profiling.', conflict_handler='resolve')

  parser = util.get_main_options(parser)

  timed_options = optparse.OptionGroup(parser, 'Timed tracing')
  timed_options.add_option('-t', '--time', help='Profile for N seconds and '
                          'download the resulting trace.', metavar='N',
                           type='float', dest='trace_time')
  parser.add_option_group(timed_options)

  cont_options = optparse.OptionGroup(parser, 'Continuous tracing')
  cont_options.add_option('--continuous', help='Profile continuously until '
                          'stopped.', action='store_true')
  cont_options.add_option('--ring-buffer', help='Use the trace buffer as a '
                          'ring buffer and save its contents when stopping '
                          'instead of appending events into one long trace.',
                          action='store_true')
  parser.add_option_group(cont_options)

  parser.add_option_group(flags.OutputOptions(parser))

  browsers = sorted(util.get_supported_browsers().keys())
  parser.add_option('-b', '--browser', help='Select among installed browsers. '
                    'One of ' + ', '.join(browsers) + ', "stable" is used by '
                    'default.', type='choice', choices=browsers,
                    default='stable')
  parser.add_option('-v', '--verbose', help='Verbose logging.',
                    action='store_true')
  parser.add_option('-z', '--compress', help='Compress the resulting trace '
                    'with gzip. ', action='store_true')

  # Add options from profile_chrome agents.
  for module in _PROFILE_CHROME_AGENT_MODULES:
    parser.add_option_group(module.add_options(parser))

  return parser


def main():
  parser = _CreateOptionParser()
  options, _args = parser.parse_args()  # pylint: disable=unused-variable
  if options.trace_cc:
    parser.error("""--trace-cc is deprecated.

For basic jank busting uses, use  --trace-frame-viewer
For detailed study of ubercompositor, pass --trace-ubercompositor.

When in doubt, just try out --trace-frame-viewer.
""")

  logging.basicConfig()

  if options.verbose:
    logging.getLogger().setLevel(logging.DEBUG)

  if not options.device_serial_number:
    devices = [a.GetDeviceSerial() for a in adb_wrapper.AdbWrapper.Devices()]
    if len(devices) == 0:
      raise RuntimeError('No ADB devices connected.')
    elif len(devices) >= 2:
      raise RuntimeError('Multiple devices connected, serial number required')
    options.device_serial_number = devices[0]
  device = device_utils.DeviceUtils.HealthyDevices(device_arg=
      options.device_serial_number)[0]
  package_info = util.get_supported_browsers()[options.browser]

  options.device = device
  options.package_info = package_info

  # Include Chrome categories by default in profile_chrome.
  if not options.chrome_categories:
    options.chrome_categories = chrome_tracing_agent.DEFAULT_CHROME_CATEGORIES

  if options.chrome_categories in ['list', 'help']:
    ui.PrintMessage('Collecting record categories list...', eol='')
    record_categories = []
    disabled_by_default_categories = []
    record_categories, disabled_by_default_categories = \
        chrome_tracing_agent.ChromeTracingAgent.GetCategories(
            device, package_info)

    ui.PrintMessage('done')
    ui.PrintMessage('Record Categories:')
    ui.PrintMessage('\n'.join('\t%s' % item \
        for item in sorted(record_categories)))

    ui.PrintMessage('\nDisabled by Default Categories:')
    ui.PrintMessage('\n'.join('\t%s' % item \
        for item in sorted(disabled_by_default_categories)))

    return 0

  if options.atrace_categories in ['list', 'help']:
    atrace_agent.list_categories(atrace_agent.get_config(options))
    print '\n'
    return 0

  if (perf_tracing_agent.PerfProfilerAgent.IsSupported() and
      options.perf_categories in ['list', 'help']):
    ui.PrintMessage('\n'.join(
        perf_tracing_agent.PerfProfilerAgent.GetCategories(device)))
    return 0

  if not options.trace_time and not options.continuous:
    ui.PrintMessage('Time interval or continuous tracing should be specified.')
    return 1

  if (options.chrome_categories and options.atrace_categories and
      'webview' in options.atrace_categories):
    logging.warning('Using the "webview" category in atrace together with '
                    'Chrome tracing results in duplicate trace events.')

  if options.output_file:
    options.output_file = os.path.expanduser(options.output_file)
  result = profiler.CaptureProfile(
      options,
      options.trace_time if not options.continuous else 0,
      _PROFILE_CHROME_AGENT_MODULES,
      output=options.output_file,
      compress=options.compress,
      write_json=options.write_json)
  if options.view:
    if sys.platform == 'darwin':
      os.system('/usr/bin/open %s' % os.path.abspath(result))
    else:
      webbrowser.open(result)
