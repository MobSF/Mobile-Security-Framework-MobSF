#!/usr/bin/env python

# Copyright (c) 2011 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Android system-wide tracing utility.

This is a tool for capturing a trace that includes data from both userland and
the kernel.  It creates an HTML file for visualizing the trace.
"""

# Make sure we're using a new enough version of Python.
# The flags= parameter of re.sub() is new in Python 2.7. And Systrace does not
# support Python 3 yet.

import sys

version = sys.version_info[:2]
if version != (2, 7):
  sys.stderr.write('This script does not support Python %d.%d. '
                   'Please use Python 2.7.\n' % version)
  sys.exit(1)


import optparse
import os
import time

_SYSTRACE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.path.pardir))
_CATAPULT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.path.pardir, os.path.pardir)
_DEVIL_DIR = os.path.join(_CATAPULT_DIR, 'devil')
if _DEVIL_DIR not in sys.path:
  sys.path.insert(0, _DEVIL_DIR)
if _SYSTRACE_DIR not in sys.path:
  sys.path.insert(0, _SYSTRACE_DIR)

from devil import devil_env
from devil.android.sdk import adb_wrapper
from systrace import systrace_runner
from systrace import util
from systrace.tracing_agents import atrace_agent
from systrace.tracing_agents import atrace_from_file_agent
from systrace.tracing_agents import battor_trace_agent
from systrace.tracing_agents import ftrace_agent

ALL_MODULES = [atrace_agent, atrace_from_file_agent,
               battor_trace_agent, ftrace_agent]


def parse_options(argv):
  """Parses and checks the command-line options.

  Returns:
    A tuple containing the options structure and a list of categories to
    be traced.
  """
  usage = 'Usage: %prog [options] [category1 [category2 ...]]'
  desc = 'Example: %prog -b 32768 -t 15 gfx input view sched freq'
  parser = optparse.OptionParser(usage=usage, description=desc,
                                 conflict_handler='resolve')
  parser = util.get_main_options(parser)

  parser.add_option('-l', '--list-categories', dest='list_categories',
                    default=False, action='store_true',
                    help='list the available categories and exit')

  # Add the other agent parsing options to the parser. For Systrace on the
  # command line, all agents are added. For Android, only the compatible agents
  # will be added.
  for module in ALL_MODULES:
    option_group = module.add_options(parser)
    if option_group:
      parser.add_option_group(option_group)

  options, categories = parser.parse_args(argv[1:])

  if options.output_file is None:
    options.output_file = 'trace.json' if options.write_json else 'trace.html'

  if options.link_assets or options.asset_dir != 'trace-viewer':
    parser.error('--link-assets and --asset-dir are deprecated.')

  if options.trace_time and options.trace_time < 0:
    parser.error('the trace time must be a non-negative number')

  if (options.trace_buf_size is not None) and (options.trace_buf_size <= 0):
    parser.error('the trace buffer size must be a positive number')

  return (options, categories)

def find_adb():
  """Finds adb on the path.

  This method is provided to avoid the issue of diskutils.spawn's
  find_executable which first searches the current directory before
  searching $PATH. That behavior results in issues where systrace.py
  uses a different adb than the one in the path.
  """
  paths = os.environ['PATH'].split(os.pathsep)
  executable = 'adb'
  if sys.platform == 'win32':
    executable = executable + '.exe'
  for p in paths:
    f = os.path.join(p, executable)
    if os.path.isfile(f):
      return f
  return None

def initialize_devil():
  """Initialize devil to use adb from $PATH"""
  adb_path = find_adb()
  if adb_path is None:
    print >> sys.stderr, "Unable to find adb, is it in your path?"
    sys.exit(1)
  devil_dynamic_config = {
    'config_type': 'BaseConfig',
    'dependencies': {
      'adb': {
        'file_info': {
          devil_env.GetPlatform(): {
            'local_paths': [os.path.abspath(adb_path)]
          }
        }
      }
    }
  }
  devil_env.config.Initialize(configs=[devil_dynamic_config])


def main_impl(arguments):
  # Parse the command line options.
  options, categories = parse_options(arguments)

  # Override --atrace-categories and --ftrace-categories flags if command-line
  # categories are provided.
  if categories:
    if options.target == 'android':
      options.atrace_categories = categories
    elif options.target == 'linux':
      options.ftrace_categories = categories
    else:
      raise RuntimeError('Categories are only valid for atrace/ftrace. Target '
                         'platform must be either Android or Linux.')

  # Include atrace categories by default in Systrace.
  if options.target == 'android' and not options.atrace_categories:
    options.atrace_categories = atrace_agent.DEFAULT_CATEGORIES

  if options.target == 'android' and not options.from_file:
    initialize_devil()
    if not options.device_serial_number:
      devices = [a.GetDeviceSerial() for a in adb_wrapper.AdbWrapper.Devices()]
      if len(devices) == 0:
        raise RuntimeError('No ADB devices connected.')
      elif len(devices) >= 2:
        raise RuntimeError('Multiple devices connected, serial number required')
      options.device_serial_number = devices[0]

  # If list_categories is selected, just print the list of categories.
  # In this case, use of the tracing controller is not necessary.
  if options.list_categories:
    if options.target == 'android':
      atrace_agent.list_categories(options)
    elif options.target == 'linux':
      ftrace_agent.list_categories(options)
    return

  # Set up the systrace runner and start tracing.
  controller = systrace_runner.SystraceRunner(
      os.path.dirname(os.path.abspath(__file__)), options)
  controller.StartTracing()

  # Wait for the given number of seconds or until the user presses enter.
  # pylint: disable=superfluous-parens
  # (need the parens so no syntax error if trying to load with Python 3)
  if options.from_file is not None:
    print('Reading results from file.')
  elif options.trace_time:
    print('Starting tracing (%d seconds)' % options.trace_time)
    time.sleep(options.trace_time)
  else:
    raw_input('Starting tracing (stop with enter)')

  # Stop tracing and collect the output.
  print('Tracing completed. Collecting output...')
  controller.StopTracing()
  print('Outputting Systrace results...')
  controller.OutputSystraceResults(write_json=options.write_json)

def main():
  main_impl(sys.argv)

if __name__ == '__main__' and __package__ is None:
  main()
