# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Parses the command line, discovers the appropriate benchmarks, and runs them.

Handles benchmark configuration, but all the logic for
actually running the benchmark is in Benchmark and PageRunner."""

import argparse
import json
import logging
import os
import sys

from telemetry import benchmark
from telemetry.core import discover
from telemetry import decorators
from telemetry.internal.browser import browser_finder
from telemetry.internal.browser import browser_options
from telemetry.internal.util import binary_manager
from telemetry.internal.util import command_line
from telemetry.internal.util import ps_util
from telemetry.util import matching
from telemetry.util import bot_utils


# Right now, we only have one of each of our power perf bots. This means that
# all eligible Telemetry benchmarks are run unsharded, which results in very
# long (12h) cycle times. We'd like to reduce the number of tests that we run
# on each bot drastically until we get more of the same hardware to shard tests
# with, but we can't do so until we've verified that the hardware configuration
# is a viable one for Chrome Telemetry tests. This is done by seeing at least
# one all-green test run. As this happens for each bot, we'll add it to this
# whitelist, making it eligible to run only BattOr power tests.
GOOD_POWER_PERF_BOT_WHITELIST = [
  "Mac Power Dual-GPU Perf",
  "Mac Power Low-End Perf"
]


DEFAULT_LOG_FORMAT = (
  '(%(levelname)s) %(asctime)s %(module)s.%(funcName)s:%(lineno)d  '
  '%(message)s')


def _IsBenchmarkEnabled(benchmark_class, possible_browser):
  return (issubclass(benchmark_class, benchmark.Benchmark) and
          decorators.IsBenchmarkEnabled(benchmark_class, possible_browser))


def PrintBenchmarkList(benchmarks, possible_browser, output_pipe=sys.stdout):
  """ Print benchmarks that are not filtered in the same order of benchmarks in
  the |benchmarks| list.

  Args:
    benchmarks: the list of benchmarks to be printed (in the same order of the
      list).
    possible_browser: the possible_browser instance that's used for checking
      which benchmarks are enabled.
    output_pipe: the stream in which benchmarks are printed on.
  """
  if not benchmarks:
    print >> output_pipe, 'No benchmarks found!'
    return

  bad_benchmark = next(
    (b for b in benchmarks if not issubclass(b, benchmark.Benchmark)), None)
  assert bad_benchmark is None, (
    '|benchmarks| param contains non benchmark class: %s' % bad_benchmark)

  # Align the benchmark names to the longest one.
  format_string = '  %%-%ds %%s' % max(len(b.Name()) for b in benchmarks)
  disabled_benchmarks = []

  print >> output_pipe, 'Available benchmarks %sare:' % (
      'for %s ' % possible_browser.browser_type if possible_browser else '')

  # Sort the benchmarks by benchmark name.
  benchmarks = sorted(benchmarks, key=lambda b: b.Name())
  for b in benchmarks:
    if not possible_browser or _IsBenchmarkEnabled(b, possible_browser):
      print >> output_pipe, format_string % (b.Name(), b.Description())
    else:
      disabled_benchmarks.append(b)

  if disabled_benchmarks:
    print >> output_pipe, (
        '\nDisabled benchmarks for %s are (force run with -d):' %
        possible_browser.browser_type)
    for b in disabled_benchmarks:
      print >> output_pipe, format_string % (b.Name(), b.Description())
  print >> output_pipe, (
      'Pass --browser to list benchmarks for another browser.\n')


class Help(command_line.OptparseCommand):
  """Display help information about a command"""

  usage = '[command]'

  def __init__(self, commands):
    self._all_commands = commands

  def Run(self, args):
    if len(args.positional_args) == 1:
      commands = _MatchingCommands(args.positional_args[0], self._all_commands)
      if len(commands) == 1:
        command = commands[0]
        parser = command.CreateParser()
        command.AddCommandLineArgs(parser, None)
        parser.print_help()
        return 0

    print >> sys.stderr, ('usage: %s [command] [<options>]' % _ScriptName())
    print >> sys.stderr, 'Available commands are:'
    for command in self._all_commands:
      print >> sys.stderr, '  %-10s %s' % (
          command.Name(), command.Description())
    print >> sys.stderr, ('"%s help <command>" to see usage information '
                          'for a specific command.' % _ScriptName())
    return 0


class List(command_line.OptparseCommand):
  """Lists the available benchmarks"""

  usage = '[benchmark_name] [<options>]'

  @classmethod
  def CreateParser(cls):
    options = browser_options.BrowserFinderOptions()
    parser = options.CreateParser('%%prog %s %s' % (cls.Name(), cls.usage))
    return parser

  @classmethod
  def AddCommandLineArgs(cls, parser, _):
    parser.add_option('-j', '--json-output-file', type='string')
    parser.add_option('-n', '--num-shards', type='int', default=1)

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args, environment):
    if not args.positional_args:
      args.benchmarks = _Benchmarks(environment)
    elif len(args.positional_args) == 1:
      args.benchmarks = _MatchBenchmarkName(args.positional_args[0],
                                            environment, exact_matches=False)
    else:
      parser.error('Must provide at most one benchmark name.')

  def Run(self, args):
    # Set at least log info level for List command.
    # TODO(nedn): remove this once crbug.com/656224 is resolved. The recipe
    # should be change to use verbose logging instead.
    logging.getLogger().setLevel(logging.INFO)
    possible_browser = browser_finder.FindBrowser(args)
    if args.browser_type in (
        'release', 'release_x64', 'debug', 'debug_x64', 'canary',
        'android-chromium', 'android-chrome'):
      args.browser_type = 'reference'
      possible_reference_browser = browser_finder.FindBrowser(args)
    else:
      possible_reference_browser = None
    if args.json_output_file:
      with open(args.json_output_file, 'w') as f:
        f.write(_GetJsonBenchmarkList(possible_browser,
                                      possible_reference_browser,
                                      args.benchmarks, args.num_shards))
    else:
      PrintBenchmarkList(args.benchmarks, possible_browser)
    return 0


class Run(command_line.OptparseCommand):
  """Run one or more benchmarks (default)"""

  usage = 'benchmark_name [page_set] [<options>]'

  @classmethod
  def CreateParser(cls):
    options = browser_options.BrowserFinderOptions()
    parser = options.CreateParser('%%prog %s %s' % (cls.Name(), cls.usage))
    return parser

  @classmethod
  def AddCommandLineArgs(cls, parser, environment):
    benchmark.AddCommandLineArgs(parser)

    # Allow benchmarks to add their own command line options.
    matching_benchmarks = []
    for arg in sys.argv[1:]:
      matching_benchmarks += _MatchBenchmarkName(arg, environment)

    if matching_benchmarks:
      # TODO(dtu): After move to argparse, add command-line args for all
      # benchmarks to subparser. Using subparsers will avoid duplicate
      # arguments.
      matching_benchmark = matching_benchmarks.pop()
      matching_benchmark.AddCommandLineArgs(parser)
      # The benchmark's options override the defaults!
      matching_benchmark.SetArgumentDefaults(parser)

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args, environment):
    all_benchmarks = _Benchmarks(environment)
    if not args.positional_args:
      possible_browser = (
          browser_finder.FindBrowser(args) if args.browser_type else None)
      PrintBenchmarkList(all_benchmarks, possible_browser)
      sys.exit(-1)

    input_benchmark_name = args.positional_args[0]
    matching_benchmarks = _MatchBenchmarkName(input_benchmark_name, environment)
    if not matching_benchmarks:
      print >> sys.stderr, 'No benchmark named "%s".' % input_benchmark_name
      print >> sys.stderr
      most_likely_matched_benchmarks = matching.GetMostLikelyMatchedObject(
          all_benchmarks, input_benchmark_name, lambda x: x.Name())
      if most_likely_matched_benchmarks:
        print >> sys.stderr, 'Do you mean any of those benchmarks below?'
        PrintBenchmarkList(most_likely_matched_benchmarks, None, sys.stderr)
      sys.exit(-1)

    if len(matching_benchmarks) > 1:
      print >> sys.stderr, ('Multiple benchmarks named "%s".' %
                            input_benchmark_name)
      print >> sys.stderr, 'Did you mean one of these?'
      print >> sys.stderr
      PrintBenchmarkList(matching_benchmarks, None, sys.stderr)
      sys.exit(-1)

    benchmark_class = matching_benchmarks.pop()
    if len(args.positional_args) > 1:
      parser.error('Too many arguments.')

    assert issubclass(benchmark_class, benchmark.Benchmark), (
        'Trying to run a non-Benchmark?!')

    benchmark.ProcessCommandLineArgs(parser, args)
    benchmark_class.ProcessCommandLineArgs(parser, args)

    cls._benchmark = benchmark_class

  def Run(self, args):
    return min(255, self._benchmark().Run(args))


def _ScriptName():
  return os.path.basename(sys.argv[0])


def _MatchingCommands(string, commands):
  return [command for command in commands
         if command.Name().startswith(string)]

@decorators.Cache
def _Benchmarks(environment):
  benchmarks = []
  for search_dir in environment.benchmark_dirs:
    benchmarks += discover.DiscoverClasses(search_dir,
                                           environment.top_level_dir,
                                           benchmark.Benchmark,
                                           index_by_class_name=True).values()
  return benchmarks

def _MatchBenchmarkName(input_benchmark_name, environment, exact_matches=True):
  def _Matches(input_string, search_string):
    if search_string.startswith(input_string):
      return True
    for part in search_string.split('.'):
      if part.startswith(input_string):
        return True
    return False

  # Exact matching.
  if exact_matches:
    # Don't add aliases to search dict, only allow exact matching for them.
    if input_benchmark_name in environment.benchmark_aliases:
      exact_match = environment.benchmark_aliases[input_benchmark_name]
    else:
      exact_match = input_benchmark_name

    for benchmark_class in _Benchmarks(environment):
      if exact_match == benchmark_class.Name():
        return [benchmark_class]
    return []

  # Fuzzy matching.
  return [benchmark_class for benchmark_class in _Benchmarks(environment)
          if _Matches(input_benchmark_name, benchmark_class.Name())]


def GetBenchmarkByName(name, environment):
  matched = _MatchBenchmarkName(name, environment, exact_matches=True)
  # With exact_matches, len(matched) is either 0 or 1.
  if len(matched) == 0:
    return None
  return matched[0]


def _GetJsonBenchmarkList(possible_browser, possible_reference_browser,
                          benchmark_classes, num_shards):
  """Returns a list of all enabled benchmarks in a JSON format expected by
  buildbots.

  JSON format:
  { "version": <int>,
    "steps": {
      <string>: {
        "device_affinity": <int>,
        "cmd": <string>,
        "perf_dashboard_id": <string>,
      },
      ...
    }
  }
  """
  # TODO(charliea): Remove this once we have more power perf bots.
  only_run_battor_benchmarks = False
  print 'Environment variables: ', os.environ
  if os.environ.get('BUILDBOT_BUILDERNAME') in GOOD_POWER_PERF_BOT_WHITELIST:
    only_run_battor_benchmarks = True

  output = {
    'version': 1,
    'steps': {
    }
  }
  for benchmark_class in benchmark_classes:
    if not _IsBenchmarkEnabled(benchmark_class, possible_browser):
      continue

    base_name = benchmark_class.Name()
    # TODO(charliea): Remove this once we have more power perf bots.
    # Only run battor power benchmarks to reduce the cycle time of this bot.
    # TODO(rnephew): Enable media.* and power.* tests when Mac BattOr issue
    # is solved.
    if only_run_battor_benchmarks and not base_name.startswith('battor'):
      continue
    base_cmd = [sys.executable, os.path.realpath(sys.argv[0]),
                '-v', '--output-format=chartjson', '--upload-results',
                base_name]
    perf_dashboard_id = base_name

    device_affinity = bot_utils.GetDeviceAffinity(num_shards, base_name)

    output['steps'][base_name] = {
      'cmd': ' '.join(base_cmd + [
            '--browser=%s' % possible_browser.browser_type]),
      'device_affinity': device_affinity,
      'perf_dashboard_id': perf_dashboard_id,
    }
    if (possible_reference_browser and
        _IsBenchmarkEnabled(benchmark_class, possible_reference_browser)):
      output['steps'][base_name + '.reference'] = {
        'cmd': ' '.join(base_cmd + [
              '--browser=reference', '--output-trace-tag=_ref']),
        'device_affinity': device_affinity,
        'perf_dashboard_id': perf_dashboard_id,
      }

  return json.dumps(output, indent=2, sort_keys=True)


def main(environment, extra_commands=None, **log_config_kwargs):
  # The log level is set in browser_options.
  log_config_kwargs.pop('level', None)
  log_config_kwargs.setdefault('format', DEFAULT_LOG_FORMAT)
  logging.basicConfig(**log_config_kwargs)

  ps_util.EnableListingStrayProcessesUponExitHook()

  # Get the command name from the command line.
  if len(sys.argv) > 1 and sys.argv[1] == '--help':
    sys.argv[1] = 'help'

  command_name = 'run'
  for arg in sys.argv[1:]:
    if not arg.startswith('-'):
      command_name = arg
      break

  # TODO(eakuefner): Remove this hack after we port to argparse.
  if command_name == 'help' and len(sys.argv) > 2 and sys.argv[2] == 'run':
    command_name = 'run'
    sys.argv[2] = '--help'

  if extra_commands is None:
    extra_commands = []
  all_commands = [Help, List, Run] + extra_commands

  # Validate and interpret the command name.
  commands = _MatchingCommands(command_name, all_commands)
  if len(commands) > 1:
    print >> sys.stderr, ('"%s" is not a %s command. Did you mean one of these?'
                          % (command_name, _ScriptName()))
    for command in commands:
      print >> sys.stderr, '  %-10s %s' % (
          command.Name(), command.Description())
    return 1
  if commands:
    command = commands[0]
  else:
    command = Run

  binary_manager.InitDependencyManager(environment.client_configs)

  # Parse and run the command.
  parser = command.CreateParser()
  command.AddCommandLineArgs(parser, environment)

  # Set the default chrome root variable.
  parser.set_defaults(chrome_root=environment.default_chrome_root)


  if isinstance(parser, argparse.ArgumentParser):
    commandline_args = sys.argv[1:]
    options, args = parser.parse_known_args(commandline_args[1:])
    command.ProcessCommandLineArgs(parser, options, args, environment)
  else:
    options, args = parser.parse_args()
    if commands:
      args = args[1:]
    options.positional_args = args
    command.ProcessCommandLineArgs(parser, options, environment)

  if command == Help:
    command_instance = command(all_commands)
  else:
    command_instance = command()
  if isinstance(command_instance, command_line.OptparseCommand):
    return command_instance.Run(options)
  else:
    return command_instance.Run(options, args)
