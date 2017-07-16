# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import fnmatch
import re
import sys
import json

from telemetry.core import discover
from telemetry.internal.browser import browser_options
from telemetry.internal.platform import android_device
from telemetry.internal.util import binary_manager
from telemetry.testing import browser_test_context
from telemetry.testing import serially_executed_browser_test_case

import typ
from typ import arg_parser

TEST_SUFFIXES = ['*_test.py', '*_tests.py', '*_unittest.py', '*_unittests.py']


def ProcessCommandLineOptions(test_class, typ_options, args):
  options = browser_options.BrowserFinderOptions()
  options.browser_type = 'any'
  parser = options.CreateParser(test_class.__doc__)
  test_class.AddCommandlineArgs(parser)
  # Set the default chrome root variable. This is required for the
  # Android browser finder to function properly.
  if typ_options.default_chrome_root:
    parser.set_defaults(chrome_root=typ_options.default_chrome_root)
  finder_options, positional_args = parser.parse_args(args)
  finder_options.positional_args = positional_args
  # Typ parses the "verbose", or "-v", command line arguments which
  # are supposed to control logging verbosity. Carry them over.
  finder_options.verbosity = typ_options.verbose
  return finder_options


def _ValidateDistinctNames(browser_test_classes):
  names_to_test_classes = {}
  for cl in browser_test_classes:
    name = cl.Name()
    if name in names_to_test_classes:
      raise Exception('Test name %s is duplicated between %s and %s' % (
          name, repr(cl), repr(names_to_test_classes[name])))
    names_to_test_classes[name] = cl


def _TestRangeForShard(total_shards, shard_index, num_tests):
  """Returns a 2-tuple containing the start (inclusive) and ending
  (exclusive) indices of the tests that should be run, given that
  |num_tests| tests are split across |total_shards| shards, and that
  |shard_index| is currently being run.
  """
  assert num_tests >= 0
  assert total_shards >= 1
  assert shard_index >= 0 and shard_index < total_shards, (
    'shard_index (%d) must be >= 0 and < total_shards (%d)' %
    (shard_index, total_shards))
  if num_tests == 0:
    return (0, 0)
  floored_tests_per_shard = num_tests // total_shards
  remaining_tests = num_tests % total_shards
  if remaining_tests == 0:
    return (floored_tests_per_shard * shard_index,
            floored_tests_per_shard * (1 + shard_index))
  # More complicated. Some shards will run floored_tests_per_shard
  # tests, and some will run 1 + floored_tests_per_shard.
  num_earlier_shards_with_one_extra_test = min(remaining_tests, shard_index)
  num_earlier_shards_with_no_extra_tests = max(
    0, shard_index - num_earlier_shards_with_one_extra_test)
  num_earlier_tests = (
    num_earlier_shards_with_one_extra_test * (floored_tests_per_shard + 1) +
    num_earlier_shards_with_no_extra_tests * floored_tests_per_shard)
  tests_for_this_shard = floored_tests_per_shard
  if shard_index < remaining_tests:
    tests_for_this_shard += 1
  return (num_earlier_tests, num_earlier_tests + tests_for_this_shard)


def _MedianTestTime(test_times):
  times = test_times.values()
  times.sort()
  if len(times) == 0:
    return 0
  halfLen = len(times) / 2
  if len(times) % 2:
    return times[halfLen]
  else:
    return 0.5 * (times[halfLen - 1] + times[halfLen])


def _TestTime(test, test_times, default_test_time):
  return test_times.get(test.shortName()) or default_test_time


def _DebugShardDistributions(shards, test_times):
  for i, s in enumerate(shards):
    num_tests = len(s)
    if test_times:
      median = _MedianTestTime(test_times)
      shard_time = 0.0
      for t in s:
        shard_time += _TestTime(t, test_times, median)
      print 'shard %d: %d seconds (%d tests)' % (i, shard_time, num_tests)
    else:
      print 'shard %d: %d tests (unknown duration)' % (i, num_tests)


def _SplitShardsByTime(test_cases, total_shards, test_times,
                       debug_shard_distributions):
  median = _MedianTestTime(test_times)
  shards = []
  for i in xrange(total_shards):
    shards.append({'total_time': 0.0, 'tests': []})
  test_cases.sort(key=lambda t: _TestTime(t, test_times, median),
                  reverse=True)

  # The greedy algorithm has been empirically tested on the WebGL 2.0
  # conformance tests' times, and results in an essentially perfect
  # shard distribution of 530 seconds per shard. In the same scenario,
  # round-robin scheduling resulted in shard times spread between 502
  # and 592 seconds, and the current alphabetical sharding resulted in
  # shard times spread between 44 and 1591 seconds.

  # Greedy scheduling. O(m*n), where m is the number of shards and n
  # is the number of test cases.
  for t in test_cases:
    min_shard_index = 0
    min_shard_time = None
    for i in xrange(total_shards):
      if min_shard_time is None or shards[i]['total_time'] < min_shard_time:
        min_shard_index = i
        min_shard_time = shards[i]['total_time']
    shards[min_shard_index]['tests'].append(t)
    shards[min_shard_index]['total_time'] += _TestTime(t, test_times, median)

  res = [s['tests'] for s in shards]
  if debug_shard_distributions:
    _DebugShardDistributions(res, test_times)

  return res


def LoadTestCasesToBeRun(
    test_class, finder_options, filter_regex_str, filter_tests_after_sharding,
    total_shards, shard_index, test_times, debug_shard_distributions):
  test_cases = []
  real_regex = re.compile(filter_regex_str)
  noop_regex = re.compile('')
  if filter_tests_after_sharding:
    filter_regex = noop_regex
    post_filter_regex = real_regex
  else:
    filter_regex = real_regex
    post_filter_regex = noop_regex

  for t in serially_executed_browser_test_case.GenerateTestCases(
      test_class, finder_options):
    if filter_regex.search(t.shortName()):
      test_cases.append(t)

  if test_times:
    # Assign tests to shards.
    shards = _SplitShardsByTime(test_cases, total_shards, test_times,
                                debug_shard_distributions)
    return [t for t in shards[shard_index]
            if post_filter_regex.search(t.shortName())]
  else:
    test_cases.sort(key=lambda t: t.shortName())
    test_range = _TestRangeForShard(total_shards, shard_index, len(test_cases))
    if debug_shard_distributions:
      tmp_shards = []
      for i in xrange(total_shards):
        tmp_range = _TestRangeForShard(total_shards, i, len(test_cases))
        tmp_shards.append(test_cases[tmp_range[0]:tmp_range[1]])
      # Can edit the code to get 'test_times' passed in here for
      # debugging and comparison purposes.
      _DebugShardDistributions(tmp_shards, None)
    return [t for t in test_cases[test_range[0]:test_range[1]]
            if post_filter_regex.search(t.shortName())]


def _CreateTestArgParsers():
  parser = typ.ArgumentParser(discovery=False, reporting=True, running=True)
  parser.add_argument('test', type=str, help='Name of the test suite to run')
  parser.add_argument('--test-filter', type=str, default='', action='store',
      help='Run only tests whose names match the given filter regexp.')
  parser.add_argument(
    '--filter-tests-after-sharding', default=False, action='store_true',
    help=('Apply the test filter after tests are split for sharding. Useful '
          'for reproducing bugs related to the order in which tests run.'))
  parser.add_argument(
      '--read-abbreviated-json-results-from', metavar='FILENAME',
      action='store', help=(
        'If specified, reads abbreviated results from that path in json form. '
        'This information is used to more evenly distribute tests among '
        'shards.'))
  parser.add_argument('--debug-shard-distributions',
      action='store_true', default=False,
      help='Print debugging information about the shards\' test distributions')

  parser.add_argument('--default-chrome-root', type=str, default=None)
  parser.add_argument('--client-config', dest='client_configs',
                      action='append', default=[])
  parser.add_argument('--start-dir', dest='start_dirs',
                      action='append', default=[])
  parser.add_argument('--skip', metavar='glob', default=[],
      action='append',
      help=('Globs of test names to skip (defaults to %(default)s).'))
  return parser


def _SkipMatch(name, skipGlobs):
  return any(fnmatch.fnmatch(name, glob) for glob in skipGlobs)


def _GetClassifier(args):
  def _SeriallyExecutedBrowserTestCaseClassifer(test_set, test):
    # Do not pick up tests that do not inherit from
    # serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase
    # class.
    if not isinstance(test,
        serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):
      return
    name = test.id()
    if _SkipMatch(name, args.skip):
      test_set.tests_to_skip.append(
          typ.TestInput(name, 'skipped because matched --skip'))
      return
    # For now, only support running these tests serially.
    test_set.isolated_tests.append(typ.TestInput(name))
  return _SeriallyExecutedBrowserTestCaseClassifer


def RunTests(args):
  parser = _CreateTestArgParsers()
  try:
    options, extra_args = parser.parse_known_args(args)
  except arg_parser._Bailout:
    return parser.exit_status
  binary_manager.InitDependencyManager(options.client_configs)

  for start_dir in options.start_dirs:
    modules_to_classes = discover.DiscoverClasses(
        start_dir, options.top_level_dir,
        base_class=serially_executed_browser_test_case.
            SeriallyExecutedBrowserTestCase)
    browser_test_classes = modules_to_classes.values()

  _ValidateDistinctNames(browser_test_classes)

  test_class = None
  for cl in browser_test_classes:
    if cl.Name() == options.test:
      test_class = cl
      break

  if not test_class:
    print 'Cannot find test class with name matching %s' % options.test
    print 'Available tests: %s' % '\n'.join(
        cl.Name() for cl in browser_test_classes)
    return 1

  # Create test context.
  context = browser_test_context.TypTestContext()
  for c in options.client_configs:
    context.client_configs.append(c)
  context.finder_options = ProcessCommandLineOptions(
      test_class, options, extra_args)
  context.test_class = test_class
  test_times = None
  if options.read_abbreviated_json_results_from:
    with open(options.read_abbreviated_json_results_from, 'r') as f:
      abbr_results = json.load(f)
      test_times = abbr_results.get('times')
  tests_to_run = LoadTestCasesToBeRun(
      test_class=test_class, finder_options=context.finder_options,
      filter_regex_str=options.test_filter,
      filter_tests_after_sharding=options.filter_tests_after_sharding,
      total_shards=options.total_shards, shard_index=options.shard_index,
      test_times=test_times,
      debug_shard_distributions=options.debug_shard_distributions)
  for t in tests_to_run:
    context.test_case_ids_to_run.add(t.id())
  context.Freeze()
  browser_test_context._global_test_context = context

  # Setup typ runner.
  runner = typ.Runner()

  runner.context = context
  runner.setup_fn = _SetUpProcess
  runner.teardown_fn = _TearDownProcess

  runner.args.jobs = options.jobs
  runner.args.metadata = options.metadata
  runner.args.passthrough = options.passthrough
  runner.args.path = options.path
  runner.args.retry_limit = options.retry_limit
  runner.args.test_results_server = options.test_results_server
  runner.args.test_type = options.test_type
  runner.args.top_level_dir = options.top_level_dir
  runner.args.write_full_results_to = options.write_full_results_to
  runner.args.write_trace_to = options.write_trace_to
  runner.args.list_only = options.list_only
  runner.classifier = _GetClassifier(options)

  runner.args.suffixes = TEST_SUFFIXES

  # Since sharding logic is handled by browser_test_runner harness by passing
  # browser_test_context.test_case_ids_to_run to subprocess to indicate test
  # cases to be run, we explicitly disable sharding logic in typ.
  runner.args.total_shards = 1
  runner.args.shard_index = 0

  runner.args.timing = True
  runner.args.verbose = options.verbose
  runner.win_multiprocessing = typ.WinMultiprocessing.importable
  try:
    ret, _, _ = runner.run()
  except KeyboardInterrupt:
    print >> sys.stderr, "interrupted, exiting"
    ret = 130
  return ret


def _SetUpProcess(child, context):
  del child  # Unused.
  args = context.finder_options
  if binary_manager.NeedsInit():
    # On windows, typ doesn't keep the DependencyManager initialization in the
    # child processes.
    binary_manager.InitDependencyManager(context.client_configs)
  if args.remote_platform_options.device == 'android':
    android_devices = android_device.FindAllAvailableDevices(args)
    if not android_devices:
      raise RuntimeError("No Android device found")
    android_devices.sort(key=lambda device: device.name)
    args.remote_platform_options.device = (
        android_devices[child.worker_num-1].guid)
  browser_test_context._global_test_context = context
  context.test_class.SetUpProcess()


def _TearDownProcess(child, context):
  del child, context  # Unused.
  browser_test_context._global_test_context.test_class.TearDownProcess()
  browser_test_context._global_test_context = None


if __name__ == '__main__':
  ret_code = RunTests(sys.argv[1:])
  sys.exit(ret_code)
