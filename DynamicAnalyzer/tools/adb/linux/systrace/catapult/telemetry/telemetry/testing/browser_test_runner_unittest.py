# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import string
import sys
import tempfile
import unittest
import json

from telemetry import decorators
from telemetry import project_config
from telemetry.core import util
from telemetry.testing import browser_test_context
from telemetry.testing import browser_test_runner
from telemetry.testing import options_for_unittests
from telemetry.testing import run_browser_tests
from telemetry.testing import serially_executed_browser_test_case


class BrowserTestRunnerTest(unittest.TestCase):

  def _ExtractTestResults(self, test_result):
    delimiter = test_result['path_delimiter']
    failures = []
    successes = []
    def _IsLeafNode(node):
      test_dict = node[1]
      return ('expected' in test_dict and
              isinstance(test_dict['expected'], basestring))
    node_queues = []
    for t in test_result['tests']:
      node_queues.append((t, test_result['tests'][t]))
    while node_queues:
      node = node_queues.pop()
      full_test_name, test_dict = node
      if _IsLeafNode(node):
        if all(res not in test_dict['expected'].split() for res in
               test_dict['actual'].split()):
          failures.append(full_test_name)
        else:
          successes.append(full_test_name)
      else:
        for k in test_dict:
          node_queues.append(
            ('%s%s%s' % (full_test_name, delimiter, k),
             test_dict[k]))
    return successes, failures

  def baseTest(self, test_filter,
               failures, successes, test_name='SimpleTest'):
    config = project_config.ProjectConfig(
        top_level_dir=os.path.join(util.GetTelemetryDir(), 'examples'),
        client_configs=[],
        benchmark_dirs=[
            os.path.join(util.GetTelemetryDir(), 'examples', 'browser_tests')]
    )
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.close()
    temp_file_name = temp_file.name
    try:
      browser_test_runner.Run(
          config,
          [test_name,
           '--write-full-results-to=%s' % temp_file_name,
           '--test-filter=%s' % test_filter])
      with open(temp_file_name) as f:
        test_result = json.load(f)

      actual_successes, actual_failures = self._ExtractTestResults(test_result)
      self.assertEquals(set(actual_failures), set(failures))
      self.assertEquals(set(actual_successes), set(successes))
    finally:
      os.remove(temp_file_name)

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testJsonOutputFormatNegativeFilter(self):
    self.baseTest(
      '^(add|multiplier).*',
      ['browser_tests.simple_numeric_test.SimpleTest.add_1_and_2',
       'browser_tests.simple_numeric_test.SimpleTest.add_7_and_3',
       'browser_tests.simple_numeric_test.SimpleTest.multiplier_simple_2'],
      ['browser_tests.simple_numeric_test.SimpleTest.add_2_and_3',
       'browser_tests.simple_numeric_test.SimpleTest.multiplier_simple',
       'browser_tests.simple_numeric_test.SimpleTest.multiplier_simple_3'])

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testJsonOutputWhenSetupClassFailed(self):
    self.baseTest(
      '.*',
      ['browser_tests.failed_tests.SetUpClassFailedTest.dummy_test_0',
       'browser_tests.failed_tests.SetUpClassFailedTest.dummy_test_1',
       'browser_tests.failed_tests.SetUpClassFailedTest.dummy_test_2'],
      [], test_name='SetUpClassFailedTest')

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testJsonOutputWhenTearDownClassFailed(self):
    self.baseTest(
      '.*',
      ['browser_tests.failed_tests.TearDownClassFailedTest.dummy_test_0',
       'browser_tests.failed_tests.TearDownClassFailedTest.dummy_test_1',
       'browser_tests.failed_tests.TearDownClassFailedTest.dummy_test_2'],
      [], test_name='TearDownClassFailedTest')

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testSetUpProcessCalledOnce(self):
    self.baseTest(
      '.*',
      [],
      ['browser_tests.process_tests.FailIfSetUpProcessCalledTwice.Dummy_0',
       'browser_tests.process_tests.FailIfSetUpProcessCalledTwice.Dummy_1',
       'browser_tests.process_tests.FailIfSetUpProcessCalledTwice.Dummy_2'],
      test_name='FailIfSetUpProcessCalledTwice')

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testTearDownProcessCalledOnce(self):
    self.baseTest(
      '.*',
      [],
      ['browser_tests.process_tests.FailIfTearDownProcessCalledTwice.Dummy_0',
       'browser_tests.process_tests.FailIfTearDownProcessCalledTwice.Dummy_1',
       'browser_tests.process_tests.FailIfTearDownProcessCalledTwice.Dummy_2'],
      test_name='FailIfTearDownProcessCalledTwice')

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testJsonOutputFormatPositiveFilter(self):
    self.baseTest(
      '(TestSimple|TestException).*',
      ['browser_tests.simple_numeric_test.SimpleTest.TestException',
       'browser_tests.simple_numeric_test.SimpleTest.TestSimple'], [])

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testExecutingTestsInSortedOrder(self):
    alphabetical_tests = []
    prefix = 'browser_tests.simple_numeric_test.SimpleTest.Alphabetical_'
    for i in xrange(20):
      alphabetical_tests.append(prefix + str(i))
    for c in string.uppercase[:26]:
      alphabetical_tests.append(prefix + c)
    for c in string.lowercase[:26]:
      alphabetical_tests.append(prefix + c)
    alphabetical_tests.sort()
    self.baseTest(
        'Alphabetical', [], alphabetical_tests)

  def shardingRangeTestHelper(self, total_shards, num_tests):
    shard_ranges = []
    for shard_index in xrange(0, total_shards):
      shard_ranges.append(run_browser_tests._TestRangeForShard(
        total_shards, shard_index, num_tests))
    # Make assertions about ranges
    num_tests_run = 0
    for i in xrange(0, len(shard_ranges)):
      cur_range = shard_ranges[i]
      if i < num_tests:
        self.assertGreater(cur_range[1], cur_range[0])
        num_tests_run += (cur_range[1] - cur_range[0])
      else:
        # Not enough tests to go around all of the shards.
        self.assertEquals(cur_range[0], cur_range[1])
    # Make assertions about non-overlapping ranges
    for i in xrange(1, len(shard_ranges)):
      prev_range = shard_ranges[i - 1]
      cur_range = shard_ranges[i]
      self.assertEquals(prev_range[1], cur_range[0])
    # Assert that we run all of the tests (very important)
    self.assertEquals(num_tests_run, num_tests)

  def testShardsWithPrimeNumTests(self):
    for total_shards in xrange(1, 20):
      # Nice non-prime number
      self.shardingRangeTestHelper(total_shards, 101)

  def testShardsWithDivisibleNumTests(self):
    for total_shards in xrange(1, 6):
      self.shardingRangeTestHelper(total_shards, 8)

  def testShardBoundaryConditions(self):
    self.shardingRangeTestHelper(1, 0)
    self.shardingRangeTestHelper(1, 1)
    self.shardingRangeTestHelper(2, 1)

  def baseShardingTest(self, total_shards, shard_index, failures, successes,
                       opt_abbr_input_json_file=None,
                       opt_test_filter='',
                       opt_filter_tests_after_sharding=False):
    config = project_config.ProjectConfig(
        top_level_dir=os.path.join(util.GetTelemetryDir(), 'examples'),
        client_configs=[],
        benchmark_dirs=[
            os.path.join(util.GetTelemetryDir(), 'examples', 'browser_tests')]
    )
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.close()
    temp_file_name = temp_file.name
    opt_args = []
    if opt_abbr_input_json_file:
      opt_args += [
        '--read-abbreviated-json-results-from=%s' % opt_abbr_input_json_file]
    if opt_test_filter:
      opt_args += [
        '--test-filter=%s' % opt_test_filter]
    if opt_filter_tests_after_sharding:
      opt_args += ['--filter-tests-after-sharding']
    try:
      browser_test_runner.Run(
          config,
          ['SimpleShardingTest',
           '--write-full-results-to=%s' % temp_file_name,
           '--total-shards=%d' % total_shards,
           '--shard-index=%d' % shard_index] + opt_args)
      with open(temp_file_name) as f:
        test_result = json.load(f)
      actual_successes, actual_failures = self._ExtractTestResults(test_result)
      self.assertEquals(set(actual_failures), set(failures))
      self.assertEquals(set(actual_successes), set(successes))
    finally:
      os.remove(temp_file_name)

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testShardedTestRun(self):
    self.baseShardingTest(3, 0, [], [
      'browser_tests.simple_sharding_test.SimpleShardingTest.Test1',
      'browser_tests.simple_sharding_test.SimpleShardingTest.Test2',
      'browser_tests.simple_sharding_test.SimpleShardingTest.Test3',
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_0',
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_1',
    ])
    self.baseShardingTest(3, 1, [], [
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_2',
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_3',
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_4',
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_5',
    ])
    self.baseShardingTest(3, 2, [], [
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_6',
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_7',
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_8',
      'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_9',
    ])

  def writeMockTestResultsFile(self):
    mock_test_results = {
      'passes': [
        'Test1',
        'Test2',
        'Test3',
        'passing_test_0',
        'passing_test_1',
        'passing_test_2',
        'passing_test_3',
        'passing_test_4',
        'passing_test_5',
        'passing_test_6',
        'passing_test_7',
        'passing_test_8',
        'passing_test_9',
      ],
      'failures': [],
      'valid': True,
      'times': {
        'Test1': 3.0,
        'Test2': 3.0,
        'Test3': 3.0,
        'passing_test_0': 3.0,
        'passing_test_1': 2.0,
        'passing_test_2': 2.0,
        'passing_test_3': 2.0,
        'passing_test_4': 2.0,
        'passing_test_5': 1.0,
        'passing_test_6': 1.0,
        'passing_test_7': 1.0,
        'passing_test_8': 1.0,
        'passing_test_9': 0.5,
      }
    }
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.close()
    temp_file_name = temp_file.name
    with open(temp_file_name, 'w') as f:
      json.dump(mock_test_results, f)
    return temp_file_name

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testSplittingShardsByTimes(self):
    temp_file_name = self.writeMockTestResultsFile()
    # It seems that the sorting order of the first four tests above is:
    #   passing_test_0, Test1, Test2, Test3
    # This is probably because the relative order of the "fixed" tests
    # (starting with "Test") and the generated ones ("passing_") is
    # not well defined, and the sorting is stable afterward.  The
    # expectations have been adjusted for this fact.
    try:
      self.baseShardingTest(
        4, 0, [],
        ['browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_0',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_1',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_5',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_9'
        ], temp_file_name)
      self.baseShardingTest(
        4, 1, [],
        ['browser_tests.simple_sharding_test.SimpleShardingTest.Test1',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_2',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_6'
        ], temp_file_name)
      self.baseShardingTest(
        4, 2, [],
        ['browser_tests.simple_sharding_test.SimpleShardingTest.Test2',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_3',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_7'
        ], temp_file_name)
      self.baseShardingTest(
        4, 3, [],
        ['browser_tests.simple_sharding_test.SimpleShardingTest.Test3',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_4',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_8'
        ], temp_file_name)
    finally:
      os.remove(temp_file_name)

  @decorators.Disabled('chromeos')  # crbug.com/696553
  def testFilteringAfterSharding(self):
    temp_file_name = self.writeMockTestResultsFile()
    try:
      self.baseShardingTest(
        4, 1, [],
        ['browser_tests.simple_sharding_test.SimpleShardingTest.Test1',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_2',
         'browser_tests.simple_sharding_test.SimpleShardingTest.passing_test_6'
        ], temp_file_name,
        opt_test_filter='(Test1|passing_test_2|passing_test_6)',
        opt_filter_tests_after_sharding=True)
    finally:
      os.remove(temp_file_name)

  def testMedianComputation(self):
    self.assertEquals(2.0, run_browser_tests._MedianTestTime(
      {'test1': 2.0, 'test2': 7.0, 'test3': 1.0}))
    self.assertEquals(2.0, run_browser_tests._MedianTestTime(
      {'test1': 2.0}))
    self.assertEquals(0.0, run_browser_tests._MedianTestTime({}))
    self.assertEqual(4.0, run_browser_tests._MedianTestTime(
      {'test1': 2.0, 'test2': 6.0, 'test3': 1.0, 'test4': 8.0}))


class Algebra(
    serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):

  @classmethod
  def GenerateTestCases_Simple(cls, options):
    del options  # Unused.
    yield 'testOne', (1, 2)
    yield 'testTwo', (3, 3)

  def Simple(self, x, y):
    self.assertEquals(x, y)

  def TestNumber(self):
    self.assertEquals(0, 1)


class ErrorneousGeometric(
    serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):

  @classmethod
  def GenerateTestCases_Compare(cls, options):
    del options  # Unused.
    assert False, 'I am a problematic generator'
    yield 'testBasic', ('square', 'circle')

  def Compare(self, x, y):
    self.assertEquals(x, y)

  def TestAngle(self):
    self.assertEquals(90, 450)

class TestLoadAllTestModules(unittest.TestCase):
  def testLoadAllTestsInModule(self):
    context = browser_test_context.TypTestContext()
    context.finder_options = options_for_unittests.GetCopy()
    context.test_class = Algebra
    context.test_case_ids_to_run.add(
      'telemetry.testing.browser_test_runner_unittest.Algebra.TestNumber')
    context.test_case_ids_to_run.add(
      'telemetry.testing.browser_test_runner_unittest.Algebra.testOne')
    context.Freeze()
    browser_test_context._global_test_context = context
    try:
      # This should not invoke GenerateTestCases of ErrorneousGeometric class,
      # otherwise that would throw Exception.
      tests = serially_executed_browser_test_case.LoadAllTestsInModule(
          sys.modules[__name__])
      self.assertEquals(sorted([t.id() for t in tests]),
          ['telemetry.testing.browser_test_runner_unittest.Algebra.TestNumber',
           'telemetry.testing.browser_test_runner_unittest.Algebra.testOne'])
    finally:
      browser_test_context._global_test_context = None
