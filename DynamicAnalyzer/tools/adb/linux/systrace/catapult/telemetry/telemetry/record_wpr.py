# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import logging
import sys

from telemetry import benchmark
from telemetry import story
from telemetry.core import discover
from telemetry.internal.browser import browser_options
from telemetry.internal.results import results_options
from telemetry.internal import story_runner
from telemetry.internal.util import binary_manager
from telemetry.page import legacy_page_test
from telemetry.util import matching
from telemetry.util import wpr_modes
from telemetry.web_perf import timeline_based_measurement
from telemetry.web_perf import timeline_based_page_test

import py_utils

DEFAULT_LOG_FORMAT = (
  '(%(levelname)s) %(asctime)s %(module)s.%(funcName)s:%(lineno)d  '
  '%(message)s')


class RecorderPageTest(legacy_page_test.LegacyPageTest):
  def __init__(self):
    super(RecorderPageTest, self).__init__()
    self.page_test = None
    self.platform = None

  def CustomizeBrowserOptions(self, options):
    if self.page_test:
      self.page_test.CustomizeBrowserOptions(options)

  def WillStartBrowser(self, browser):
    if self.platform is not None:
      assert browser.GetOSName() == self.platform
    self.platform = browser.GetOSName()
    if self.page_test:
      self.page_test.WillStartBrowser(browser)

  def DidStartBrowser(self, browser):
    if self.page_test:
      self.page_test.DidStartBrowser(browser)

  def WillNavigateToPage(self, page, tab):
    """Override to ensure all resources are fetched from network."""
    tab.ClearCache(force=False)
    if self.page_test:
      self.page_test.WillNavigateToPage(page, tab)

  def DidNavigateToPage(self, page, tab):
    if self.page_test:
      self.page_test.DidNavigateToPage(page, tab)
    tab.WaitForDocumentReadyStateToBeComplete()
    py_utils.WaitFor(tab.HasReachedQuiescence, 30)

  def CleanUpAfterPage(self, page, tab):
    if self.page_test:
      self.page_test.CleanUpAfterPage(page, tab)

  def ValidateAndMeasurePage(self, page, tab, results):
    if self.page_test:
      self.page_test.ValidateAndMeasurePage(page, tab, results)

  def RunNavigateSteps(self, page, tab):
    if self.page_test:
      self.page_test.RunNavigateSteps(page, tab)
    else:
      super(RecorderPageTest, self).RunNavigateSteps(page, tab)


def _GetSubclasses(base_dir, cls):
  """Returns all subclasses of |cls| in |base_dir|.

  Args:
    cls: a class

  Returns:
    dict of {underscored_class_name: benchmark class}
  """
  return discover.DiscoverClasses(base_dir, base_dir, cls,
                                  index_by_class_name=True)


def _MaybeGetInstanceOfClass(target, base_dir, cls):
  if isinstance(target, cls):
    return target
  classes = _GetSubclasses(base_dir, cls)
  return classes[target]() if target in classes else None


def _PrintAllImpl(all_items, item_name, output_stream):
  output_stream.write('Available %s\' names with descriptions:\n' % item_name)
  keys = sorted(all_items.keys())
  key_description = [(k, all_items[k].Description()) for k in keys]
  _PrintPairs(key_description, output_stream)
  output_stream.write('\n')


def _PrintAllBenchmarks(base_dir, output_stream):
  # TODO: reuse the logic of finding supported benchmarks in benchmark_runner.py
  # so this only prints out benchmarks that are supported by the recording
  # platform.
  _PrintAllImpl(_GetSubclasses(base_dir, benchmark.Benchmark), 'benchmarks',
                output_stream)


def _PrintAllStories(base_dir, output_stream):
  # TODO: actually print all stories once record_wpr support general
  # stories recording.
  _PrintAllImpl(_GetSubclasses(base_dir, story.StorySet), 'story sets',
                output_stream)


def _PrintPairs(pairs, output_stream, prefix=''):
  """Prints a list of string pairs with alignment."""
  first_column_length = max(len(a) for a, _ in pairs)
  format_string = '%s%%-%ds  %%s\n' % (prefix, first_column_length)
  for a, b in pairs:
    output_stream.write(format_string % (a, b.strip()))


class WprRecorder(object):

  def __init__(self, base_dir, target, args=None):
    self._base_dir = base_dir
    self._record_page_test = RecorderPageTest()
    self._options = self._CreateOptions()

    self._benchmark = _MaybeGetInstanceOfClass(target, base_dir,
                                               benchmark.Benchmark)
    self._parser = self._options.CreateParser(usage='See %prog --help')
    self._AddCommandLineArgs()
    self._ParseArgs(args)
    self._ProcessCommandLineArgs()
    if self._benchmark is not None:
      test = self._benchmark.CreatePageTest(self.options)
      if isinstance(test, timeline_based_measurement.TimelineBasedMeasurement):
        test = timeline_based_page_test.TimelineBasedPageTest(test)
      # This must be called after the command line args are added.
      self._record_page_test.page_test = test

    self._page_set_base_dir = (
        self._options.page_set_base_dir if self._options.page_set_base_dir
        else self._base_dir)
    self._story_set = self._GetStorySet(target)

  @property
  def options(self):
    return self._options

  def _CreateOptions(self):
    options = browser_options.BrowserFinderOptions()
    options.browser_options.wpr_mode = wpr_modes.WPR_RECORD
    return options

  def CreateResults(self):
    if self._benchmark is not None:
      benchmark_metadata = self._benchmark.GetMetadata()
    else:
      benchmark_metadata = benchmark.BenchmarkMetadata('record_wpr')

    return results_options.CreateResults(benchmark_metadata, self._options)

  def _AddCommandLineArgs(self):
    self._parser.add_option('--page-set-base-dir', action='store',
                            type='string')
    story_runner.AddCommandLineArgs(self._parser)
    if self._benchmark is not None:
      self._benchmark.AddCommandLineArgs(self._parser)
      self._benchmark.SetArgumentDefaults(self._parser)
    self._parser.add_option('--upload', action='store_true')
    self._SetArgumentDefaults()

  def _SetArgumentDefaults(self):
    self._parser.set_defaults(**{'output_formats': ['none']})

  def _ParseArgs(self, args=None):
    args_to_parse = sys.argv[1:] if args is None else args
    self._parser.parse_args(args_to_parse)

  def _ProcessCommandLineArgs(self):
    story_runner.ProcessCommandLineArgs(self._parser, self._options)

    if self._options.use_live_sites:
      self._parser.error("Can't --use-live-sites while recording")

    if self._benchmark is not None:
      self._benchmark.ProcessCommandLineArgs(self._parser, self._options)

  def _GetStorySet(self, target):
    if self._benchmark is not None:
      return self._benchmark.CreateStorySet(self._options)
    story_set = _MaybeGetInstanceOfClass(target, self._page_set_base_dir,
                                         story.StorySet)
    if story_set is None:
      sys.stderr.write('Target %s is neither benchmark nor story set.\n'
                       % target)
      if not self._HintMostLikelyBenchmarksStories(target):
        sys.stderr.write(
            'Found no similar benchmark or story. Please use '
            '--list-benchmarks or --list-stories to list candidates.\n')
        self._parser.print_usage()
      sys.exit(1)
    return story_set

  def _HintMostLikelyBenchmarksStories(self, target):
    def _Impl(all_items, category_name):
      candidates = matching.GetMostLikelyMatchedObject(
          all_items.iteritems(), target, name_func=lambda kv: kv[1].Name())
      if candidates:
        sys.stderr.write('\nDo you mean any of those %s below?\n' %
                         category_name)
        _PrintPairs([(k, v.Description()) for k, v in candidates], sys.stderr)
        return True
      return False

    has_benchmark_hint = _Impl(
        _GetSubclasses(self._base_dir, benchmark.Benchmark), 'benchmarks')
    has_story_hint = _Impl(
        _GetSubclasses(self._base_dir, story.StorySet), 'stories')
    return has_benchmark_hint or has_story_hint

  def Record(self, results):
    assert self._story_set.wpr_archive_info, (
      'Pageset archive_data_file path must be specified.')
    self._story_set.wpr_archive_info.AddNewTemporaryRecording()
    self._record_page_test.CustomizeBrowserOptions(self._options)
    story_runner.Run(self._record_page_test, self._story_set,
        self._options, results)

  def HandleResults(self, results, upload_to_cloud_storage):
    if results.failures or results.skipped_values:
      logging.warning('Some pages failed and/or were skipped. The recording '
                      'has not been updated for these pages.')
    results.PrintSummary()
    self._story_set.wpr_archive_info.AddRecordedStories(
        results.pages_that_succeeded,
        upload_to_cloud_storage,
        target_platform=self._record_page_test.platform)


def Main(environment, **log_config_kwargs):
  # the log level is set in browser_options
  log_config_kwargs.pop('level', None)
  log_config_kwargs.setdefault('format', DEFAULT_LOG_FORMAT)
  logging.basicConfig(**log_config_kwargs)

  parser = argparse.ArgumentParser(
      usage='Record a benchmark or a story (page set).')
  parser.add_argument(
      'benchmark',
      help=('benchmark name. This argument is optional. If both benchmark name '
            'and story name are specified, this takes precedence as the '
            'target of the recording.'),
      nargs='?')
  parser.add_argument('--story', help='story (page set) name')
  parser.add_argument('--list-stories', dest='list_stories',
                      action='store_true', help='list all story names.')
  parser.add_argument('--list-benchmarks', dest='list_benchmarks',
                      action='store_true', help='list all benchmark names.')
  parser.add_argument('--upload', action='store_true',
                      help='upload to cloud storage.')
  args, extra_args = parser.parse_known_args()

  if args.list_benchmarks or args.list_stories:
    if args.list_benchmarks:
      _PrintAllBenchmarks(environment.top_level_dir, sys.stderr)
    if args.list_stories:
      _PrintAllStories(environment.top_level_dir, sys.stderr)
    return 0

  target = args.benchmark or args.story

  if not target:
    sys.stderr.write('Please specify target (benchmark or story). Please refer '
                     'usage below\n\n')
    parser.print_help()
    return 0

  binary_manager.InitDependencyManager(environment.client_configs)

  # TODO(nednguyen): update WprRecorder so that it handles the difference
  # between recording a benchmark vs recording a story better based on
  # the distinction between args.benchmark & args.story
  wpr_recorder = WprRecorder(environment.top_level_dir, target, extra_args)
  results = wpr_recorder.CreateResults()
  wpr_recorder.Record(results)
  wpr_recorder.HandleResults(results, args.upload)
  return min(255, len(results.failures))
