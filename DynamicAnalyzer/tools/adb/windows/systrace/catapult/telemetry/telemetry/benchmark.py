# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse

from telemetry import decorators
from telemetry.internal import story_runner
from telemetry.internal.util import command_line
from telemetry.page import legacy_page_test
from telemetry.web_perf import timeline_based_measurement

Disabled = decorators.Disabled
Enabled = decorators.Enabled
Owner = decorators.Owner

class InvalidOptionsError(Exception):
  """Raised for invalid benchmark options."""
  pass


class BenchmarkMetadata(object):
  def __init__(self, name, description='', rerun_options=None):
    self._name = name
    self._description = description
    self._rerun_options = rerun_options

  @property
  def name(self):
    return self._name

  @property
  def description(self):
    return self._description

  @property
  def rerun_options(self):
    return self._rerun_options

  def AsDict(self):
    return {
      'type': 'telemetry_benchmark',
      'name': self._name,
      'description': self._description,
      'rerun_options': self._rerun_options,
    }


class Benchmark(command_line.Command):
  """Base class for a Telemetry benchmark.

  A benchmark packages a measurement and a PageSet together.
  Benchmarks default to using TBM unless you override the value of
  Benchmark.test, or override the CreatePageTest method.

  New benchmarks should override CreateStorySet.
  """
  options = {}
  page_set = None
  test = timeline_based_measurement.TimelineBasedMeasurement

  def __init__(self, max_failures=None):
    """Creates a new Benchmark.

    Args:
      max_failures: The number of story run's failures before bailing
          from executing subsequent page runs. If None, we never bail.
    """
    self._max_failures = max_failures
    self._has_original_tbm_options = (
        self.CreateTimelineBasedMeasurementOptions.__func__ ==
        Benchmark.CreateTimelineBasedMeasurementOptions.__func__)
    has_original_create_page_test = (
        self.CreatePageTest.__func__ == Benchmark.CreatePageTest.__func__)
    assert self._has_original_tbm_options or has_original_create_page_test, (
        'Cannot override both CreatePageTest and '
        'CreateTimelineBasedMeasurementOptions.')

  # pylint: disable=unused-argument
  @classmethod
  def ShouldDisable(cls, possible_browser):
    """Override this method to disable a benchmark under specific conditions.

     Supports logic too complex for simple Enabled and Disabled decorators.
     Decorators are still respected in cases where this function returns False.
     """
    return False

  def Run(self, finder_options):
    """Do not override this method."""
    return story_runner.RunBenchmark(self, finder_options)

  @property
  def max_failures(self):
    return self._max_failures

  @classmethod
  def Name(cls):
    return '%s.%s' % (cls.__module__.split('.')[-1], cls.__name__)

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    """Override to specify whether to tear down state after each story run.

    Tearing down all states after each story run, e.g., clearing profiles,
    stopping the browser, stopping local server, etc. So the browser will not be
    reused among multiple stories. This is particularly useful to get the
    startup part of launching the browser in each story.

    This should only be used by TimelineBasedMeasurement (TBM) benchmarks, but
    not by PageTest based benchmarks.
    """
    return True

  # NOTE: this is a temporary workaround for crbug.com/645329, do not rely on
  # this as a stable public API as we may remove this without public notice.
  @classmethod
  def IsShouldTearDownStateAfterEachStoryRunOverriden(cls):
    return (cls.ShouldTearDownStateAfterEachStoryRun.__func__ !=
            Benchmark.ShouldTearDownStateAfterEachStoryRun.__func__)

  @classmethod
  def ShouldTearDownStateAfterEachStorySetRun(cls):
    """Override to specify whether to tear down state after each story set run.

    Defaults to True in order to reset the state and make individual story set
    repeats more independent of each other. The intended effect is to average
    out noise in measurements between repeats.

    Long running benchmarks willing to stess test the browser and have it run
    for long periods of time may switch this value to False.

    This should only be used by TimelineBasedMeasurement (TBM) benchmarks, but
    not by PageTest based benchmarks.
    """
    return True

  @classmethod
  def AddCommandLineArgs(cls, parser):
    group = optparse.OptionGroup(parser, '%s test options' % cls.Name())
    cls.AddBenchmarkCommandLineArgs(group)

    if cls.HasTraceRerunDebugOption():
      group.add_option(
          '--rerun-with-debug-trace',
          action='store_true',
          help='Rerun option that enables more extensive tracing.')

    if group.option_list:
      parser.add_option_group(group)

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, group):
    del group  # unused

  @classmethod
  def HasTraceRerunDebugOption(cls):
    return False

  def GetTraceRerunCommands(self):
    if self.HasTraceRerunDebugOption():
      return [['Debug Trace', '--rerun-with-debug-trace']]
    return []

  def SetupTraceRerunOptions(self, browser_options, tbm_options):
    if self.HasTraceRerunDebugOption():
      if browser_options.rerun_with_debug_trace:
        self.SetupBenchmarkDebugTraceRerunOptions(tbm_options)
      else:
        self.SetupBenchmarkDefaultTraceRerunOptions(tbm_options)

  def SetupBenchmarkDefaultTraceRerunOptions(self, tbm_options):
    """Setup tracing categories associated with default trace option."""

  def SetupBenchmarkDebugTraceRerunOptions(self, tbm_options):
    """Setup tracing categories associated with debug trace option."""

  @classmethod
  def SetArgumentDefaults(cls, parser):
    default_values = parser.get_default_values()
    invalid_options = [
        o for o in cls.options if not hasattr(default_values, o)]
    if invalid_options:
      raise InvalidOptionsError('Invalid benchmark options: %s',
                                ', '.join(invalid_options))
    parser.set_defaults(**cls.options)

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args):
    pass

  # pylint: disable=unused-argument
  @classmethod
  def ValueCanBeAddedPredicate(cls, value, is_first_result):
    """Returns whether |value| can be added to the test results.

    Override this method to customize the logic of adding values to test
    results.

    Args:
      value: a value.Value instance (except failure.FailureValue,
        skip.SkipValue or trace.TraceValue which will always be added).
      is_first_result: True if |value| is the first result for its
          corresponding story.

    Returns:
      True if |value| should be added to the test results.
      Otherwise, it returns False.
    """
    return True

  def CustomizeBrowserOptions(self, options):
    """Add browser options that are required by this benchmark."""

  def GetMetadata(self):
    return BenchmarkMetadata(
        self.Name(), self.__doc__, self.GetTraceRerunCommands())

  def CreateTimelineBasedMeasurementOptions(self):
    """Return the TimelineBasedMeasurementOptions for this Benchmark.

    Override this method to configure a TimelineBasedMeasurement benchmark.
    Otherwise, override CreatePageTest for PageTest tests. Do not override
    both methods.
    """
    return timeline_based_measurement.Options()

  def CreatePageTest(self, options):  # pylint: disable=unused-argument
    """Return the PageTest for this Benchmark.

    Override this method for PageTest tests.
    Override, override CreateTimelineBasedMeasurementOptions to configure
    TimelineBasedMeasurement tests. Do not override both methods.

    Args:
      options: a browser_options.BrowserFinderOptions instance
    Returns:
      |test()| if |test| is a PageTest class.
      Otherwise, a TimelineBasedMeasurement instance.
    """
    is_page_test = issubclass(self.test, legacy_page_test.LegacyPageTest)
    is_tbm = self.test == timeline_based_measurement.TimelineBasedMeasurement
    if not is_page_test and not is_tbm:
      raise TypeError('"%s" is not a PageTest or a TimelineBasedMeasurement.' %
                      self.test.__name__)
    if is_page_test:
      assert self._has_original_tbm_options, (
          'Cannot override CreateTimelineBasedMeasurementOptions '
          'with a PageTest.')
      return self.test()  # pylint: disable=no-value-for-parameter

    opts = self.CreateTimelineBasedMeasurementOptions()
    self.SetupTraceRerunOptions(options, opts)
    return timeline_based_measurement.TimelineBasedMeasurement(opts)

  def CreateStorySet(self, options):
    """Creates the instance of StorySet used to run the benchmark.

    Can be overridden by subclasses.
    """
    del options  # unused
    # TODO(aiolos, nednguyen, eakufner): replace class attribute page_set with
    # story_set.
    if not self.page_set:
      raise NotImplementedError('This test has no "page_set" attribute.')
    return self.page_set()  # pylint: disable=not-callable


def AddCommandLineArgs(parser):
  story_runner.AddCommandLineArgs(parser)


def ProcessCommandLineArgs(parser, args):
  story_runner.ProcessCommandLineArgs(parser, args)
