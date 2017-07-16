# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import fnmatch
import logging
import os
import sys

from telemetry.core import util
from telemetry.core import platform as platform_module
from telemetry import decorators
from telemetry.internal.browser import browser_finder
from telemetry.internal.browser import browser_finder_exceptions
from telemetry.internal.browser import browser_options
from telemetry.internal.platform import android_device
from telemetry.internal.util import binary_manager
from telemetry.internal.util import command_line
from telemetry.internal.util import ps_util
from telemetry.testing import browser_test_case
from telemetry.testing import options_for_unittests

from py_utils import cloud_storage
from py_utils import xvfb

import typ


class RunTestsCommand(command_line.OptparseCommand):
  """Run unit tests"""

  usage = '[test_name ...] [<options>]'
  xvfb_process = None

  def __init__(self):
    super(RunTestsCommand, self).__init__()
    self.stream = sys.stdout

  @classmethod
  def CreateParser(cls):
    options = browser_options.BrowserFinderOptions()
    options.browser_type = 'any'
    parser = options.CreateParser('%%prog %s' % cls.usage)
    return parser

  @classmethod
  def AddCommandLineArgs(cls, parser, _):
    parser.add_option('--start-xvfb', action='store_true',
                      default=False, help='Start Xvfb display if needed.')
    parser.add_option('--disable-cloud-storage-io', action='store_true',
                      default=False, help=('Disable cloud storage IO when '
                                           'tests are run in parallel.'))
    parser.add_option('--repeat-count', type='int', default=1,
                      help='Repeats each a provided number of times.')
    parser.add_option('--no-browser', action='store_true', default=False,
                      help='Don\'t require an actual browser to run the tests.')
    parser.add_option('-d', '--also-run-disabled-tests',
                      dest='run_disabled_tests',
                      action='store_true', default=False,
                      help='Ignore @Disabled and @Enabled restrictions.')
    parser.add_option('--exact-test-filter', action='store_true', default=False,
                      help='Treat test filter as exact matches (default is '
                           'substring matches).')
    parser.add_option('--client-config', dest='client_configs',
                      action='append', default=[])
    parser.add_option('--disable-logging-config', action='store_true',
                      default=False, help='Configure logging (default on)')
    parser.add_option('--skip', metavar='glob', default=[],
                      action='append', help=(
                          'Globs of test names to skip (defaults to '
                          '%(default)s).'))
    typ.ArgumentParser.add_option_group(parser,
                                        "Options for running the tests",
                                        running=True,
                                        skip=['-d', '-v', '--verbose'])
    typ.ArgumentParser.add_option_group(parser,
                                        "Options for reporting the results",
                                        reporting=True)

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args, _):
    # We retry failures by default unless we're running a list of tests
    # explicitly.
    if not args.retry_limit and not args.positional_args:
      args.retry_limit = 3

    if args.no_browser:
      return

    if args.start_xvfb and xvfb.ShouldStartXvfb():
      cls.xvfb_process = xvfb.StartXvfb()
      # Work around Mesa issues on Linux. See
      # https://github.com/catapult-project/catapult/issues/3074
      args.browser_options.AppendExtraBrowserArgs('--disable-gpu')

    try:
      possible_browser = browser_finder.FindBrowser(args)
    except browser_finder_exceptions.BrowserFinderException, ex:
      parser.error(ex)

    if not possible_browser:
      parser.error('No browser found of type %s. Cannot run tests.\n'
                   'Re-run with --browser=list to see '
                   'available browser types.' % args.browser_type)

  @classmethod
  def main(cls, args=None, stream=None):  # pylint: disable=arguments-differ
    # We override the superclass so that we can hook in the 'stream' arg.
    parser = cls.CreateParser()
    cls.AddCommandLineArgs(parser, None)
    options, positional_args = parser.parse_args(args)
    options.positional_args = positional_args

    try:
      # Must initialize the DependencyManager before calling
      # browser_finder.FindBrowser(args)
      binary_manager.InitDependencyManager(options.client_configs)
      cls.ProcessCommandLineArgs(parser, options, None)

      obj = cls()
      if stream is not None:
        obj.stream = stream
      return obj.Run(options)
    finally:
      if cls.xvfb_process:
        cls.xvfb_process.kill()

  def Run(self, args):
    runner = typ.Runner()
    if self.stream:
      runner.host.stdout = self.stream

    if args.no_browser:
      possible_browser = None
      platform = platform_module.GetHostPlatform()
    else:
      possible_browser = browser_finder.FindBrowser(args)
      platform = possible_browser.platform

    fetch_reference_chrome_binary = False
    # Fetch all binaries needed by telemetry before we run the benchmark.
    if possible_browser and possible_browser.browser_type == 'reference':
      fetch_reference_chrome_binary = True
    binary_manager.FetchBinaryDependencies(
        platform, args.client_configs, fetch_reference_chrome_binary)

    # Telemetry seems to overload the system if we run one test per core,
    # so we scale things back a fair amount. Many of the telemetry tests
    # are long-running, so there's a limit to how much parallelism we
    # can effectively use for now anyway.
    #
    # It should be possible to handle multiple devices if we adjust the
    # browser_finder code properly, but for now we only handle one on ChromeOS.
    if platform.GetOSName() == 'chromeos':
      runner.args.jobs = 1
    elif platform.GetOSName() == 'android':
      android_devs = android_device.FindAllAvailableDevices(args)
      runner.args.jobs = len(android_devs)
      if runner.args.jobs == 0:
        raise RuntimeError("No Android device found")
      print 'Running tests with %d Android device(s).' % runner.args.jobs
    elif platform.GetOSVersionName() == 'xp':
      # For an undiagnosed reason, XP falls over with more parallelism.
      # See crbug.com/388256
      runner.args.jobs = max(int(args.jobs) // 4, 1)
    else:
      runner.args.jobs = max(int(args.jobs) // 2, 1)

    runner.args.skip = args.skip
    runner.args.metadata = args.metadata
    runner.args.passthrough = args.passthrough
    runner.args.path = args.path
    runner.args.retry_limit = args.retry_limit
    runner.args.test_results_server = args.test_results_server
    runner.args.test_type = args.test_type
    runner.args.top_level_dir = args.top_level_dir
    runner.args.write_full_results_to = args.write_full_results_to
    runner.args.write_trace_to = args.write_trace_to
    runner.args.list_only = args.list_only
    runner.args.shard_index = args.shard_index
    runner.args.total_shards = args.total_shards

    runner.args.path.append(util.GetUnittestDataDir())

    # Always print out these info for the ease of debugging.
    runner.args.timing = True
    runner.args.verbose = 3

    runner.classifier = GetClassifier(args, possible_browser)
    runner.context = args
    runner.setup_fn = _SetUpProcess
    runner.teardown_fn = _TearDownProcess
    runner.win_multiprocessing = typ.WinMultiprocessing.importable
    try:
      ret, _, _ = runner.run()
    except KeyboardInterrupt:
      print >> sys.stderr, "interrupted, exiting"
      ret = 130
    return ret


def _SkipMatch(name, skipGlobs):
  return any(fnmatch.fnmatch(name, glob) for glob in skipGlobs)


def GetClassifier(args, possible_browser):

  def ClassifyTestWithoutBrowser(test_set, test):
    name = test.id()
    if _SkipMatch(name, args.skip):
      test_set.tests_to_skip.append(
          typ.TestInput(name, 'skipped because matched --skip'))
      return
    if (not args.positional_args
        or _MatchesSelectedTest(name, args.positional_args,
                                  args.exact_test_filter)):
      # TODO(telemetry-team): Make sure that all telemetry unittest that invokes
      # actual browser are subclasses of browser_test_case.BrowserTestCase
      # (crbug.com/537428)
      if issubclass(test.__class__, browser_test_case.BrowserTestCase):
        test_set.tests_to_skip.append(typ.TestInput(
            name, msg='Skip the test because it requires a browser.'))
      else:
        test_set.parallel_tests.append(typ.TestInput(name))

  def ClassifyTestWithBrowser(test_set, test):
    name = test.id()
    if _SkipMatch(name, args.skip):
      test_set.tests_to_skip.append(
          typ.TestInput(name, 'skipped because matched --skip'))
      return
    if (not args.positional_args
        or _MatchesSelectedTest(name, args.positional_args,
                                args.exact_test_filter)):
      assert hasattr(test, '_testMethodName')
      method = getattr(
          test, test._testMethodName)  # pylint: disable=protected-access
      should_skip, reason = decorators.ShouldSkip(method, possible_browser)
      if should_skip and not args.run_disabled_tests:
        test_set.tests_to_skip.append(typ.TestInput(name, msg=reason))
      elif decorators.ShouldBeIsolated(method, possible_browser):
        test_set.isolated_tests.append(typ.TestInput(name))
      else:
        test_set.parallel_tests.append(typ.TestInput(name))

  if possible_browser:
    return ClassifyTestWithBrowser
  else:
    return ClassifyTestWithoutBrowser


def _MatchesSelectedTest(name, selected_tests, selected_tests_are_exact):
  if not selected_tests:
    return False
  if selected_tests_are_exact:
    return any(name in selected_tests)
  else:
    return any(test in name for test in selected_tests)


def _SetUpProcess(child, context): # pylint: disable=unused-argument
  ps_util.EnableListingStrayProcessesUponExitHook()
  # Make sure that we don't invokes cloud storage I/Os when we run the tests in
  # parallel.
  # TODO(nednguyen): always do this once telemetry tests in Chromium is updated
  # to prefetch files.
  # (https://github.com/catapult-project/catapult/issues/2192)
  args = context
  if args.disable_cloud_storage_io:
    os.environ[cloud_storage.DISABLE_CLOUD_STORAGE_IO] = '1'
  if binary_manager.NeedsInit():
    # Typ doesn't keep the DependencyManager initialization in the child
    # processes.
    binary_manager.InitDependencyManager(context.client_configs)
  # We need to reset the handlers in case some other parts of telemetry already
  # set it to make this work.
  if not args.disable_logging_config:
    logging.getLogger().handlers = []
    logging.basicConfig(
        level=logging.INFO,
        format='(%(levelname)s) %(asctime)s pid=%(process)d'
               '  %(module)s.%(funcName)s:%(lineno)d'
               '  %(message)s')
  if args.remote_platform_options.device == 'android':
    android_devices = android_device.FindAllAvailableDevices(args)
    if not android_devices:
      raise RuntimeError("No Android device found")
    android_devices.sort(key=lambda device: device.name)
    args.remote_platform_options.device = (
        android_devices[child.worker_num-1].guid)
  options_for_unittests.Push(args)


def _TearDownProcess(child, context): # pylint: disable=unused-argument
  # It's safe to call teardown_browser even if we did not start any browser
  # in any of the tests.
  browser_test_case.teardown_browser()
  options_for_unittests.Pop()


if __name__ == '__main__':
  ret_code = RunTestsCommand.main()
  sys.exit(ret_code)
