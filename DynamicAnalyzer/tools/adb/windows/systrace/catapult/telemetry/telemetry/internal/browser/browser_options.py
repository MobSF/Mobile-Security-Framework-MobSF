# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import copy
import logging
import optparse
import os
import shlex
import socket
import sys

from py_utils import cloud_storage  # pylint: disable=import-error

from telemetry.core import platform
from telemetry.core import util
from telemetry.internal.browser import browser_finder
from telemetry.internal.browser import browser_finder_exceptions
from telemetry.internal.browser import profile_types
from telemetry.internal.platform import device_finder
from telemetry.internal.platform import remote_platform_options
from telemetry.internal.platform.profiler import profiler_finder
from telemetry.internal.util import binary_manager
from telemetry.util import wpr_modes


class BrowserFinderOptions(optparse.Values):
  """Options to be used for discovering a browser."""

  def __init__(self, browser_type=None):
    optparse.Values.__init__(self)

    self.browser_type = browser_type
    self.browser_executable = None
    self.chrome_root = None  # Path to src/
    self.chromium_output_dir = None  # E.g.: out/Debug
    self.device = None
    self.cros_ssh_identity = None

    self.cros_remote = None

    self.profiler = None
    self.verbosity = 0

    self.browser_options = BrowserOptions()
    self.output_file = None

    self.remote_platform_options = None

    self.no_performance_mode = False

  def __repr__(self):
    return str(sorted(self.__dict__.items()))

  def Copy(self):
    return copy.deepcopy(self)

  def CreateParser(self, *args, **kwargs):
    parser = optparse.OptionParser(*args, **kwargs)

    # Selection group
    group = optparse.OptionGroup(parser, 'Which browser to use')
    group.add_option('--browser',
        dest='browser_type',
        default=None,
        help='Browser type to run, '
             'in order of priority. Supported values: list,%s' %
             ','.join(browser_finder.FindAllBrowserTypes(self)))
    group.add_option('--browser-executable',
        dest='browser_executable',
        help='The exact browser to run.')
    group.add_option('--chrome-root',
        dest='chrome_root',
        help='Where to look for chrome builds. '
             'Defaults to searching parent dirs by default.')
    group.add_option('--chromium-output-directory',
        dest='chromium_output_dir',
        help='Where to look for build artifacts. '
             'Can also be specified by setting environment variable '
             'CHROMIUM_OUTPUT_DIR.')
    group.add_option(
        '--remote',
        dest='cros_remote',
        help='The hostname of a remote ChromeOS device to use.')
    group.add_option(
        '--remote-ssh-port',
        type=int,
        default=socket.getservbyname('ssh'),
        dest='cros_remote_ssh_port',
        help='The SSH port of the remote ChromeOS device (requires --remote).')
    identity = None
    testing_rsa = os.path.join(
        util.GetTelemetryThirdPartyDir(), 'chromite', 'ssh_keys', 'testing_rsa')
    if os.path.exists(testing_rsa):
      identity = testing_rsa
    group.add_option('--identity',
        dest='cros_ssh_identity',
        default=identity,
        help='The identity file to use when ssh\'ing into the ChromeOS device')
    parser.add_option_group(group)

    # Debugging options
    group = optparse.OptionGroup(parser, 'When things go wrong')
    profiler_choices = profiler_finder.GetAllAvailableProfilers()
    group.add_option(
        '--profiler', default=None, type='choice',
        choices=profiler_choices,
        help='Record profiling data using this tool. Supported values: %s. '
             '(Notice: this flag cannot be used for Timeline Based Measurement '
             'benchmarks.)' % ', '.join(profiler_choices))
    group.add_option(
        '-v', '--verbose', action='count', dest='verbosity',
        help='Increase verbosity level (repeat as needed)')
    group.add_option('--print-bootstrap-deps',
                     action='store_true',
                     help='Output bootstrap deps list.')
    parser.add_option_group(group)

    # Platform options
    group = optparse.OptionGroup(parser, 'Platform options')
    group.add_option('--no-performance-mode', action='store_true',
        help='Some platforms run on "full performance mode" where the '
        'test is executed at maximum CPU speed in order to minimize noise '
        '(specially important for dashboards / continuous builds). '
        'This option prevents Telemetry from tweaking such platform settings.')
    parser.add_option_group(group)

    # Remote platform options
    group = optparse.OptionGroup(parser, 'Remote platform options')
    group.add_option('--android-blacklist-file',
                     help='Device blacklist JSON file.')
    group.add_option('--device',
    help='The device ID to use. '
         'If not specified, only 0 or 1 connected devices are supported. '
         'If specified as "android", all available Android devices are '
         'used.')
    parser.add_option_group(group)

    # Browser options.
    self.browser_options.AddCommandLineArgs(parser)

    real_parse = parser.parse_args
    def ParseArgs(args=None):
      defaults = parser.get_default_values()
      for k, v in defaults.__dict__.items():
        if k in self.__dict__ and self.__dict__[k] != None:
          continue
        self.__dict__[k] = v
      ret = real_parse(args, self) # pylint: disable=E1121

      if self.verbosity >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
      elif self.verbosity:
        logging.getLogger().setLevel(logging.INFO)
      else:
        logging.getLogger().setLevel(logging.WARNING)

      if self.chromium_output_dir:
        os.environ['CHROMIUM_OUTPUT_DIR'] = self.chromium_output_dir

      # Parse remote platform options.
      self.BuildRemotePlatformOptions()

      if self.remote_platform_options.device == 'list':
        if binary_manager.NeedsInit():
          binary_manager.InitDependencyManager([])
        devices = device_finder.GetDevicesMatchingOptions(self)
        print 'Available devices:'
        for device in devices:
          print ' ', device.name
        sys.exit(0)

      if self.browser_executable and not self.browser_type:
        self.browser_type = 'exact'
      if self.browser_type == 'list':
        if binary_manager.NeedsInit():
          binary_manager.InitDependencyManager([])
        devices = device_finder.GetDevicesMatchingOptions(self)
        if not devices:
          sys.exit(0)
        browser_types = {}
        for device in devices:
          try:
            possible_browsers = browser_finder.GetAllAvailableBrowsers(self,
                                                                       device)
            browser_types[device.name] = sorted(
              [browser.browser_type for browser in possible_browsers])
          except browser_finder_exceptions.BrowserFinderException as ex:
            print >> sys.stderr, 'ERROR: ', ex
            sys.exit(1)
        print 'Available browsers:'
        if len(browser_types) == 0:
          print '  No devices were found.'
        for device_name in sorted(browser_types.keys()):
          print '  ', device_name
          for browser_type in browser_types[device_name]:
            print '    ', browser_type
        sys.exit(0)

      # Parse browser options.
      self.browser_options.UpdateFromParseResults(self)

      return ret
    parser.parse_args = ParseArgs
    return parser

  # TODO(eakuefner): Factor this out into OptionBuilder pattern
  def BuildRemotePlatformOptions(self):
    if self.device or self.android_blacklist_file:
      self.remote_platform_options = (
          remote_platform_options.AndroidPlatformOptions(
              self.device, self.android_blacklist_file))

      # We delete these options because they should live solely in the
      # AndroidPlatformOptions instance belonging to this class.
      if self.device:
        del self.device
      if self.android_blacklist_file:
        del self.android_blacklist_file
    else:
      self.remote_platform_options = (
          remote_platform_options.AndroidPlatformOptions())

  def AppendExtraBrowserArgs(self, args):
    self.browser_options.AppendExtraBrowserArgs(args)

  def MergeDefaultValues(self, defaults):
    for k, v in defaults.__dict__.items():
      self.ensure_value(k, v)

class BrowserOptions(object):
  """Options to be used for launching a browser."""

  # Levels of browser logging.
  NO_LOGGING = 'none'
  NON_VERBOSE_LOGGING = 'non-verbose'
  VERBOSE_LOGGING = 'verbose'

  _LOGGING_LEVELS = (NO_LOGGING, NON_VERBOSE_LOGGING, VERBOSE_LOGGING)
  _DEFAULT_LOGGING_LEVEL = NO_LOGGING

  def __init__(self):
    self.browser_type = None
    self.show_stdout = False

    self.extensions_to_load = []

    # If set, copy the generated profile to this path on exit.
    self.output_profile_path = None

    # When set to True, the browser will use the default profile.  Telemetry
    # will not provide an alternate profile directory.
    self.dont_override_profile = False
    self.profile_dir = None
    self.profile_type = None
    self._extra_browser_args = set()
    self.extra_wpr_args = []
    self.wpr_mode = wpr_modes.WPR_OFF
    self.full_performance_mode = True

    # The amount of time Telemetry should wait for the browser to start.
    # This property is not exposed as a command line option.
    self._browser_startup_timeout = 60

    self.disable_background_networking = True
    self.browser_user_agent_type = None

    self.clear_sytem_cache_for_browser_and_profile_on_start = False
    self.startup_url = 'about:blank'

    # Background pages of built-in component extensions can interfere with
    # performance measurements.
    self.disable_component_extensions_with_background_pages = True
    # Disable default apps.
    self.disable_default_apps = True

    self.logging_verbosity = self._DEFAULT_LOGGING_LEVEL

    # The cloud storage bucket & path for uploading logs data produced by the
    # browser to.
    # If logs_cloud_remote_path is None, a random remote path is generated every
    # time the logs data is uploaded.
    self.logs_cloud_bucket = cloud_storage.TELEMETRY_OUTPUT
    self.logs_cloud_remote_path = None

    # TODO(danduong): Find a way to store target_os here instead of
    # finder_options.
    self._finder_options = None

    # Whether to take screen shot for failed page & put them in telemetry's
    # profiling results.
    self.take_screenshot_for_failed_page = False

  def __repr__(self):
    # This works around the infinite loop caused by the introduction of a
    # circular reference with _finder_options.
    obj = self.__dict__.copy()
    del obj['_finder_options']
    return str(sorted(obj.items()))

  def IsCrosBrowserOptions(self):
    return False

  @classmethod
  def AddCommandLineArgs(cls, parser):

    ############################################################################
    # Please do not add any more options here without first discussing with    #
    # a telemetry owner. This is not the right place for platform-specific     #
    # options.                                                                 #
    ############################################################################

    group = optparse.OptionGroup(parser, 'Browser options')
    profile_choices = profile_types.GetProfileTypes()
    group.add_option('--profile-type',
        dest='profile_type',
        type='choice',
        default='clean',
        choices=profile_choices,
        help=('The user profile to use. A clean profile is used by default. '
              'Supported values: ' + ', '.join(profile_choices)))
    group.add_option('--profile-dir',
        dest='profile_dir',
        help='Profile directory to launch the browser with. '
             'A clean profile is used by default')
    group.add_option('--extra-browser-args',
        dest='extra_browser_args_as_string',
        help='Additional arguments to pass to the browser when it starts')
    group.add_option('--extra-wpr-args',
        dest='extra_wpr_args_as_string',
        help=('Additional arguments to pass to Web Page Replay. '
              'See third_party/web-page-replay/replay.py for usage.'))
    group.add_option('--show-stdout',
        action='store_true',
        help='When possible, will display the stdout of the process')

    group.add_option('--browser-logging-verbosity',
        dest='logging_verbosity',
        type='choice',
        choices=cls._LOGGING_LEVELS,
        help=('Browser logging verbosity. The log file is saved in temp '
              "directory. Note that logging affects the browser's "
              'performance. Supported values: %s. Defaults to %s.' % (
                  ', '.join(cls._LOGGING_LEVELS), cls._DEFAULT_LOGGING_LEVEL)))
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, 'Compatibility options')
    group.add_option('--gtest_output',
        help='Ignored argument for compatibility with runtest.py harness')
    parser.add_option_group(group)

  def UpdateFromParseResults(self, finder_options):
    """Copies our options from finder_options"""
    browser_options_list = [
        'extra_browser_args_as_string',
        'extra_wpr_args_as_string',
        'profile_dir',
        'profile_type',
        'show_stdout',
        ]
    for o in browser_options_list:
      a = getattr(finder_options, o, None)
      if a is not None:
        setattr(self, o, a)
        delattr(finder_options, o)

    self.browser_type = finder_options.browser_type
    self._finder_options = finder_options

    if hasattr(self, 'extra_browser_args_as_string'):
      tmp = shlex.split(
        self.extra_browser_args_as_string)
      self.AppendExtraBrowserArgs(tmp)
      delattr(self, 'extra_browser_args_as_string')
    if hasattr(self, 'extra_wpr_args_as_string'):
      tmp = shlex.split(
        self.extra_wpr_args_as_string)
      self.extra_wpr_args.extend(tmp)
      delattr(self, 'extra_wpr_args_as_string')
    if self.profile_type == 'default':
      self.dont_override_profile = True

    if self.profile_dir and self.profile_type != 'clean':
      logging.critical(
          "It's illegal to specify both --profile-type and --profile-dir.\n"
          "For more information see: http://goo.gl/ngdGD5")
      sys.exit(1)

    if self.profile_dir and not os.path.isdir(self.profile_dir):
      logging.critical(
          "Directory specified by --profile-dir (%s) doesn't exist "
          "or isn't a directory.\n"
          "For more information see: http://goo.gl/ngdGD5" % self.profile_dir)
      sys.exit(1)

    if not self.profile_dir:
      self.profile_dir = profile_types.GetProfileDir(self.profile_type)

    if getattr(finder_options, 'logging_verbosity'):
      self.logging_verbosity = finder_options.logging_verbosity
      delattr(finder_options, 'logging_verbosity')

    # This deferred import is necessary because browser_options is imported in
    # telemetry/telemetry/__init__.py.
    finder_options.browser_options = CreateChromeBrowserOptions(self)

  @property
  def finder_options(self):
    return self._finder_options

  @property
  def extra_browser_args(self):
    return self._extra_browser_args

  @property
  def browser_startup_timeout(self):
    return self._browser_startup_timeout

  @browser_startup_timeout.setter
  def browser_startup_timeout(self, value):
    self._browser_startup_timeout = value

  def AppendExtraBrowserArgs(self, args):
    if isinstance(args, list):
      self._extra_browser_args.update(args)
    else:
      self._extra_browser_args.add(args)


def CreateChromeBrowserOptions(br_options):
  browser_type = br_options.browser_type

  if (platform.GetHostPlatform().GetOSName() == 'chromeos' or
      (browser_type and browser_type.startswith('cros'))):
    return CrosBrowserOptions(br_options)

  return br_options


class ChromeBrowserOptions(BrowserOptions):
  """Chrome-specific browser options."""

  def __init__(self, br_options):
    super(ChromeBrowserOptions, self).__init__()
    # Copy to self.
    self.__dict__.update(br_options.__dict__)


class CrosBrowserOptions(ChromeBrowserOptions):
  """ChromeOS-specific browser options."""

  def __init__(self, br_options):
    super(CrosBrowserOptions, self).__init__(br_options)
    # Create a browser with oobe property.
    self.create_browser_with_oobe = False
    # Clear enterprise policy before logging in.
    self.clear_enterprise_policy = True
    # Disable GAIA/enterprise services.
    self.disable_gaia_services = True

    self.auto_login = True
    self.gaia_login = False
    self.username = 'test@test.test'
    self.password = ''
    self.gaia_id = '12345'
    # For non-accelerated QEMU VMs.
    self.browser_startup_timeout = 240

  def IsCrosBrowserOptions(self):
    return True
