# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Finds desktop browsers that can be controlled by telemetry."""

import logging
import os
import sys

import dependency_manager  # pylint: disable=import-error

from telemetry.core import exceptions
from telemetry.core import platform as platform_module
from telemetry.internal.backends.chrome import desktop_browser_backend
from telemetry.internal.browser import browser
from telemetry.internal.browser import possible_browser
from telemetry.internal.platform import desktop_device
from telemetry.internal.util import binary_manager
# This is a workaround for https://goo.gl/1tGNgd
from telemetry.internal.util import path as path_module


class PossibleDesktopBrowser(possible_browser.PossibleBrowser):
  """A desktop browser that can be controlled."""

  def __init__(self, browser_type, finder_options, executable, flash_path,
               is_content_shell, browser_directory, is_local_build=False):
    target_os = sys.platform.lower()
    super(PossibleDesktopBrowser, self).__init__(
        browser_type, target_os, not is_content_shell)
    assert browser_type in FindAllBrowserTypes(finder_options), (
        'Please add %s to desktop_browser_finder.FindAllBrowserTypes' %
        browser_type)
    self._local_executable = executable
    self._flash_path = flash_path
    self._is_content_shell = is_content_shell
    self._browser_directory = browser_directory
    self.is_local_build = is_local_build

  def __repr__(self):
    return 'PossibleDesktopBrowser(type=%s, executable=%s, flash=%s)' % (
        self.browser_type, self._local_executable, self._flash_path)

  def _InitPlatformIfNeeded(self):
    if self._platform:
      return

    self._platform = platform_module.GetHostPlatform()

    # pylint: disable=protected-access
    self._platform_backend = self._platform._platform_backend

  def Create(self, finder_options):
    if self._flash_path and not os.path.exists(self._flash_path):
      logging.warning(
          'Could not find Flash at %s. Continuing without Flash.\n'
          'To run with Flash, check it out via http://go/read-src-internal',
          self._flash_path)
      self._flash_path = None

    self._InitPlatformIfNeeded()

    browser_backend = desktop_browser_backend.DesktopBrowserBackend(
        self._platform_backend,
        finder_options.browser_options, self._local_executable,
        self._flash_path, self._is_content_shell, self._browser_directory)
    return browser.Browser(
        browser_backend, self._platform_backend, self._credentials_path)

  def SupportsOptions(self, browser_options):
    if ((len(browser_options.extensions_to_load) != 0)
        and self._is_content_shell):
      return False
    return True

  def UpdateExecutableIfNeeded(self):
    pass

  def last_modification_time(self):
    if os.path.exists(self._local_executable):
      return os.path.getmtime(self._local_executable)
    return -1

def SelectDefaultBrowser(possible_browsers):
  local_builds_by_date = [
      b for b in sorted(possible_browsers,
                        key=lambda b: b.last_modification_time())
      if b.is_local_build]
  if local_builds_by_date:
    return local_builds_by_date[-1]
  return None

def CanFindAvailableBrowsers():
  return not platform_module.GetHostPlatform().GetOSName() == 'chromeos'

def CanPossiblyHandlePath(target_path):
  _, extension = os.path.splitext(target_path.lower())
  if sys.platform == 'darwin' or sys.platform.startswith('linux'):
    return not extension
  elif sys.platform.startswith('win'):
    return extension == '.exe'
  return False

def FindAllBrowserTypes(_):
  return [
      'exact',
      'reference',
      'release',
      'release_x64',
      'debug',
      'debug_x64',
      'default',
      'stable',
      'beta',
      'dev',
      'canary',
      'content-shell-debug',
      'content-shell-debug_x64',
      'content-shell-release',
      'content-shell-release_x64',
      'content-shell-default',
      'system']

def FindAllAvailableBrowsers(finder_options, device):
  """Finds all the desktop browsers available on this machine."""
  if not isinstance(device, desktop_device.DesktopDevice):
    return []

  browsers = []

  if not CanFindAvailableBrowsers():
    return []

  has_x11_display = True
  if (sys.platform.startswith('linux') and
      os.getenv('DISPLAY') == None):
    has_x11_display = False

  os_name = platform_module.GetHostPlatform().GetOSName()
  arch_name = platform_module.GetHostPlatform().GetArchName()
  try:
    flash_path = binary_manager.LocalPath('flash', arch_name, os_name)
  except dependency_manager.NoPathFoundError:
    flash_path = None
    logging.warning(
        'Chrome build location for %s_%s not found. Browser will be run '
        'without Flash.', os_name, arch_name)

  chromium_app_names = []
  if sys.platform == 'darwin':
    chromium_app_names.append('Chromium.app/Contents/MacOS/Chromium')
    chromium_app_names.append('Google Chrome.app/Contents/MacOS/Google Chrome')
    content_shell_app_name = 'Content Shell.app/Contents/MacOS/Content Shell'
  elif sys.platform.startswith('linux'):
    chromium_app_names.append('chrome')
    content_shell_app_name = 'content_shell'
  elif sys.platform.startswith('win'):
    chromium_app_names.append('chrome.exe')
    content_shell_app_name = 'content_shell.exe'
  else:
    raise Exception('Platform not recognized')

  # Add the explicit browser executable if given and we can handle it.
  if (finder_options.browser_executable and
      CanPossiblyHandlePath(finder_options.browser_executable)):
    is_content_shell = finder_options.browser_executable.endswith(
        content_shell_app_name)
    is_chrome_or_chromium = len([x for x in chromium_app_names if
        finder_options.browser_executable.endswith(x)]) != 0

    # It is okay if the executable name doesn't match any of known chrome
    # browser executables, since it may be of a different browser.
    if is_chrome_or_chromium or is_content_shell:
      normalized_executable = os.path.expanduser(
          finder_options.browser_executable)
      if path_module.IsExecutable(normalized_executable):
        browser_directory = os.path.dirname(finder_options.browser_executable)
        browsers.append(PossibleDesktopBrowser(
            'exact', finder_options, normalized_executable, flash_path,
            is_content_shell,
            browser_directory))
      else:
        raise exceptions.PathMissingError(
            '%s specified by --browser-executable does not exist or is not '
            'executable' %
            normalized_executable)

  def AddIfFound(browser_type, build_path, app_name, content_shell):
    app = os.path.join(build_path, app_name)
    if path_module.IsExecutable(app):
      browsers.append(PossibleDesktopBrowser(
          browser_type, finder_options, app, flash_path,
          content_shell, build_path, is_local_build=True))
      return True
    return False

  # Add local builds
  for build_path in path_module.GetBuildDirectories(finder_options.chrome_root):
    # TODO(agrieve): Extract browser_type from args.gn's is_debug.
    browser_type = os.path.basename(build_path).lower()
    for chromium_app_name in chromium_app_names:
      AddIfFound(browser_type, build_path, chromium_app_name, False)
    AddIfFound('content-shell-' + browser_type, build_path,
               content_shell_app_name, True)

  reference_build = None
  if finder_options.browser_type == 'reference':
    # Reference builds are only available in a Chromium checkout. We should not
    # raise an error just because they don't exist.
    os_name = platform_module.GetHostPlatform().GetOSName()
    arch_name = platform_module.GetHostPlatform().GetArchName()
    reference_build = binary_manager.FetchPath(
        'chrome_stable', arch_name, os_name)

  # Mac-specific options.
  if sys.platform == 'darwin':
    mac_canary_root = '/Applications/Google Chrome Canary.app/'
    mac_canary = mac_canary_root + 'Contents/MacOS/Google Chrome Canary'
    mac_system_root = '/Applications/Google Chrome.app'
    mac_system = mac_system_root + '/Contents/MacOS/Google Chrome'
    if path_module.IsExecutable(mac_canary):
      browsers.append(PossibleDesktopBrowser('canary', finder_options,
                                             mac_canary, None, False,
                                             mac_canary_root))

    if path_module.IsExecutable(mac_system):
      browsers.append(PossibleDesktopBrowser('system', finder_options,
                                             mac_system, None, False,
                                             mac_system_root))

    if reference_build and path_module.IsExecutable(reference_build):
      reference_root = os.path.dirname(os.path.dirname(os.path.dirname(
          reference_build)))
      browsers.append(PossibleDesktopBrowser('reference', finder_options,
                                             reference_build, None, False,
                                             reference_root))

  # Linux specific options.
  if sys.platform.startswith('linux'):
    versions = {
        'system': os.path.split(os.path.realpath('/usr/bin/google-chrome'))[0],
        'stable': '/opt/google/chrome',
        'beta': '/opt/google/chrome-beta',
        'dev': '/opt/google/chrome-unstable'
    }

    for version, root in versions.iteritems():
      browser_path = os.path.join(root, 'chrome')
      if path_module.IsExecutable(browser_path):
        browsers.append(PossibleDesktopBrowser(version, finder_options,
                                               browser_path, None, False, root))
    if reference_build and path_module.IsExecutable(reference_build):
      reference_root = os.path.dirname(reference_build)
      browsers.append(PossibleDesktopBrowser('reference', finder_options,
                                             reference_build, None, False,
                                             reference_root))

  # Win32-specific options.
  if sys.platform.startswith('win'):
    app_paths = [
        ('system', os.path.join('Google', 'Chrome', 'Application')),
        ('canary', os.path.join('Google', 'Chrome SxS', 'Application')),
    ]
    if reference_build:
      app_paths.append(
          ('reference', os.path.dirname(reference_build)))

    for browser_name, app_path in app_paths:
      for chromium_app_name in chromium_app_names:
        full_path = path_module.FindInstalledWindowsApplication(
            os.path.join(app_path, chromium_app_name))
        if full_path:
          browsers.append(PossibleDesktopBrowser(
              browser_name, finder_options, full_path,
              None, False, os.path.dirname(full_path)))

  has_ozone_platform = False
  for arg in finder_options.browser_options.extra_browser_args:
    if "--ozone-platform" in arg:
      has_ozone_platform = True

  if len(browsers) and not has_x11_display and not has_ozone_platform:
    logging.warning(
      'Found (%s), but you do not have a DISPLAY environment set.' %
      ','.join([b.browser_type for b in browsers]))
    return []

  return browsers
