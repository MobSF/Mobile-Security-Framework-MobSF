# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Finds CrOS browsers that can be controlled by telemetry."""

import logging

from telemetry.core import cros_interface
from telemetry.core import platform as platform_module
from telemetry.internal.backends.chrome import cros_browser_backend
from telemetry.internal.backends.chrome import cros_browser_with_oobe
from telemetry.internal.browser import browser
from telemetry.internal.browser import browser_finder_exceptions
from telemetry.internal.browser import possible_browser
from telemetry.internal.platform import cros_device


class PossibleCrOSBrowser(possible_browser.PossibleBrowser):
  """A launchable CrOS browser instance."""
  def __init__(self, browser_type, finder_options, cros_platform, is_guest):
    super(PossibleCrOSBrowser, self).__init__(browser_type, 'cros', True)
    assert browser_type in FindAllBrowserTypes(finder_options), (
        'Please add %s to cros_browser_finder.FindAllBrowserTypes()' %
         browser_type)
    self._platform = cros_platform
    self._platform_backend = (
        cros_platform._platform_backend)  # pylint: disable=protected-access
    self._is_guest = is_guest

  def __repr__(self):
    return 'PossibleCrOSBrowser(browser_type=%s)' % self.browser_type

  def _InitPlatformIfNeeded(self):
    pass

  def Create(self, finder_options):
    if finder_options.browser_options.output_profile_path:
      raise NotImplementedError(
          'Profile generation is not yet supported on CrOS.')

    browser_options = finder_options.browser_options
    browser_backend = cros_browser_backend.CrOSBrowserBackend(
        self._platform_backend, browser_options, self._platform_backend.cri,
        self._is_guest)
    if browser_options.create_browser_with_oobe:
      return cros_browser_with_oobe.CrOSBrowserWithOOBE(
          browser_backend,
          self._platform_backend,
          self._credentials_path)
    return browser.Browser(
        browser_backend, self._platform_backend, self._credentials_path)

  def SupportsOptions(self, browser_options):
    return (len(browser_options.extensions_to_load) == 0) or not self._is_guest

  def UpdateExecutableIfNeeded(self):
    pass

def SelectDefaultBrowser(possible_browsers):
  if cros_device.IsRunningOnCrOS():
    for b in possible_browsers:
      if b.browser_type == 'system':
        return b
  return None

def CanFindAvailableBrowsers(finder_options):
  return (cros_device.IsRunningOnCrOS() or
          finder_options.cros_remote or
          cros_interface.HasSSH())

def FindAllBrowserTypes(_):
  return [
      'cros-chrome',
      'cros-chrome-guest',
      'system',
      'system-guest',
  ]

def FindAllAvailableBrowsers(finder_options, device):
  """Finds all available CrOS browsers, locally and remotely."""
  browsers = []
  if not isinstance(device, cros_device.CrOSDevice):
    return browsers

  if cros_device.IsRunningOnCrOS():
    browsers = [PossibleCrOSBrowser('system', finder_options,
                                    platform_module.GetHostPlatform(),
                                    is_guest=False),
                PossibleCrOSBrowser('system-guest', finder_options,
                                    platform_module.GetHostPlatform(),
                                    is_guest=True)]

  # Check ssh
  try:
    platform = platform_module.GetPlatformForDevice(device, finder_options)
  except cros_interface.LoginException, ex:
    if isinstance(ex, cros_interface.KeylessLoginRequiredException):
      logging.warn('Could not ssh into %s. Your device must be configured',
                   finder_options.cros_remote)
      logging.warn('to allow passwordless login as root.')
      logging.warn('For a test-build device, pass this to your script:')
      logging.warn('   --identity $(CHROMITE)/ssh_keys/testing_rsa')
      logging.warn('')
      logging.warn('For a developer-mode device, the steps are:')
      logging.warn(' - Ensure you have an id_rsa.pub (etc) on this computer')
      logging.warn(' - On the chromebook:')
      logging.warn('   -  Control-Alt-T; shell; sudo -s')
      logging.warn('   -  openssh-server start')
      logging.warn('   -  scp <this machine>:.ssh/id_rsa.pub /tmp/')
      logging.warn('   -  mkdir /root/.ssh')
      logging.warn('   -  chown go-rx /root/.ssh')
      logging.warn('   -  cat /tmp/id_rsa.pub >> /root/.ssh/authorized_keys')
      logging.warn('   -  chown 0600 /root/.ssh/authorized_keys')
    raise browser_finder_exceptions.BrowserFinderException(str(ex))

  browsers.extend([PossibleCrOSBrowser('cros-chrome', finder_options,
                                       platform, is_guest=False),
                   PossibleCrOSBrowser('cros-chrome-guest',
                                       finder_options, platform,
                                       is_guest=True)])
  return browsers
